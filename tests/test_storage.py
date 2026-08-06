from __future__ import annotations

import json
import uuid
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import Any

import pytest

import storage


class FakeCursor(AbstractContextManager["FakeCursor"]):
    def __init__(self, steps: list[dict[str, Any]]) -> None:
        self.steps = steps
        self.current: dict[str, Any] = {}
        self.rowcount = -1
        self.executions: list[tuple[str, tuple[Any, ...]]] = []

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        self.executions.append((query, params))
        if not self.steps:
            raise AssertionError("unexpected SQL execution")
        self.current = self.steps.pop(0)
        self.rowcount = self.current.get("rowcount", -1)

    def fetchone(self) -> Any:
        return self.current.get("one")


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self.fake_cursor = cursor

    def cursor(self) -> FakeCursor:
        return self.fake_cursor


def test_enqueue_is_idempotent_and_parameterized() -> None:
    cursor = FakeCursor(
        [
            {"one": None},
            {
                "one": {
                    "id": 41,
                    "job_kind": "scrape",
                    "payload": {"county": "Midland"},
                    "payload_version": 1,
                }
            },
        ]
    )
    created_id, created = storage.enqueue_job(
        FakeConnection(cursor),
        job_kind="scrape",
        payload={"county": "Midland"},
        idempotency_key="hourly:key-with-quotes-'",
    )
    assert (created_id, created) == (41, False)
    assert "key-with-quotes" not in cursor.executions[0][0]
    assert json.loads(cursor.executions[0][1][1]) == {"county": "Midland"}


def test_enqueue_rejects_idempotency_payload_collision() -> None:
    cursor = FakeCursor(
        [
            {"one": None},
            {
                "one": {
                    "id": 41,
                    "job_kind": "scrape",
                    "payload": {"county": "Ward"},
                    "payload_version": 1,
                }
            },
        ]
    )
    with pytest.raises(storage.IdempotencyConflict):
        storage.enqueue_job(
            FakeConnection(cursor),
            job_kind="scrape",
            payload={"county": "Midland"},
            idempotency_key="same-key-different-work",
        )


def test_claim_uses_skip_locked_and_returns_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage, "recover_stale_leases", lambda connection: (0, 0))
    token = uuid.uuid4()
    expires = datetime.now(timezone.utc)
    cursor = FakeCursor(
        [
            {
                "one": {
                    "id": 7,
                    "job_kind": "scrape",
                    "payload": {"county": "Midland"},
                    "payload_version": 1,
                    "idempotency_key": "hourly:1",
                    "attempts": 1,
                    "max_attempts": 5,
                    "lease_token": token,
                    "lease_expires_at": expires,
                }
            }
        ]
    )
    job = storage.claim_job(FakeConnection(cursor), worker_id="worker-1")
    assert job is not None and job.lease_token == token and job.attempts == 1
    assert "FOR UPDATE SKIP LOCKED" in cursor.executions[0][0]
    assert cursor.executions[0][1][0] == "worker-1"


def test_canary_only_claim_never_selects_ordinary_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage, "recover_stale_leases", lambda connection: (0, 0))
    cursor = FakeCursor([{"one": None}])
    assert (
        storage.claim_job(
            FakeConnection(cursor),
            worker_id="proof-worker",
            claim_kind="acceptance_canary",
        )
        is None
    )
    query, parameters = cursor.executions[0]
    assert "AND job_kind = %s" in query
    assert parameters[:2] == ("proof-worker", "acceptance_canary")


def test_retry_has_bounded_exponential_backoff() -> None:
    cursor = FakeCursor(
        [
            {"one": {"attempts": 3, "max_attempts": 5}},
            {"rowcount": 1},
        ]
    )
    state = storage.fail_job(
        FakeConnection(cursor),
        job_id=9,
        lease_token=uuid.uuid4(),
        error="temporary failure",
        base_backoff_seconds=10,
        max_backoff_seconds=25,
    )
    assert state == "pending"
    assert cursor.executions[1][1][0] == 25


def test_exhausted_job_is_dead_lettered() -> None:
    cursor = FakeCursor(
        [
            {"one": {"attempts": 5, "max_attempts": 5}},
            {"rowcount": 1},
            {"rowcount": 1},
        ]
    )
    state = storage.fail_job(
        FakeConnection(cursor),
        job_id=10,
        lease_token=uuid.uuid4(),
        error="permanent after retries",
    )
    assert state == "dead"
    assert "work_queue_dead_letter" in cursor.executions[1][0]


def test_stale_lease_recovery_requeues_and_dead_letters() -> None:
    cursor = FakeCursor(
        [
            {"rowcount": 2},
            {"rowcount": 2},
            {"rowcount": 3},
        ]
    )
    recovered, dead = storage.recover_stale_leases(FakeConnection(cursor))
    assert (recovered, dead) == (3, 2)
    assert all("lease_expires_at <= clock_timestamp()" in sql for sql, _ in cursor.executions)


def test_stale_owner_is_rejected_after_advisory_locks() -> None:
    cursor = FakeCursor([{}, {}, {"one": None}])
    with pytest.raises(storage.LeaseFenceRejected):
        with storage.lease_write_fence(
            FakeConnection(cursor),
            job_id=22,
            lease_token=uuid.uuid4(),
            object_key="SHADOWGLASS_V35/Ward/Deed/page_000001.json",
        ):
            raise AssertionError("stale owner entered write fence")
    assert "pg_advisory_xact_lock" in cursor.executions[0][0]
    assert "pg_advisory_xact_lock" in cursor.executions[1][0]
    assert "FOR UPDATE" in cursor.executions[2][0]


def test_live_fence_is_active_only_inside_context() -> None:
    cursor = FakeCursor([{}, {}, {"one": {"id": 22}}])
    token = uuid.uuid4()
    with storage.lease_write_fence(
        FakeConnection(cursor),
        job_id=22,
        lease_token=token,
        object_key="SHADOWGLASS_V35/Ward/Deed/page_000001.json",
    ) as proof:
        assert proof.active and proof.lease_token == token
    assert not proof.active
