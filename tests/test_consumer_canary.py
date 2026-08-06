from __future__ import annotations

from typing import Any

import pytest

import consumer_canary
import storage
from object_store import StoredPage


class FakeStore:
    def __init__(self) -> None:
        self.removed: list[str] = []

    def canary_key(self, canary_id: str) -> str:
        return f"_acceptance_canary/v1/{canary_id}.json"

    def verify_canary(self, canary_id: str) -> StoredPage:
        return StoredPage(self.canary_key(canary_id), "d" * 64, "etag", 12)

    def remove_canary(self, canary_id: str) -> None:
        self.removed.append(canary_id)


def test_real_canary_state_transition_and_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = "b" * 32
    states = iter(
        (
            storage.QueueJobState("pending", 0, 1, False),
            storage.QueueJobState("processing", 1, 1, False),
            storage.QueueJobState("completed", 1, 1, False),
        )
    )
    enqueued: list[dict[str, Any]] = []
    monkeypatch.setattr(
        storage,
        "enqueue_job",
        lambda *args, **kwargs: enqueued.append(kwargs) or (77, True),
    )
    monkeypatch.setattr(
        storage, "get_queue_job_state", lambda *args, **kwargs: next(states)
    )
    store = FakeStore()
    result = consumer_canary.run_acceptance_canary(
        object(),
        store,  # type: ignore[arg-type]
        target_worker_id="candidate-release",
        canary_id=identity,
        timeout_seconds=10,
        poll_seconds=0.01,
        monotonic=lambda: 0.0,
        sleep=lambda _: None,
    )
    assert result.job_id == 77 and result.attempts == 1 and result.cleaned_up
    assert enqueued[0]["job_kind"] == "acceptance_canary"
    assert enqueued[0]["max_attempts"] == 1
    assert enqueued[0]["payload"]["targetWorkerId"] == "candidate-release"
    assert store.removed == [identity]


def test_retry_evidence_fails_release_but_still_cleans_terminal_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = "c" * 32
    monkeypatch.setattr(storage, "enqueue_job", lambda *args, **kwargs: (78, True))
    monkeypatch.setattr(
        storage,
        "get_queue_job_state",
        lambda *args, **kwargs: storage.QueueJobState("completed", 2, 2, False),
    )
    store = FakeStore()
    with pytest.raises(consumer_canary.CanaryError, match="retried"):
        consumer_canary.run_acceptance_canary(
            object(),
            store,  # type: ignore[arg-type]
            target_worker_id="candidate-release",
            canary_id=identity,
            timeout_seconds=10,
            monotonic=lambda: 0.0,
        )
    assert store.removed == [identity]


def test_dead_letter_canary_fails_without_claiming_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage, "enqueue_job", lambda *args, **kwargs: (79, True))
    monkeypatch.setattr(
        storage,
        "get_queue_job_state",
        lambda *args, **kwargs: storage.QueueJobState("dead", 1, 1, True),
    )
    cancelled: list[int] = []
    monkeypatch.setattr(
        storage,
        "cancel_acceptance_canary",
        lambda *args, **kwargs: cancelled.append(kwargs["job_id"]) or False,
    )
    store = FakeStore()
    with pytest.raises(consumer_canary.CanaryError, match="dead-lettered"):
        consumer_canary.run_acceptance_canary(
            object(),
            store,  # type: ignore[arg-type]
            target_worker_id="candidate-release",
            canary_id="e" * 32,
            timeout_seconds=10,
            monotonic=lambda: 0.0,
        )
    assert cancelled == [79]
    assert store.removed == ["e" * 32]


def test_timeout_cancels_targeted_job_and_removes_possible_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = "f" * 32
    monkeypatch.setattr(storage, "enqueue_job", lambda *args, **kwargs: (80, True))
    monkeypatch.setattr(
        storage,
        "get_queue_job_state",
        lambda *args, **kwargs: storage.QueueJobState("pending", 0, 1, False),
    )
    cancelled: list[tuple[int, str]] = []
    monkeypatch.setattr(
        storage,
        "cancel_acceptance_canary",
        lambda *args, **kwargs: cancelled.append(
            (kwargs["job_id"], kwargs["canary_id"])
        )
        or True,
    )
    ticks = iter((0.0, 0.0, 2.0))
    store = FakeStore()
    with pytest.raises(consumer_canary.CanaryError, match="timeout"):
        consumer_canary.run_acceptance_canary(
            object(),
            store,  # type: ignore[arg-type]
            target_worker_id="candidate-release",
            canary_id=identity,
            timeout_seconds=1,
            monotonic=lambda: next(ticks),
            sleep=lambda _: None,
        )
    assert cancelled == [(80, identity)]
    assert store.removed == [identity]
