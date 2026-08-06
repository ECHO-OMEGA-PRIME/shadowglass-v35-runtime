from __future__ import annotations

import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

import pytest

import queue_worker
import storage
from scraper import Discovery, ScrapedPage


CONTEXT = storage.JobContext(1, "Midland", "https://county.example", "publicsearch", 2, "Deed")
VALID_PAYLOAD = {
    "type": "scrape",
    "county": "Midland",
    "countyId": 1,
    "instrumentType": "Deed",
    "instrumentTypeId": 2,
    "startPage": 0,
    "endPage": 0,
    "platform": "publicsearch",
    "retry": 0,
}


def make_job(payload: Mapping[str, Any], *, kind: str = "scrape") -> storage.QueueJob:
    return storage.QueueJob(
        id=12,
        job_kind=kind,
        payload=payload,
        payload_version=1,
        idempotency_key="hourly:one",
        attempts=1,
        max_attempts=5,
        lease_token=uuid.uuid4(),
        lease_expires_at=datetime.now(timezone.utc),
    )


class FakeScraper:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[str] = []

    def discover(self, _: storage.JobContext, heartbeat: Any = None) -> Discovery:
        self.calls.append("discover")
        if heartbeat:
            heartbeat()
        if self.error:
            raise self.error
        return Discovery(50, 1)

    def scrape(
        self,
        _: storage.JobContext,
        start_page: int,
        end_page: int,
        heartbeat: Any = None,
    ) -> list[ScrapedPage]:
        self.calls.append(f"scrape:{start_page}:{end_page}")
        if heartbeat:
            heartbeat()
        if self.error:
            raise self.error
        return [ScrapedPage(0, [{"id": "doc-1"}], 1, 1)]


@dataclass
class Stored:
    key: str = "SHADOWGLASS_V35/Midland/Deed/page_000000.json"
    sha256: str = "a" * 64
    etag: str = "etag"


class FakeStore:
    def __init__(self) -> None:
        self.documents: list[Mapping[str, Any]] = []
        self.canaries: list[str] = []

    def page_key(self, **_: Any) -> str:
        return "SHADOWGLASS_V35/Midland/Deed/page_000000.json"

    def put_page(self, **kwargs: Any) -> Stored:
        assert kwargs["fence"].active
        self.documents.append(kwargs["document"])
        return Stored()

    def canary_key(self, canary_id: str) -> str:
        return f"_acceptance_canary/v1/{canary_id}.json"

    def put_canary(self, *, canary_id: str, fence: storage.LeaseWriteFence) -> Stored:
        assert fence.active and fence.object_key == self.canary_key(canary_id)
        self.canaries.append(canary_id)
        return Stored(key=fence.object_key)


def _common(monkeypatch: pytest.MonkeyPatch, job: storage.QueueJob) -> None:
    monkeypatch.setattr(storage, "claim_job", lambda *args, **kwargs: job)
    monkeypatch.setattr(storage, "load_job_context", lambda *args, **kwargs: CONTEXT)
    monkeypatch.setattr(storage, "extend_lease", lambda *args, **kwargs: True)

    @contextmanager
    def fenced(*args: Any, **kwargs: Any) -> Any:
        proof = storage.LeaseWriteFence(
            kwargs["job_id"], kwargs["lease_token"], kwargs["object_key"]
        )
        try:
            yield proof
        finally:
            proof._close()

    monkeypatch.setattr(storage, "lease_write_fence", fenced)


def test_scrape_persists_before_atomic_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    job = make_job(VALID_PAYLOAD)
    _common(monkeypatch, job)
    completed: list[list[Mapping[str, Any]]] = []
    monkeypatch.setattr(
        storage,
        "complete_scrape",
        lambda *args, **kwargs: completed.append(kwargs["pages"]) or 1,
    )
    scraper, store = FakeScraper(), FakeStore()
    assert queue_worker.process_once(object(), scraper, store, worker_id="worker") == "completed"
    assert scraper.calls == ["scrape:0:0"]
    assert store.documents[0]["records"] == [{"id": "doc-1"}]
    assert completed[0][0]["object_key"].startswith("SHADOWGLASS_V35/")


def test_arbitrary_url_field_is_rejected_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    job = make_job({**VALID_PAYLOAD, "url": "http://attacker.invalid"})
    dead: list[int] = []
    monkeypatch.setattr(storage, "claim_job", lambda *args, **kwargs: job)
    monkeypatch.setattr(
        storage,
        "dead_letter_job",
        lambda *args, **kwargs: dead.append(kwargs["job_id"]) or True,
    )
    scraper = FakeScraper()
    assert queue_worker.process_once(object(), scraper, FakeStore(), worker_id="worker") == "dead"
    assert dead == [12] and scraper.calls == []


def test_remote_failure_retries_without_payload_in_error(monkeypatch: pytest.MonkeyPatch) -> None:
    job = make_job(VALID_PAYLOAD)
    _common(monkeypatch, job)
    failures: list[str] = []
    monkeypatch.setattr(
        storage,
        "fail_job",
        lambda *args, **kwargs: failures.append(kwargs["error"]) or "pending",
    )
    result = queue_worker.process_once(
        object(), FakeScraper(RuntimeError("secret response")), FakeStore(), worker_id="worker"
    )
    assert result == "pending"
    assert failures == ["work failed (RuntimeError)"]


def test_payload_version_and_zero_based_bounds_are_enforced() -> None:
    with pytest.raises(queue_worker.PermanentJobError):
        queue_worker.validate_payload("scrape", 2, VALID_PAYLOAD)
    with pytest.raises(queue_worker.PermanentJobError):
        queue_worker.validate_payload(
            "scrape", 1, {**VALID_PAYLOAD, "startPage": 0, "endPage": 1000}
        )


def test_discovery_persists_and_fans_out_atomically(monkeypatch: pytest.MonkeyPatch) -> None:
    job = make_job({**VALID_PAYLOAD, "type": "discover"}, kind="discover")
    _common(monkeypatch, job)
    completed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        storage,
        "complete_discovery",
        lambda *args, **kwargs: completed.append(
            (kwargs["total_records"], kwargs["page_count"])
        )
        or 1,
    )
    scraper = FakeScraper()
    assert queue_worker.process_once(object(), scraper, FakeStore(), worker_id="worker") == "completed"
    assert scraper.calls == ["discover"]
    assert completed == [(50, 1)]


def test_acceptance_canary_uses_real_consumer_without_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary_id = "a" * 32
    job = make_job(
        {"canaryId": canary_id, "targetWorkerId": "candidate"},
        kind="acceptance_canary",
    )
    _common(monkeypatch, job)
    completed: list[int] = []
    monkeypatch.setattr(
        storage,
        "complete_job",
        lambda *args, **kwargs: completed.append(kwargs["job_id"]) or True,
    )
    scraper, store = FakeScraper(), FakeStore()
    assert queue_worker.process_once(object(), scraper, store, worker_id="candidate") == "completed"
    assert scraper.calls == []
    assert store.canaries == [canary_id]
    assert completed == [12]


def test_stale_fence_does_not_mutate_new_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    job = make_job(VALID_PAYLOAD)
    _common(monkeypatch, job)

    @contextmanager
    def rejected(*args: Any, **kwargs: Any) -> Any:
        raise storage.LeaseFenceRejected("stale")
        yield

    failures: list[str] = []
    monkeypatch.setattr(storage, "lease_write_fence", rejected)
    monkeypatch.setattr(
        storage,
        "fail_job",
        lambda *args, **kwargs: failures.append("called") or "pending",
    )
    result = queue_worker.process_once(
        object(), FakeScraper(), FakeStore(), worker_id="old-owner"
    )
    assert result == "stale" and failures == []
