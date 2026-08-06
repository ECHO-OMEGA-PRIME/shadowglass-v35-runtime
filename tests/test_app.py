from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app as command_app
from app import Runtime, Settings
from storage import DispatchReservation


class FakeStore:
    def __init__(self) -> None:
        self.dispatched: dict[str, tuple[int, str]] = {}
        self.states: list[tuple[str, str]] = []
        self.rate_allowed = True

    def rate_limit(self, subject: str, action: str, limit: int) -> bool:
        assert len(subject) == 64
        assert limit == 60
        return self.rate_allowed

    def reserve_dispatch(self, *, idempotency_key: str, target: str, action: str, payload: dict[str, Any]) -> DispatchReservation:
        if idempotency_key in self.dispatched:
            return DispatchReservation(self.dispatched[idempotency_key][0], False, self.dispatched[idempotency_key][1])
        receipt = len(self.dispatched) + 1
        self.dispatched[idempotency_key] = (receipt, "dispatching")
        return DispatchReservation(receipt, True, "dispatching")

    def mark_dispatched(self, receipt_id: int) -> None:
        for key, (candidate, _) in list(self.dispatched.items()):
            if candidate == receipt_id:
                self.dispatched[key] = (candidate, "dispatched")

    def mark_failed(self, receipt_id: int, error_class: str) -> None:
        raise AssertionError(error_class)

    def query(self, statement: str, params: tuple[Any, ...], *, limit: int = 500) -> list[dict[str, Any]]:
        if statement == "ping":
            return [{"ok": 1}]
        if statement == "stats":
            return [{"counties": 1, "instrument_types": 2, "records": 3, "jobs": 4}]
        if statement == "counties":
            return [{"id": 1, "name": "Midland", "platform": "tyler", "is_active": 1}]
        if statement == "record":
            return [{"id": 1, "external_id": "doc-1"}]
        if statement == "search":
            return [{"id": 1}]
        if statement == "schedules":
            return []
        return []

    def set_job_state(self, county: str, state: str) -> int:
        self.states.append((county, state))
        return 2

    def resolve_context(self, county: str, instrument_type: str, platform: str) -> dict[str, Any]:
        return {"county_id": 1, "county": county, "instrument_type_id": 2, "instrument_type": instrument_type, "platform": platform}

    def resolve_contexts(self, counties: list[str], platform: str, instrument_type: str | None, *, limit: int = 100) -> list[dict[str, Any]]:
        return [{"county_id": index + 1, "county": county, "instrument_type_id": 2, "instrument_type": instrument_type or "Deed", "platform": platform} for index, county in enumerate(counties[:limit])]

    def advance_schedule(self, schedule_id: int) -> None:
        raise AssertionError(schedule_id)


@dataclass
class FakeProducer:
    sent: list[tuple[str, dict[str, Any]]]

    def send(self, target: str, payload: dict[str, Any]) -> None:
        self.sent.append((target, payload))


@pytest.fixture()
def runtime() -> Runtime:
    settings = Settings(
        database_url="postgresql://unused",
        command_key="command-secret",
        cors_origins=("https://throne.echo-op.com",),
        account_id="a" * 32,
        queue_token="provider-secret",
        queue_ids={"publicsearch": "1" * 32, "texasfile": "2" * 32, "tyler": "3" * 32},
        version="test-release",
        environment="test",
    )
    return Runtime(settings=settings, store=FakeStore(), producer=FakeProducer([]))


@pytest.fixture()
def client(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    command_app.app.dependency_overrides[command_app._runtime] = lambda: runtime
    monkeypatch.setattr(command_app, "get_runtime", lambda: runtime)
    with TestClient(command_app.app) as test_client:
        yield test_client
    command_app.app.dependency_overrides.clear()


def auth() -> dict[str, str]:
    return {"X-Echo-Command-Key": "command-secret"}


def mutation(key: str = "acceptance-key") -> dict[str, str]:
    return {**auth(), "Idempotency-Key": key}


def test_exact_route_contract() -> None:
    pairs = sorted(
        (method, route.path.replace("{record_id}", "{}").replace("{county}", "{}"))
        for route in command_app.app.routes
        for method in route.methods
    )
    assert pairs == [
        ("GET", "/"),
        ("GET", "/counties"),
        ("GET", "/dashboard"),
        ("GET", "/health"),
        ("GET", "/record/{}"),
        ("GET", "/search"),
        ("GET", "/stats"),
        ("GET", "/status"),
        ("GET", "/status/{}"),
        ("GET", "/test/tyler"),
        ("POST", "/discover"),
        ("POST", "/pause/{}"),
        ("POST", "/resume/{}"),
        ("POST", "/scrape"),
        ("POST", "/scrape/all"),
        ("POST", "/scrape/multi"),
        ("POST", "/scrape/platform"),
    ]


def test_public_health_and_security_headers(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True, "status": "healthy", "version": "test-release"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["strict-transport-security"].startswith("max-age=")


def test_cors_is_exact_allowlist(client: TestClient) -> None:
    allowed = client.options("/scrape", headers={"Origin": "https://throne.echo-op.com"})
    blocked = client.options("/scrape", headers={"Origin": "https://example.invalid"})
    assert allowed.status_code == 204
    assert allowed.headers["access-control-allow-origin"] == "https://throne.echo-op.com"
    assert blocked.status_code == 403
    assert "access-control-allow-origin" not in blocked.headers


def test_mutation_requires_authentication(client: TestClient) -> None:
    response = client.post("/scrape", headers={"Idempotency-Key": "acceptance-key"}, json={"county": "Midland", "instrument_type": "Deed", "platform": "tyler"})
    assert response.status_code == 401


def test_mutation_requires_idempotency(client: TestClient) -> None:
    response = client.post("/scrape", headers=auth(), json={"county": "Midland", "instrument_type": "Deed", "platform": "tyler"})
    assert response.status_code == 400


def test_scrape_dispatches_canonical_payload(client: TestClient, runtime: Runtime) -> None:
    response = client.post("/scrape", headers=mutation(), json={"county": "Midland", "instrument_type": "Deed", "platform": "tyler", "start_page": 2, "end_page": 4})
    assert response.status_code == 200
    assert response.json()["state"] == "dispatched"
    assert runtime.producer.sent == [("tyler", {"type": "scrape", "county": "Midland", "countyId": 1, "instrumentType": "Deed", "instrumentTypeId": 2, "platform": "tyler", "startPage": 2, "endPage": 4, "retry": 0})]


def test_duplicate_dispatch_is_not_sent_twice(client: TestClient, runtime: Runtime) -> None:
    body = {"county": "Midland", "instrument_type": "Deed", "platform": "publicsearch"}
    first = client.post("/discover", headers=mutation("dedupe-key"), json=body)
    second = client.post("/discover", headers=mutation("dedupe-key"), json=body)
    assert first.status_code == second.status_code == 200
    assert second.json()["duplicate"] is True
    assert len(runtime.producer.sent) == 1


def test_invalid_page_range_fails_closed(client: TestClient) -> None:
    response = client.post("/scrape", headers=mutation(), json={"county": "Midland", "instrument_type": "Deed", "platform": "tyler", "start_page": 9, "end_page": 2})
    assert response.status_code == 400


def test_extra_payload_field_is_rejected(client: TestClient) -> None:
    response = client.post("/scrape", headers=mutation(), json={"county": "Midland", "instrument_type": "Deed", "platform": "tyler", "baseUrl": "https://attacker.invalid"})
    assert response.status_code == 422


def test_pause_and_resume_are_bounded(client: TestClient, runtime: Runtime) -> None:
    paused = client.post("/pause/Midland", headers=mutation("pause-key"))
    resumed = client.post("/resume/Midland", headers=mutation("resume-key"))
    assert paused.json()["changed"] == resumed.json()["changed"] == 2
    assert runtime.store.states == [("Midland", "paused"), ("Midland", "pending")]


def test_sensitive_reads_require_auth(client: TestClient) -> None:
    assert client.get("/status").status_code == 401
    assert client.get("/record/doc-1").status_code == 401
    assert client.get("/search?q=deed").status_code == 401
    assert client.get("/record/doc-1", headers=auth()).status_code == 200
    assert client.get("/search?q=deed", headers=auth()).status_code == 200


def test_rate_limit_blocks_mutation(client: TestClient, runtime: Runtime) -> None:
    runtime.store.rate_allowed = False
    response = client.get("/test/tyler", headers=mutation("canary-key"))
    assert response.status_code == 429
    assert runtime.producer.sent == []


def test_multi_dispatch_has_bound(client: TestClient) -> None:
    jobs = [{"county": f"County {index}", "instrument_type": "Deed", "platform": "tyler"} for index in range(101)]
    response = client.post("/scrape/multi", headers=mutation(), json={"jobs": jobs})
    assert response.status_code == 422


def test_fanout_accepts_maximum_length_parent_key(client: TestClient, runtime: Runtime) -> None:
    response = client.post(
        "/scrape/multi",
        headers=mutation("a" * 180),
        json={"jobs": [{"county": "Midland", "instrument_type": "Deed", "platform": "tyler"}]},
    )
    assert response.status_code == 200
    derived_key = next(iter(runtime.store.dispatched))
    assert len(derived_key) <= 180
    assert command_app.SAFE_KEY.fullmatch(derived_key)


def test_dashboard_is_not_placeholder(client: TestClient) -> None:
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "FORGE command plane is online" in response.text
    assert "TODO" not in response.text


def test_scheduler_is_idle_by_default(runtime: Runtime) -> None:
    assert runtime.run_schedules() == {"eligible": 0, "dispatched": 0}
