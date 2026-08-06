from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

import app as module


class FakeService:
    def __init__(self) -> None:
        self.writes: list[str] = []

    def health(self) -> dict[str, str]:
        return {"database": "healthy"}

    def stats(self) -> dict[str, int]:
        return {
            "counties": 102,
            "instrument_types": 21,
            "deed_records": 212600,
            "scrape_jobs": 0,
            "scrape_logs": 0,
            "r2_uploads": 0,
            "queue_pending": 0,
            "queue_processing": 0,
            "queue_dead": 0,
        }

    def counties(self) -> list[dict[str, Any]]:
        return [{"id": 1, "name": "Test", "state": "TX", "platform": "tyler", "is_active": 1}]

    def search(self, **_: Any) -> dict[str, Any]:
        return {"records": [], "total": 0, "limit": 50, "offset": 0}

    def record(self, record_id: int) -> dict[str, Any]:
        return {"id": record_id, "county": "Test"}

    def jobs(self, county: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        return [{"id": 1, "county": county or "Test", "status": "completed"}]

    def enqueue_scrape(self, **_: Any) -> tuple[int, bool]:
        self.writes.append("scrape")
        return 9, True

    def enqueue_county(self, **_: Any) -> list[tuple[int, bool]]:
        self.writes.append("county")
        return [(index, True) for index in range(21)]

    def instrument_type_count(self) -> int:
        return 21

    def enqueue_discovery(self, **_: Any) -> tuple[int, bool]:
        self.writes.append("discover")
        return 10, True

    def set_paused(self, job_id: int, paused: bool) -> dict[str, Any]:
        self.writes.append("paused" if paused else "resumed")
        return {"id": job_id, "status": "paused" if paused else "pending"}


def client(monkeypatch: Any) -> tuple[TestClient, FakeService]:
    service = FakeService()
    monkeypatch.setattr(module, "_service", service)
    monkeypatch.setattr(
        module,
        "_token",
        lambda name: {
            "api_read_token": "read-token",
            "api_write_token": "write-token",
            "api_smoke_token": "smoke-token",
        }.get(name, ""),
    )
    module.limiter = module.SlidingWindowLimiter()
    return TestClient(module.app), service


def headers(token: str = "read-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_exact_recovered_route_contract() -> None:
    expected = {
        ("GET", "/"),
        ("GET", "/dashboard"),
        ("GET", "/health"),
        ("GET", "/stats"),
        ("GET", "/counties"),
        ("GET", "/search"),
        ("GET", "/record/{id}"),
        ("GET", "/status"),
        ("GET", "/status/{county}"),
        ("GET", "/test/tyler"),
        ("POST", "/scrape"),
        ("POST", "/scrape/all"),
        ("POST", "/scrape/multi"),
        ("POST", "/discover"),
        ("POST", "/pause/{id}"),
        ("POST", "/resume/{id}"),
        ("POST", "/scrape/direct"),
    }
    actual: set[tuple[str, str]] = set()
    for route in module.app.routes:
        path = getattr(route, "path", "")
        for method in getattr(route, "methods", set()):
            if method in {"GET", "POST"}:
                actual.add((method, path))
    assert actual == expected


def test_health_and_read_routes(monkeypatch: Any) -> None:
    api, _ = client(monkeypatch)
    response = api.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    for name, expected in module.SECURITY_HEADERS.items():
        assert response.headers[name] == expected
    reads = (
        ("/", "text/html"),
        ("/dashboard", "text/html"),
        ("/stats", "application/json"),
        ("/counties", "application/json"),
        ("/search?q=lease", "application/json"),
        ("/record/1", "application/json"),
        ("/status", "application/json"),
        ("/status/Test", "application/json"),
        ("/test/tyler?county=Test", "application/json"),
    )
    for path, content_type in reads:
        response = api.get(path, headers=headers())
        assert response.status_code == 200, path
        assert content_type in response.headers["content-type"]


def test_auth_scope_and_cors(monkeypatch: Any) -> None:
    api, _ = client(monkeypatch)
    assert api.get("/stats").status_code == 401
    assert api.get("/stats", headers=headers("invalid")).status_code == 403
    body = {"county": "Test", "instrumentType": "Deed", "startPage": 1}
    write_headers = {**headers("read-token"), "X-Idempotency-Key": "test-read-scope"}
    assert api.post("/scrape", headers=write_headers, json=body).status_code == 403
    assert api.options("/stats", headers={"Origin": "https://untrusted.invalid"}).status_code == 403
    response = api.get("/stats", headers={**headers(), "Origin": "https://untrusted.invalid"})
    assert "access-control-allow-origin" not in response.headers


def test_all_write_routes_are_dry_run_safe(monkeypatch: Any) -> None:
    api, service = client(monkeypatch)
    common = {
        **headers("write-token"),
        "X-Shadowglass-Smoke-Token": "smoke-token",
    }
    requests = (
        ("/scrape", {"county": "Test", "instrumentType": "Deed", "startPage": 1}),
        ("/scrape/all", {"county": "Test"}),
        ("/scrape/multi", {"counties": ["Test", "Demo"]}),
        ("/discover", {"county": "Test"}),
        ("/pause/1", None),
        ("/resume/1", None),
        ("/scrape/direct", {"county": "Test", "instrumentType": "Deed", "pages": 2}),
    )
    for index, (path, body) in enumerate(requests):
        request_headers = {**common, "X-Idempotency-Key": f"smoke-write-{index}"}
        response = api.post(path, headers=request_headers, json=body)
        assert response.status_code in {200, 202}, path
        assert "preview" in str(response.json())
    assert service.writes == []


def test_legacy_smoke_header_cannot_suppress_a_write(monkeypatch: Any) -> None:
    api, service = client(monkeypatch)
    response = api.post(
        "/scrape",
        headers={
            **headers("write-token"),
            "X-Idempotency-Key": "legacy-smoke-header-0001",
            "X-Shadowglass-Smoke-Test": "1",
        },
        json={"county": "Test", "instrumentType": "Deed", "startPage": 1},
    )
    assert response.status_code == 202
    assert service.writes == ["scrape"]


def test_write_and_idempotency_validation(monkeypatch: Any) -> None:
    api, service = client(monkeypatch)
    body = {"county": "Test", "instrumentType": "Deed", "startPage": 1}
    assert api.post("/scrape", headers=headers("write-token"), json=body).status_code == 400
    response = api.post(
        "/scrape",
        headers={**headers("write-token"), "X-Idempotency-Key": "real-write-0001"},
        json=body,
    )
    assert response.status_code == 202
    assert response.json()["job_id"] == 9
    assert service.writes == ["scrape"]


def test_invalid_and_oversized_requests_are_bounded(monkeypatch: Any) -> None:
    api, _ = client(monkeypatch)
    write = {**headers("write-token"), "X-Idempotency-Key": "invalid-body-0001"}
    assert api.post("/scrape", headers=write, json={"county": "../bad"}).status_code == 422
    oversized = "x" * (module.MAX_BODY_BYTES + 1)
    assert api.post("/scrape", headers=write, content=oversized).status_code == 413
    assert api.get("/missing", headers=headers()).status_code == 404
