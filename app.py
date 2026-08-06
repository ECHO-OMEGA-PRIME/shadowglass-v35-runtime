"""Authenticated 17-route replacement for the rescued ShadowGlass v35 Worker."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from collections import OrderedDict, deque
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response

import storage
from core import (
    SERVICE_NAME,
    VERSION,
    DirectScrapeRequest,
    DiscoverRequest,
    ScrapeAllRequest,
    ScrapeMultiRequest,
    ScrapeRequest,
    validate_idempotency_key,
)
from service import (
    JobStateConflict,
    NotFound,
    ServiceUnavailable,
    ShadowglassService,
    credential_text,
)


PUBLIC_PATHS = frozenset({"/health"})
WRITE_TEMPLATES = frozenset(
    {
        "/scrape",
        "/scrape/all",
        "/scrape/multi",
        "/discover",
        "/pause/{id}",
        "/resume/{id}",
        "/scrape/direct",
    }
)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; "
        "img-src 'none'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "Cache-Control": "no-store",
}
MAX_BODY_BYTES = 128_000

logger = logging.getLogger("echo.shadowglass.v35")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(os.getenv("SG_LOG_LEVEL", "INFO").upper())


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = 4096) -> None:
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_keys = max(64, min(max_keys, 65_536))

    def allow(self, key: str, limit: int, seconds: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - seconds
        with self._lock:
            events = self._events.get(key)
            if events is None:
                while len(self._events) >= self._max_keys:
                    self._events.popitem(last=False)
                events = deque()
                self._events[key] = events
            else:
                self._events.move_to_end(key)
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False, max(1, int(seconds - (now - events[0])))
            events.append(now)
            return True, 0


limiter = SlidingWindowLimiter()
app = FastAPI(
    title="ShadowGlass v35",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
_service: ShadowglassService | None = None


def get_service() -> ShadowglassService:
    global _service
    if _service is None:
        _service = ShadowglassService()
    return _service


@lru_cache(maxsize=2)
def _token(name: str) -> str:
    return credential_text(name)


def _presented_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("x-shadowglass-token", "").strip()


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str):
        return template
    path = request.url.path
    for prefix, replacement in (
        ("/record/", "/record/{id}"),
        ("/status/", "/status/{county}"),
        ("/pause/", "/pause/{id}"),
        ("/resume/", "/resume/{id}"),
    ):
        if path.startswith(prefix):
            return replacement
    return path[:120]


def _client_key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return hashlib.sha256(host.encode("utf-8", "ignore")).hexdigest()[:16]


@app.middleware("http")
async def security_middleware(request: Request, call_next: Any) -> Response:
    started = time.monotonic()
    request_id = request.headers.get("x-request-id", "")[:80] or str(uuid.uuid4())
    response: Response
    template = _route_template(request)
    try:
        if request.method == "OPTIONS":
            response = JSONResponse({"detail": "cross-origin requests are disabled"}, status_code=403)
        elif request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > MAX_BODY_BYTES:
                response = JSONResponse({"detail": "request body too large"}, status_code=413)
            else:
                response = await _authorized_response(request, template, call_next)
        else:
            response = await _authorized_response(request, template, call_next)
    except Exception:
        logger.error(
            json.dumps(
                {
                    "event": "request_error",
                    "request_id": request_id,
                    "method": request.method,
                    "path": template,
                },
                sort_keys=True,
            )
        )
        response = JSONResponse(
            {"detail": "internal service error", "request_id": request_id},
            status_code=500,
        )
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    response.headers["X-Request-ID"] = request_id
    response.headers["Vary"] = "Origin"
    duration_ms = round((time.monotonic() - started) * 1000, 2)
    logger.info(
        json.dumps(
            {
                "event": "request",
                "request_id": request_id,
                "method": request.method,
                "path": template,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
            sort_keys=True,
        )
    )
    return response


async def _authorized_response(request: Request, template: str, call_next: Any) -> Response:
    protected = request.url.path not in PUBLIC_PATHS
    is_write = template in WRITE_TEMPLATES
    scope = "public"
    if protected:
        auth_allowed, auth_retry_after = limiter.allow(
            f"auth:{_client_key(request)}", 60
        )
        if not auth_allowed:
            response = JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
            response.headers["Retry-After"] = str(auth_retry_after)
            return response
        presented = _presented_token(request)
        if not presented:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        read_token = _token("api_read_token")
        write_token = _token("api_write_token")
        if not read_token or not write_token:
            return JSONResponse({"detail": "authentication unavailable"}, status_code=503)
        has_read = hmac.compare_digest(presented, read_token)
        has_write = hmac.compare_digest(presented, write_token)
        if is_write and not has_write:
            return JSONResponse({"detail": "write scope required"}, status_code=403)
        if not is_write and not (has_read or has_write):
            return JSONResponse({"detail": "invalid credential"}, status_code=403)
        scope = "write" if has_write else "read"
    limit_name = "SG_WRITE_RATE_LIMIT" if is_write else "SG_READ_RATE_LIMIT"
    default_limit = "30" if is_write else "240"
    limit = max(1, min(int(os.getenv(limit_name, default_limit)), 2000))
    subject = scope if protected else _client_key(request)
    allowed, retry_after = limiter.allow(f"{subject}:{template}:{request.method}", limit)
    if not allowed:
        response = JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        response.headers["Retry-After"] = str(retry_after)
        return response
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse({"detail": "invalid request"}, status_code=422)


@app.exception_handler(NotFound)
async def not_found(_: Request, error: NotFound) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=404)


@app.exception_handler(ServiceUnavailable)
async def service_unavailable(_: Request, __: ServiceUnavailable) -> JSONResponse:
    return JSONResponse({"detail": "service dependency unavailable"}, status_code=503)


@app.exception_handler(JobStateConflict)
async def job_state_conflict(_: Request, __: JobStateConflict) -> JSONResponse:
    return JSONResponse({"detail": "queue job state conflict"}, status_code=409)


@app.exception_handler(storage.IdempotencyConflict)
async def idempotency_conflict(_: Request, __: storage.IdempotencyConflict) -> JSONResponse:
    return JSONResponse({"detail": "idempotency key conflict"}, status_code=409)


def _idempotency(request: Request) -> str:
    try:
        return validate_idempotency_key(request.headers.get("x-idempotency-key"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _dry_run(request: Request) -> bool:
    presented = request.headers.get("x-shadowglass-smoke-token", "").strip()
    expected = _token("api_smoke_token")
    return bool(expected and presented and hmac.compare_digest(presented, expected))


@app.get("/health")
def health() -> JSONResponse:
    try:
        database = get_service().health()["database"]
    except ServiceUnavailable:
        return JSONResponse(
            {
                "service": SERVICE_NAME,
                "version": VERSION,
                "status": "degraded",
                "database": "unavailable",
                "consumer_dependencies": "not-probed-by-api",
                "r2_archive": "unavailable-delta",
            },
            status_code=503,
        )
    return JSONResponse(
        {
            "service": SERVICE_NAME,
            "version": VERSION,
            "status": "healthy",
            "database": database,
            "consumer_dependencies": "isolated-to-consumer",
            "r2_archive": "unavailable-delta",
        }
    )


DASHBOARD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShadowGlass v35</title><style>html{background:#061015;color:#d9f8ff;font-family:ui-sans-serif,system-ui}body{max-width:780px;margin:10vh auto;padding:32px}main{border:1px solid #1a6475;background:linear-gradient(135deg,#0a1b22,#071116);padding:42px;box-shadow:0 30px 80px #0008}h1{font-weight:650;letter-spacing:.04em;color:#85e9ff}p{line-height:1.65;color:#a8cbd3}.line{height:2px;background:linear-gradient(90deg,#39d6ff,transparent);margin:24px 0}code{color:#ffd37a}</style></head><body><main><h1>ShadowGlass v35</h1><div class="line"></div><p>Private-cluster county-record orchestration is online. The API, durable consumer, and hourly scheduler are isolated behind scoped credentials.</p><p>Service identity: <code>shadowglass-v35</code></p></main></body></html>"""


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(DASHBOARD)


@app.get("/stats")
def stats() -> dict[str, Any]:
    return {"service": SERVICE_NAME, **get_service().stats(), "r2_archive": "unavailable-delta"}


@app.get("/counties")
def counties() -> dict[str, Any]:
    rows = get_service().counties()
    return {"counties": rows, "count": len(rows)}


@app.get("/search")
def search(
    q: str | None = Query(default=None, max_length=200),
    county: str | None = Query(default=None, max_length=80),
    type: str | None = Query(default=None, max_length=120),
    grantor: str | None = Query(default=None, max_length=200),
    grantee: str | None = Query(default=None, max_length=200),
    from_: str | None = Query(default=None, alias="from", max_length=32),
    to: str | None = Query(default=None, max_length=32),
    section: str | None = Query(default=None, max_length=120),
    block: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> dict[str, Any]:
    return get_service().search(
        query=q,
        county=county,
        instrument_type=type,
        grantor=grantor,
        grantee=grantee,
        from_date=from_,
        to_date=to,
        section=section,
        block=block,
        limit=limit,
        offset=offset,
    )


@app.get("/record/{id}")
def record(id: int) -> dict[str, Any]:
    if id < 1:
        raise HTTPException(status_code=400, detail="invalid record id")
    return {"record": get_service().record(id), "r2_archive": "unavailable-delta"}


@app.get("/status")
def all_status(limit: int = Query(default=100, ge=1, le=250)) -> dict[str, Any]:
    jobs = get_service().jobs(limit=limit)
    return {"jobs": jobs, "count": len(jobs)}


@app.get("/status/{county}")
def county_status(county: str, limit: int = Query(default=100, ge=1, le=250)) -> dict[str, Any]:
    jobs = get_service().jobs(county=county, limit=limit)
    return {"county": county, "jobs": jobs, "count": len(jobs)}


@app.get("/test/tyler")
def test_tyler(county: str = Query(default="", max_length=80)) -> dict[str, Any]:
    # Provider access is deliberately isolated to the queue consumer. This API
    # compatibility route proves its own database boundary without receiving
    # relay or object-store credentials.
    get_service().health()
    return {
        "ok": True,
        "county_supplied": bool(county),
        "provider_probe": "consumer-owned",
    }


@app.post("/scrape", status_code=202)
def scrape(body: ScrapeRequest, request: Request) -> dict[str, Any]:
    key = _idempotency(request)
    if _dry_run(request):
        return {"status": "preview", "created": False, "jobs": 1}
    job_id, created = get_service().enqueue_scrape(
        county=body.county,
        instrument_type=body.instrumentType,
        start_page=body.startPage,
        end_page=body.startPage,
        idempotency_key=key,
    )
    return {"status": "queued" if created else "replayed", "created": created, "job_id": job_id}


@app.post("/scrape/all", status_code=202)
def scrape_all(body: ScrapeAllRequest, request: Request) -> dict[str, Any]:
    key = _idempotency(request)
    if _dry_run(request):
        return {
            "status": "preview",
            "created": 0,
            "jobs": get_service().instrument_type_count(),
        }
    jobs = get_service().enqueue_county(county=body.county, idempotency_key=key)
    return {"status": "queued", "jobs": len(jobs), "created": sum(created for _, created in jobs)}


@app.post("/scrape/multi", status_code=202)
def scrape_multi(body: ScrapeMultiRequest, request: Request) -> dict[str, Any]:
    key = _idempotency(request)
    if _dry_run(request):
        return {
            "status": "preview",
            "created": 0,
            "jobs": len(body.counties) * get_service().instrument_type_count(),
        }
    jobs: list[tuple[int, bool]] = []
    for index, county in enumerate(body.counties):
        jobs.extend(
            get_service().enqueue_county(
                county=county,
                idempotency_key=f"{key}:county:{index}",
            )
        )
    return {"status": "queued", "jobs": len(jobs), "created": sum(created for _, created in jobs)}


@app.post("/discover", status_code=202)
def discover(body: DiscoverRequest, request: Request) -> dict[str, Any]:
    key = _idempotency(request)
    if _dry_run(request):
        return {
            "status": "preview",
            "created": 0,
            "jobs": get_service().instrument_type_count(),
        }
    jobs = get_service().enqueue_discovery(county=body.county, idempotency_key=key)
    created = sum(was_created for _, was_created in jobs)
    return {"status": "queued", "created": created, "jobs": len(jobs)}


@app.post("/pause/{id}")
def pause(id: int, request: Request) -> dict[str, Any]:
    _idempotency(request)
    if id < 1:
        raise HTTPException(status_code=400, detail="invalid job id")
    if _dry_run(request):
        return {"id": id, "status": "preview-paused"}
    return get_service().set_paused(id, True)


@app.post("/resume/{id}")
def resume(id: int, request: Request) -> dict[str, Any]:
    _idempotency(request)
    if id < 1:
        raise HTTPException(status_code=400, detail="invalid job id")
    if _dry_run(request):
        return {"id": id, "status": "preview-pending"}
    return get_service().set_paused(id, False)


@app.post("/scrape/direct", status_code=202)
def scrape_direct(body: DirectScrapeRequest, request: Request) -> dict[str, Any]:
    key = _idempotency(request)
    if _dry_run(request):
        return {"status": "preview", "created": False, "jobs": 1, "durable": True}
    job_id, created = get_service().enqueue_scrape(
        county=body.county,
        instrument_type=body.instrumentType,
        start_page=0,
        end_page=body.pages - 1,
        idempotency_key=key,
        priority=10,
    )
    return {
        "status": "queued" if created else "replayed",
        "created": created,
        "job_id": job_id,
        "durable": True,
    }
