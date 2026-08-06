"""Authenticated FORGE replacement for the recovered ShadowGlass command Worker."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Mapping

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from provider_queue import CloudflareQueueProducer, ProviderQueueError
from storage import CommandStore, DispatchInDoubt, IdempotencyConflict


LOGGER = logging.getLogger("shadowglass.command")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
SERVICE_DIR = Path(os.getenv("SHADOWGLASS_COMMAND_CREDENTIAL_DIR", "/etc/echo/credentials/shadowglass-v7-command"))
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,99}$")
SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,179}$")


def _credential(name: str, environment: str) -> str:
    value = os.getenv(environment, "").strip()
    if value:
        return value
    broker = os.getenv("CREDENTIALS_DIRECTORY", "").strip()
    path = (Path(broker) / name) if broker else (SERVICE_DIR / name)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"required credential is unavailable: {name}") from exc
    if not value:
        raise RuntimeError(f"required credential is empty: {name}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    command_key: str
    cors_origins: tuple[str, ...]
    account_id: str
    queue_token: str
    queue_ids: Mapping[str, str]
    version: str
    environment: str

    @classmethod
    def load(cls) -> "Settings":
        origins = tuple(
            item.strip()
            for item in _credential("cors-origins", "CORS_ORIGINS").split(",")
            if item.strip()
        )
        if not origins or any(not item.startswith(("https://", "http://127.0.0.1")) for item in origins):
            raise RuntimeError("CORS allowlist is invalid")
        return cls(
            database_url=_credential("database-url", "DATABASE_URL"),
            command_key=_credential("command-key", "COMMAND_KEY"),
            cors_origins=origins,
            account_id=_credential("cloudflare-account-id", "CLOUDFLARE_ACCOUNT_ID"),
            queue_token=_credential("cloudflare-queue-token", "CLOUDFLARE_QUEUE_TOKEN"),
            queue_ids={
                "publicsearch": _credential("ps-queue-id", "PS_QUEUE_ID"),
                "texasfile": _credential("tf-queue-id", "TF_QUEUE_ID"),
                "tyler": _credential("tyler-queue-id", "TYLER_QUEUE_ID"),
            },
            version=os.getenv("SERVICE_VERSION", "dev"),
            environment=os.getenv("ENVIRONMENT", "production"),
        )


class DispatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    county: str = Field(min_length=1, max_length=100)
    instrument_type: str = Field(min_length=1, max_length=120)
    platform: Literal["publicsearch", "texasfile", "tyler"]
    start_page: int = Field(default=0, ge=0, le=100_000)
    end_page: int = Field(default=0, ge=0, le=100_000)

    @field_validator("county", "instrument_type")
    @classmethod
    def safe_names(cls, value: str | None) -> str | None:
        if value is not None and not SAFE_NAME.fullmatch(value):
            raise ValueError("name contains unsupported characters")
        return value


class MultiDispatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jobs: list[DispatchBody] = Field(min_length=1, max_length=100)


class PlatformDispatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: Literal["publicsearch", "texasfile", "tyler"]
    counties: list[str] = Field(min_length=1, max_length=100)
    instrument_type: str | None = Field(default=None, max_length=120)

    @field_validator("counties")
    @classmethod
    def safe_counties(cls, values: list[str]) -> list[str]:
        if any(not SAFE_NAME.fullmatch(value) for value in values):
            raise ValueError("county contains unsupported characters")
        return values


def _child_key(parent: str, discriminator: int) -> str:
    """Derive a stable bounded key for fan-out and scheduled dispatches."""
    candidate = f"{parent}:{discriminator}"
    if len(candidate) <= 180:
        return candidate
    return f"{hashlib.sha256(parent.encode()).hexdigest()}:{discriminator}"


@dataclass(slots=True)
class Runtime:
    settings: Settings
    store: CommandStore
    producer: CloudflareQueueProducer

    def authenticate(self, supplied: str | None) -> str:
        candidate = (supplied or "").strip()
        if candidate.lower().startswith("bearer "):
            candidate = candidate[7:].strip()
        if not candidate or not hmac.compare_digest(candidate, self.settings.command_key):
            raise HTTPException(status_code=401, detail="authentication required")
        return hashlib.sha256(candidate.encode()).hexdigest()

    def dispatch(
        self,
        *,
        action: str,
        target: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not SAFE_KEY.fullmatch(idempotency_key):
            raise HTTPException(status_code=400, detail="valid Idempotency-Key required")
        canonical = {"type": action, **dict(payload)}
        try:
            reservation = self.store.reserve_dispatch(
                idempotency_key=idempotency_key,
                target=target,
                action=action,
                payload=canonical,
            )
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except DispatchInDoubt as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if not reservation.created:
            return {"ok": True, "duplicate": True, "state": reservation.state}
        try:
            self.producer.send(target, canonical)
            self.store.mark_dispatched(reservation.receipt_id)
        except ProviderQueueError as exc:
            self.store.mark_failed(reservation.receipt_id, type(exc).__name__)
            raise HTTPException(status_code=503, detail="queue provider unavailable") from exc
        return {"ok": True, "duplicate": False, "state": "dispatched"}

    def run_schedules(self, limit: int = 25) -> dict[str, int]:
        rows = self.store.query("schedules", (limit,), limit=limit)
        dispatched = 0
        for row in rows:
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            epoch_slot = int(time.time()) // 60
            key = _child_key(str(row["idempotency_prefix"]), epoch_slot)
            self.dispatch(
                action=str(row["action"]),
                target=str(row["target_queue"]),
                payload=payload,
                idempotency_key=key,
            )
            self.store.advance_schedule(int(row["id"]))
            dispatched += 1
        return {"eligible": len(rows), "dispatched": dispatched}


@lru_cache(maxsize=1)
def get_runtime() -> Runtime:
    settings = Settings.load()
    return Runtime(
        settings=settings,
        store=CommandStore(settings.database_url),
        producer=CloudflareQueueProducer(
            account_id=settings.account_id,
            token=settings.queue_token,
            targets=settings.queue_ids,
        ),
    )


app = FastAPI(
    title="ShadowGlass v7 Command",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def security_and_observability(request: Request, call_next: Any) -> Any:
    started = time.perf_counter()
    request_id = hashlib.sha256(os.urandom(24)).hexdigest()[:20]
    origin = request.headers.get("origin", "")
    allowed_origin = ""
    try:
        settings = get_runtime().settings
        if origin and origin in settings.cors_origins:
            allowed_origin = origin
        if request.method == "OPTIONS":
            if not allowed_origin:
                return JSONResponse(status_code=403, content={"detail": "origin not allowed"})
            response = JSONResponse(status_code=204, content=None)
        else:
            response = await call_next(request)
    except Exception:
        LOGGER.exception(json.dumps({"event": "request_failed", "request_id": request_id}))
        raise
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Request-ID"] = request_id
    if allowed_origin:
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Authorization, Content-Type, Idempotency-Key, X-Echo-Command-Key"
        )
        response.headers["Vary"] = "Origin"
    LOGGER.info(
        json.dumps(
            {
                "event": "request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
            separators=(",", ":"),
        )
    )
    return response


def _runtime() -> Runtime:
    return get_runtime()


def _subject(
    authorization: str | None = Header(default=None),
    x_echo_command_key: str | None = Header(default=None),
    runtime: Runtime = Depends(_runtime),
) -> str:
    return runtime.authenticate(x_echo_command_key or authorization)


def _key(idempotency_key: str | None = Header(default=None)) -> str:
    candidate = (idempotency_key or "").strip()
    if not SAFE_KEY.fullmatch(candidate):
        raise HTTPException(status_code=400, detail="valid Idempotency-Key required")
    return candidate


def _mutation_guard(
    request: Request,
    subject: str = Depends(_subject),
    runtime: Runtime = Depends(_runtime),
) -> str:
    if not runtime.store.rate_limit(subject, request.url.path, 60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    return subject


def _payload(body: DispatchBody, runtime: Runtime) -> dict[str, Any]:
    if body.end_page < body.start_page:
        raise HTTPException(status_code=400, detail="end_page precedes start_page")
    try:
        context = runtime.store.resolve_context(
            body.county, body.instrument_type, body.platform
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "county": context["county"],
        "countyId": context["county_id"],
        "instrumentType": context["instrument_type"],
        "instrumentTypeId": context["instrument_type_id"],
        "platform": context["platform"],
        "startPage": body.start_page,
        "endPage": body.end_page,
        "retry": 0,
    }


def _dashboard() -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' "
        "content='width=device-width,initial-scale=1'><title>ShadowGlass Command</title>"
        "<style>body{background:#07111f;color:#d9e8ff;font:16px system-ui;margin:4rem}"
        "main{max-width:760px;padding:2rem;border:1px solid #31547b;background:#0b192b}"
        "h1{color:#71c7ff}code{color:#b8e3ff}</style></head><body><main>"
        "<h1>ShadowGlass v7 Command</h1><p>FORGE command plane is online.</p>"
        "<p>Mutations require authenticated, idempotent API requests.</p></main></body></html>"
    )


@app.get("/")
def root() -> HTMLResponse:
    return _dashboard()


@app.get("/counties")
def counties(runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    return {"counties": runtime.store.query("counties", (500,), limit=500)}


@app.get("/dashboard")
def dashboard() -> HTMLResponse:
    return _dashboard()


@app.get("/health")
def health(runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    try:
        runtime.store.query("ping", (), limit=1)
    except Exception:
        return JSONResponse(status_code=503, content={"ok": False, "status": "degraded"})
    return {"ok": True, "status": "healthy", "version": runtime.settings.version}


@app.get("/record/{record_id}")
def record(record_id: str, _: str = Depends(_subject), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    if len(record_id) > 200 or any(ord(char) < 32 for char in record_id):
        raise HTTPException(status_code=400, detail="invalid record identity")
    numeric = int(record_id) if record_id.isdigit() else -1
    rows = runtime.store.query("record", (numeric, record_id), limit=1)
    if not rows:
        raise HTTPException(status_code=404, detail="record not found")
    return {"record": rows[0]}


@app.get("/search")
def search(q: str = Query(min_length=2, max_length=120), limit: int = Query(50, ge=1, le=200), _: str = Depends(_subject), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    pattern = f"%{q.replace('%', '').replace('_', '')}%"
    return {"records": runtime.store.query("search", (pattern, pattern, pattern, pattern, limit), limit=limit)}


@app.get("/stats")
def stats(runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    rows = runtime.store.query("stats", (), limit=1)
    return rows[0] if rows else {}


@app.get("/status")
def status(_: str = Depends(_subject), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    return {"jobs": runtime.store.query("status_all", (500,), limit=500)}


@app.get("/status/{county}")
def status_county(county: str, _: str = Depends(_subject), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    if not SAFE_NAME.fullmatch(county):
        raise HTTPException(status_code=400, detail="invalid county")
    return {"jobs": runtime.store.query("status_county", (county, 500), limit=500)}


@app.get("/test/tyler")
def test_tyler(_: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    return runtime.dispatch(action="acceptance_canary", target="tyler", payload={"canary": True}, idempotency_key=key)


@app.post("/discover")
def discover(body: DispatchBody, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    return runtime.dispatch(action="discover", target=body.platform, payload=_payload(body, runtime), idempotency_key=key)


@app.post("/pause/{county}")
def pause(county: str, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    if not SAFE_NAME.fullmatch(county):
        raise HTTPException(status_code=400, detail="invalid county")
    return {"ok": True, "changed": runtime.store.set_job_state(county, "paused"), "idempotency_key_sha256": hashlib.sha256(key.encode()).hexdigest()}


@app.post("/resume/{county}")
def resume(county: str, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    if not SAFE_NAME.fullmatch(county):
        raise HTTPException(status_code=400, detail="invalid county")
    return {"ok": True, "changed": runtime.store.set_job_state(county, "pending"), "idempotency_key_sha256": hashlib.sha256(key.encode()).hexdigest()}


@app.post("/scrape")
def scrape(body: DispatchBody, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    return runtime.dispatch(action="scrape", target=body.platform, payload=_payload(body, runtime), idempotency_key=key)


@app.post("/scrape/all")
def scrape_all(body: PlatformDispatchBody, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    contexts = runtime.store.resolve_contexts(
        body.counties, body.platform, body.instrument_type, limit=100
    )
    if not contexts:
        raise HTTPException(status_code=404, detail="no active contexts matched")
    results = []
    for index, context in enumerate(contexts):
        payload = {"county": context["county"], "countyId": context["county_id"], "instrumentType": context["instrument_type"], "instrumentTypeId": context["instrument_type_id"], "platform": context["platform"], "startPage": 0, "endPage": 0, "retry": 0}
        results.append(runtime.dispatch(action="scrape", target=body.platform, payload=payload, idempotency_key=_child_key(key, index)))
    return {"ok": True, "submitted": len(results)}


@app.post("/scrape/multi")
def scrape_multi(body: MultiDispatchBody, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    for index, job in enumerate(body.jobs):
        runtime.dispatch(action="scrape", target=job.platform, payload=_payload(job, runtime), idempotency_key=_child_key(key, index))
    return {"ok": True, "submitted": len(body.jobs)}


@app.post("/scrape/platform")
def scrape_platform(body: PlatformDispatchBody, _: str = Depends(_mutation_guard), key: str = Depends(_key), runtime: Runtime = Depends(_runtime)) -> dict[str, Any]:
    contexts = runtime.store.resolve_contexts(
        body.counties, body.platform, body.instrument_type, limit=100
    )
    if not contexts:
        raise HTTPException(status_code=404, detail="no active contexts matched")
    for index, context in enumerate(contexts):
        runtime.dispatch(action="scrape", target=body.platform, payload={"county": context["county"], "countyId": context["county_id"], "instrumentType": context["instrument_type"], "instrumentTypeId": context["instrument_type_id"], "platform": context["platform"], "startPage": 0, "endPage": 0, "retry": 0}, idempotency_key=_child_key(key, index))
    return {"ok": True, "submitted": len(contexts), "platform": body.platform}
