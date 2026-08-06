"""PostgreSQL persistence for the ShadowGlass v35 migration.

All identifiers in this module are constants owned by this service.  Caller data is
always passed as query parameters; callers cannot select schemas, tables, or SQL.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ContextManager, Iterator, Mapping, Protocol

SCHEMA = "cf_shadowglass_v35"
SUPPORTED_PAYLOAD_VERSION = 1


class IdempotencyConflict(RuntimeError):
    """An idempotency key was reused for different immutable work."""


class LeaseFenceRejected(RuntimeError):
    """An object write was attempted by a stale or expired lease owner."""


class Cursor(Protocol):
    """Minimal DB-API cursor surface used by this module."""

    rowcount: int

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> Any: ...

    def fetchone(self) -> Any: ...

    def fetchall(self) -> list[Any]: ...


class Connection(Protocol):
    """Minimal connection surface shared by psycopg2 and test fakes."""

    def cursor(self) -> ContextManager[Cursor]: ...


@dataclass(frozen=True, slots=True)
class QueueJob:
    """A leased queue item.  The lease token is required for all state changes."""

    id: int
    job_kind: str
    payload: Mapping[str, Any]
    payload_version: int
    idempotency_key: str
    attempts: int
    max_attempts: int
    lease_token: uuid.UUID
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class JobContext:
    """Immutable county and instrument context hydrated from migrated state."""

    county_id: int
    county: str
    base_url: str
    platform: str
    instrument_type_id: int
    instrument_type: str


@dataclass(slots=True)
class LeaseWriteFence:
    """Short-lived proof that a specific object key is write-fenced."""

    job_id: int
    lease_token: uuid.UUID
    object_key: str
    _active: bool = True

    @property
    def active(self) -> bool:
        return self._active

    def _close(self) -> None:
        self._active = False


@dataclass(frozen=True, slots=True)
class QueueJobState:
    """Non-payload queue status used by release canary verification."""

    state: str
    attempts: int
    max_attempts: int
    dead_lettered: bool


def connect(dsn: str) -> Any:
    """Open a psycopg2 connection returning rows as mappings."""

    if not dsn or not dsn.strip():
        raise ValueError("a non-empty PostgreSQL DSN is required")
    import psycopg2
    from psycopg2.extras import RealDictCursor

    return psycopg2.connect(dsn, cursor_factory=RealDictCursor)


def _transaction(connection: Any) -> ContextManager[Any]:
    transaction = getattr(connection, "transaction", None)
    if callable(transaction):
        return transaction()
    if hasattr(connection, "__enter__") and hasattr(connection, "__exit__"):
        return connection
    return nullcontext(connection)


def _advisory_lock_id(scope: str, identity: str) -> int:
    raw = int.from_bytes(
        hashlib.sha256(f"{scope}:{identity}".encode("utf-8")).digest()[:8], "big"
    )
    return raw if raw < 2**63 else raw - 2**64


@contextmanager
def lease_write_fence(
    connection: Connection,
    *,
    job_id: int,
    lease_token: uuid.UUID,
    object_key: str,
) -> Iterator[LeaseWriteFence]:
    """Fence one object write with DB locks and live-token validation.

    The transaction-level job lock serializes old/new owners of the same queue
    row.  The object-key lock also serializes distinct jobs targeting the same
    deterministic object.  ``FOR UPDATE`` prevents lease recovery or reassignment
    during the object-store operation.  Token/expiry are checked only after both
    locks have been acquired, closing the stale-owner race.
    """

    if job_id < 1 or not object_key or len(object_key) > 1024:
        raise ValueError("invalid lease-fence identity")
    proof: LeaseWriteFence | None = None
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (_advisory_lock_id("shadowglass-v35-job", str(job_id)),),
            )
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (_advisory_lock_id("shadowglass-v35-object", object_key),),
            )
            cursor.execute(
                f"""
                SELECT id
                FROM {SCHEMA}.work_queue
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                  AND lease_expires_at > clock_timestamp()
                FOR UPDATE
                """,
                (job_id, str(lease_token)),
            )
            if cursor.fetchone() is None:
                raise LeaseFenceRejected("object write lease is no longer live")
            proof = LeaseWriteFence(job_id, lease_token, object_key)
            try:
                yield proof
            finally:
                proof._close()


def get_queue_job_state(connection: Connection, *, job_id: int) -> QueueJobState:
    """Read state/attempt evidence without reading or returning the payload."""

    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT queue.state, queue.attempts, queue.max_attempts,
                   (dead.queue_id IS NOT NULL) AS dead_lettered
            FROM {SCHEMA}.work_queue AS queue
            LEFT JOIN {SCHEMA}.work_queue_dead_letter AS dead
              ON dead.queue_id = queue.id
            WHERE queue.id = %s
            """,
            (job_id,),
        )
        item = _as_mapping(
            cursor.fetchone(), ("state", "attempts", "max_attempts", "dead_lettered")
        )
    return QueueJobState(
        state=str(item["state"]),
        attempts=int(item["attempts"]),
        max_attempts=int(item["max_attempts"]),
        dead_lettered=bool(item["dead_lettered"]),
    )


def _as_mapping(row: Any, columns: tuple[str, ...]) -> Mapping[str, Any]:
    if isinstance(row, Mapping):
        return row
    if row is None:
        raise LookupError("expected a database row")
    return dict(zip(columns, row, strict=True))


def _decode_payload(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        decoded = json.loads(value)
        if isinstance(decoded, Mapping):
            return decoded
    raise ValueError("queue payload is not a JSON object")


def _job_from_row(row: Any) -> QueueJob:
    columns = (
        "id",
        "job_kind",
        "payload",
        "payload_version",
        "idempotency_key",
        "attempts",
        "max_attempts",
        "lease_token",
        "lease_expires_at",
    )
    item = _as_mapping(row, columns)
    return QueueJob(
        id=int(item["id"]),
        job_kind=str(item["job_kind"]),
        payload=_decode_payload(item["payload"]),
        payload_version=int(item["payload_version"]),
        idempotency_key=str(item["idempotency_key"]),
        attempts=int(item["attempts"]),
        max_attempts=int(item["max_attempts"]),
        lease_token=uuid.UUID(str(item["lease_token"])),
        lease_expires_at=item["lease_expires_at"],
    )


def enqueue_job(
    connection: Connection,
    *,
    job_kind: str,
    payload: Mapping[str, Any],
    idempotency_key: str,
    priority: int = 100,
    max_attempts: int = 5,
    payload_version: int = SUPPORTED_PAYLOAD_VERSION,
) -> tuple[int, bool]:
    """Insert one pending job, returning ``(id, created)``.

    Reusing an idempotency key is a no-op and returns the existing row id.  It
    never mutates the existing payload, which prevents a key collision from
    silently changing queued work.
    """

    if not job_kind.strip() or not idempotency_key.strip():
        raise ValueError("job_kind and idempotency_key must be non-empty")
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    if not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    query = f"""
        INSERT INTO {SCHEMA}.work_queue
            (job_kind, payload, payload_version, idempotency_key, priority, max_attempts)
        VALUES (%s, %s::jsonb, %s, %s, %s, %s)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING id
    """
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                query,
                (job_kind, encoded, payload_version, idempotency_key, priority, max_attempts),
            )
            row = cursor.fetchone()
            if row is not None:
                item = _as_mapping(row, ("id",))
                return int(item["id"]), True
            cursor.execute(
                f"""
                SELECT id, job_kind, payload, payload_version
                FROM {SCHEMA}.work_queue
                WHERE idempotency_key = %s
                """,
                (idempotency_key,),
            )
            existing = _as_mapping(
                cursor.fetchone(), ("id", "job_kind", "payload", "payload_version")
            )
            if (
                str(existing["job_kind"]) != job_kind
                or int(existing["payload_version"]) != payload_version
                or json.dumps(
                    _decode_payload(existing["payload"]),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                != encoded
            ):
                raise IdempotencyConflict(
                    "idempotency key is already bound to different work"
                )
            return int(existing["id"]), False


def load_job_context(connection: Connection, payload: Mapping[str, Any]) -> JobContext:
    """Hydrate and cross-check caller-independent scrape context."""

    county_id = int(payload.get("countyId") or 0)
    instrument_id = int(payload.get("instrumentTypeId") or 0)
    if county_id < 1 or instrument_id < 1:
        raise ValueError("queue payload lacks county or instrument identity")
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT c.id AS county_id, c.name AS county, c.base_url, c.platform,
                   i.id AS instrument_type_id, i.name AS instrument_type
            FROM {SCHEMA}.counties c
            CROSS JOIN {SCHEMA}.instrument_types i
            WHERE c.id = %s AND i.id = %s AND c.is_active <> 0
            """,
            (county_id, instrument_id),
        )
        row = cursor.fetchone()
    if row is None:
        raise LookupError("queue context does not identify an active county/instrument")
    item = _as_mapping(
        row,
        (
            "county_id",
            "county",
            "base_url",
            "platform",
            "instrument_type_id",
            "instrument_type",
        ),
    )
    if (
        str(payload.get("county") or "").casefold() != str(item["county"]).casefold()
        or str(payload.get("instrumentType") or "").casefold()
        != str(item["instrument_type"]).casefold()
    ):
        raise ValueError("queue context names do not match migrated identities")
    return JobContext(
        county_id=int(item["county_id"]),
        county=str(item["county"]),
        base_url=str(item["base_url"]),
        platform=str(item["platform"] or ""),
        instrument_type_id=int(item["instrument_type_id"]),
        instrument_type=str(item["instrument_type"]),
    )


def complete_discovery(
    connection: Connection,
    *,
    job: QueueJob,
    context: JobContext,
    total_records: int,
    page_count: int,
) -> int:
    """Persist discovery, enqueue its pages, and ACK the lease atomically."""

    if total_records < 0 or not 0 <= page_count <= 10_000:
        raise ValueError("discovery result is outside safe bounds")
    queued = 0
    with _transaction(connection):
        with connection.cursor() as cursor:
            status = "completed" if page_count == 0 else "pending"
            cursor.execute(
                f"""
                INSERT INTO {SCHEMA}.scrape_jobs
                  (county_id, instrument_type_id, status, total_records,
                   scraped_records, last_page, updated_at, completed_at)
                VALUES (%s, %s, %s, %s, 0, -1, clock_timestamp()::text,
                        CASE WHEN %s = 'completed' THEN clock_timestamp()::text END)
                ON CONFLICT (county_id, instrument_type_id) DO UPDATE SET
                  status = EXCLUDED.status,
                  total_records = EXCLUDED.total_records,
                  scraped_records = 0,
                  last_page = -1,
                  updated_at = EXCLUDED.updated_at,
                  completed_at = EXCLUDED.completed_at
                """,
                (
                    context.county_id,
                    context.instrument_type_id,
                    status,
                    total_records,
                    status,
                ),
            )
            for page in range(page_count):
                payload = {
                    "type": "scrape",
                    "county": context.county,
                    "countyId": context.county_id,
                    "instrumentType": context.instrument_type,
                    "instrumentTypeId": context.instrument_type_id,
                    "startPage": page,
                    "endPage": page,
                    "platform": context.platform,
                    "retry": 0,
                }
                cursor.execute(
                    f"""
                    INSERT INTO {SCHEMA}.work_queue
                      (job_kind, payload, payload_version, idempotency_key, priority)
                    VALUES ('scrape', %s::jsonb, %s, %s, 100)
                    ON CONFLICT (idempotency_key) DO NOTHING
                    """,
                    (
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        SUPPORTED_PAYLOAD_VERSION,
                        f"discovery:{job.id}:page:{page}",
                    ),
                )
                queued += max(cursor.rowcount, 0)
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'completed', completed_at = clock_timestamp(),
                    updated_at = clock_timestamp(), leased_by = NULL,
                    lease_token = NULL, lease_expires_at = NULL, last_error = NULL
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                  AND lease_expires_at > clock_timestamp()
                """,
                (job.id, str(job.lease_token)),
            )
            if cursor.rowcount != 1:
                raise LookupError("discovery lease expired before atomic completion")
    return queued


def complete_scrape(
    connection: Connection,
    *,
    job: QueueJob,
    context: JobContext,
    pages: list[Mapping[str, Any]],
) -> int:
    """Persist page receipts, normalized records, checkpoint, and queue ACK."""

    record_count = 0
    with _transaction(connection):
        with connection.cursor() as cursor:
            for page in pages:
                records = list(page.get("records") or [])
                object_key = str(page["object_key"])
                page_number = int(page["page"])
                cursor.execute(
                    f"""
                    INSERT INTO {SCHEMA}.r2_uploads
                      (r2_key, county_id, instrument_type_id, page_number,
                       record_count, uploaded_at)
                    VALUES (%s, %s, %s, %s, %s, clock_timestamp()::text)
                    ON CONFLICT (r2_key) DO UPDATE SET
                      record_count = EXCLUDED.record_count,
                      uploaded_at = EXCLUDED.uploaded_at
                    """,
                    (
                        object_key,
                        context.county_id,
                        context.instrument_type_id,
                        page_number,
                        len(records),
                    ),
                )
                for record in records:
                    external_id = str(record.get("id") or "")[:500] or None
                    cursor.execute(
                        f"""
                        INSERT INTO {SCHEMA}.deed_records
                          (external_id, county, instrument_type, instrument_type_id,
                           grantor, grantee, recorded_date, filing_date,
                           legal_description, book, page_num, doc_number,
                           consideration, source_url, r2_key, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s, clock_timestamp()::text)
                        ON CONFLICT (county, instrument_type, external_id)
                          WHERE external_id IS NOT NULL
                        DO UPDATE SET
                          grantor = EXCLUDED.grantor,
                          grantee = EXCLUDED.grantee,
                          recorded_date = EXCLUDED.recorded_date,
                          filing_date = EXCLUDED.filing_date,
                          legal_description = EXCLUDED.legal_description,
                          book = EXCLUDED.book,
                          page_num = EXCLUDED.page_num,
                          doc_number = EXCLUDED.doc_number,
                          consideration = EXCLUDED.consideration,
                          source_url = EXCLUDED.source_url,
                          r2_key = EXCLUDED.r2_key
                        """,
                        (
                            external_id,
                            context.county,
                            context.instrument_type,
                            context.instrument_type_id,
                            str(record.get("grantor") or "")[:2000],
                            str(record.get("grantee") or "")[:2000],
                            str(record.get("recordedDate") or "")[:100],
                            str(record.get("filingDate") or "")[:100],
                            str(record.get("legalDescription") or "")[:8000],
                            str(record.get("bookPage") or "")[:200],
                            str(record.get("bookPage") or "")[:200],
                            external_id,
                            str(record.get("consideration") or "")[:500],
                            str(record.get("pdfUrl") or "")[:4000],
                            object_key,
                        ),
                    )
                record_count += len(records)
                cursor.execute(
                    f"""
                    INSERT INTO {SCHEMA}.scrape_logs
                      (job_id, level, message, metadata, created_at)
                    SELECT id, 'info', 'persisted page object', %s, clock_timestamp()::text
                    FROM {SCHEMA}.scrape_jobs
                    WHERE county_id = %s AND instrument_type_id = %s
                    """,
                    (
                        json.dumps(
                            {
                                "object_sha256": str(page.get("sha256") or ""),
                                "page": page_number,
                                "records": len(records),
                            },
                            separators=(",", ":"),
                        ),
                        context.county_id,
                        context.instrument_type_id,
                    ),
                )
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'completed', completed_at = clock_timestamp(),
                    updated_at = clock_timestamp(), leased_by = NULL,
                    lease_token = NULL, lease_expires_at = NULL, last_error = NULL
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                  AND lease_expires_at > clock_timestamp()
                """,
                (job.id, str(job.lease_token)),
            )
            if cursor.rowcount != 1:
                raise LookupError("scrape lease expired before atomic completion")
            cursor.execute(
                f"""
                SELECT EXISTS (
                    SELECT 1
                    FROM {SCHEMA}.work_queue
                    WHERE id <> %s
                      AND job_kind = 'scrape'
                      AND state IN ('pending', 'paused', 'processing')
                      AND payload ->> 'countyId' = %s
                      AND payload ->> 'instrumentTypeId' = %s
                ) AS has_remaining
                """,
                (
                    job.id,
                    str(context.county_id),
                    str(context.instrument_type_id),
                ),
            )
            remaining_row = _as_mapping(cursor.fetchone(), ("has_remaining",))
            has_remaining = bool(remaining_row["has_remaining"])
            job_status = "running" if has_remaining else "completed"
            last_page = max((int(page["page"]) for page in pages), default=-1)
            cursor.execute(
                f"""
                INSERT INTO {SCHEMA}.scrape_jobs
                  (county_id, instrument_type_id, status, total_records,
                   scraped_records, last_page, started_at, completed_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s,
                        clock_timestamp()::text,
                        CASE WHEN %s = 'completed' THEN clock_timestamp()::text END,
                        clock_timestamp()::text)
                ON CONFLICT (county_id, instrument_type_id) DO UPDATE SET
                  status = EXCLUDED.status,
                  scraped_records = COALESCE(
                      {SCHEMA}.scrape_jobs.scraped_records, 0
                  ) + EXCLUDED.scraped_records,
                  last_page = GREATEST(
                      COALESCE({SCHEMA}.scrape_jobs.last_page, -1),
                      EXCLUDED.last_page
                  ),
                  completed_at = EXCLUDED.completed_at,
                  updated_at = EXCLUDED.updated_at
                """,
                (
                    context.county_id,
                    context.instrument_type_id,
                    job_status,
                    record_count,
                    record_count,
                    last_page,
                    job_status,
                ),
            )
    return record_count


def recover_stale_leases(connection: Connection) -> tuple[int, int]:
    """Requeue expired leases or dead-letter jobs whose attempts are exhausted."""

    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO {SCHEMA}.work_queue_dead_letter
                    (queue_id, job_kind, payload, payload_version, idempotency_key,
                     attempts, max_attempts, last_error)
                SELECT id, job_kind, payload, payload_version, idempotency_key,
                       attempts, max_attempts, COALESCE(last_error, 'lease expired')
                FROM {SCHEMA}.work_queue
                WHERE state = 'processing'
                  AND lease_expires_at <= clock_timestamp()
                  AND attempts >= max_attempts
                ON CONFLICT (queue_id) DO NOTHING
                """
            )
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'dead', leased_by = NULL, lease_token = NULL,
                    lease_expires_at = NULL, updated_at = clock_timestamp(),
                    last_error = COALESCE(last_error, 'lease expired')
                WHERE state = 'processing'
                  AND lease_expires_at <= clock_timestamp()
                  AND attempts >= max_attempts
                """
            )
            dead = max(cursor.rowcount, 0)
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'pending', leased_by = NULL, lease_token = NULL,
                    lease_expires_at = NULL, available_at = clock_timestamp(),
                    updated_at = clock_timestamp(),
                    last_error = COALESCE(last_error, 'lease expired')
                WHERE state = 'processing'
                  AND lease_expires_at <= clock_timestamp()
                  AND attempts < max_attempts
                """
            )
            requeued = max(cursor.rowcount, 0)
    return requeued, dead


def extend_lease(
    connection: Connection,
    *,
    job_id: int,
    lease_token: uuid.UUID,
    lease_seconds: int,
) -> bool:
    """Extend an owned live lease during bounded remote work."""

    if not 30 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 30 and 3600")
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET lease_expires_at = clock_timestamp() + make_interval(secs => %s),
                    updated_at = clock_timestamp()
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                  AND lease_expires_at > clock_timestamp()
                """,
                (lease_seconds, job_id, str(lease_token)),
            )
            return cursor.rowcount == 1


def claim_job(
    connection: Connection,
    *,
    worker_id: str,
    lease_seconds: int = 120,
    claim_kind: str | None = None,
) -> QueueJob | None:
    """Atomically claim the highest-priority eligible job with SKIP LOCKED."""

    if not worker_id.strip():
        raise ValueError("worker_id must be non-empty")
    if not 5 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 5 and 3600")
    if claim_kind not in (None, "acceptance_canary"):
        raise ValueError("claim_kind is not an approved isolated claim mode")
    recover_stale_leases(connection)
    token = uuid.uuid4()
    kind_clause = "" if claim_kind is None else "AND job_kind = %s"
    query = f"""
        WITH candidate AS (
            SELECT id
            FROM {SCHEMA}.work_queue
            WHERE state = 'pending'
              AND available_at <= clock_timestamp()
              AND attempts < max_attempts
               AND (
                     job_kind <> 'acceptance_canary'
                     OR payload ->> 'targetWorkerId' = %s
               )
              {kind_clause}
            ORDER BY priority ASC, available_at ASC, id ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE {SCHEMA}.work_queue AS queue
        SET state = 'processing', attempts = queue.attempts + 1,
            leased_by = %s, lease_token = %s,
            lease_expires_at = clock_timestamp() + make_interval(secs => %s),
            updated_at = clock_timestamp()
        FROM candidate
        WHERE queue.id = candidate.id
        RETURNING queue.id, queue.job_kind, queue.payload, queue.payload_version,
                  queue.idempotency_key, queue.attempts, queue.max_attempts,
                  queue.lease_token, queue.lease_expires_at
    """
    with _transaction(connection):
        with connection.cursor() as cursor:
            parameters: list[Any] = [worker_id]
            if claim_kind is not None:
                parameters.append(claim_kind)
            parameters.extend((worker_id, str(token), lease_seconds))
            cursor.execute(query, tuple(parameters))
            row = cursor.fetchone()
    return None if row is None else _job_from_row(row)


def renew_lease(
    connection: Connection,
    *,
    job_id: int,
    lease_token: uuid.UUID,
    lease_seconds: int = 120,
) -> bool:
    """Extend a live lease without allowing lease ownership to change."""

    if not 5 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 5 and 3600")
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET lease_expires_at = clock_timestamp() + make_interval(secs => %s),
                    updated_at = clock_timestamp()
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                  AND lease_expires_at > clock_timestamp()
                """,
                (lease_seconds, job_id, str(lease_token)),
            )
            return cursor.rowcount == 1


def complete_job(
    connection: Connection, *, job_id: int, lease_token: uuid.UUID
) -> bool:
    """Acknowledge a job only when the caller still owns its live lease."""

    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'completed', completed_at = clock_timestamp(),
                    updated_at = clock_timestamp(), leased_by = NULL,
                    lease_token = NULL, lease_expires_at = NULL, last_error = NULL
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                  AND lease_expires_at > clock_timestamp()
                """,
                (job_id, str(lease_token)),
            )
            return cursor.rowcount == 1


def fail_job(
    connection: Connection,
    *,
    job_id: int,
    lease_token: uuid.UUID,
    error: str,
    base_backoff_seconds: int = 30,
    max_backoff_seconds: int = 3600,
) -> str:
    """Retry or dead-letter a failed leased job, returning its new state."""

    if base_backoff_seconds < 1 or max_backoff_seconds < base_backoff_seconds:
        raise ValueError("invalid backoff bounds")
    safe_error = " ".join(str(error).split())[:1000] or "relay dispatch failed"
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT attempts, max_attempts
                FROM {SCHEMA}.work_queue
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                FOR UPDATE
                """,
                (job_id, str(lease_token)),
            )
            row = cursor.fetchone()
            if row is None:
                raise LookupError("job lease is missing, expired, or no longer owned")
            item = _as_mapping(row, ("attempts", "max_attempts"))
            attempts = int(item["attempts"])
            max_attempts = int(item["max_attempts"])
            if attempts >= max_attempts:
                cursor.execute(
                    f"""
                    INSERT INTO {SCHEMA}.work_queue_dead_letter
                        (queue_id, job_kind, payload, payload_version, idempotency_key,
                         attempts, max_attempts, last_error)
                    SELECT id, job_kind, payload, payload_version, idempotency_key,
                           attempts, max_attempts, %s
                    FROM {SCHEMA}.work_queue
                    WHERE id = %s AND lease_token = %s
                    ON CONFLICT (queue_id) DO NOTHING
                    """,
                    (safe_error, job_id, str(lease_token)),
                )
                cursor.execute(
                    f"""
                    UPDATE {SCHEMA}.work_queue
                    SET state = 'dead', leased_by = NULL, lease_token = NULL,
                        lease_expires_at = NULL, last_error = %s,
                        updated_at = clock_timestamp()
                    WHERE id = %s AND state = 'processing' AND lease_token = %s
                    """,
                    (safe_error, job_id, str(lease_token)),
                )
                if cursor.rowcount != 1:
                    raise LookupError("job lease changed during dead-letter transition")
                return "dead"

            backoff = min(max_backoff_seconds, base_backoff_seconds * (2 ** (attempts - 1)))
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'pending', leased_by = NULL, lease_token = NULL,
                    lease_expires_at = NULL,
                    available_at = clock_timestamp() + make_interval(secs => %s),
                    last_error = %s, updated_at = clock_timestamp()
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                """,
                (backoff, safe_error, job_id, str(lease_token)),
            )
            if cursor.rowcount != 1:
                raise LookupError("job lease changed during retry transition")
            return "pending"


def dead_letter_job(
    connection: Connection,
    *,
    job_id: int,
    lease_token: uuid.UUID,
    error: str,
) -> bool:
    """Immediately dead-letter non-retryable work owned by the caller."""

    safe_error = " ".join(str(error).split())[:1000] or "invalid job"
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO {SCHEMA}.work_queue_dead_letter
                    (queue_id, job_kind, payload, payload_version, idempotency_key,
                     attempts, max_attempts, last_error)
                SELECT id, job_kind, payload, payload_version, idempotency_key,
                       attempts, max_attempts, %s
                FROM {SCHEMA}.work_queue
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                ON CONFLICT (queue_id) DO NOTHING
                """,
                (safe_error, job_id, str(lease_token)),
            )
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'dead', leased_by = NULL, lease_token = NULL,
                    lease_expires_at = NULL, last_error = %s,
                    updated_at = clock_timestamp()
                WHERE id = %s AND state = 'processing' AND lease_token = %s
                """,
                (safe_error, job_id, str(lease_token)),
            )
            return cursor.rowcount == 1


def cancel_acceptance_canary(
    connection: Connection, *, job_id: int, canary_id: str
) -> bool:
    """Make one exact release canary terminal after a failed acceptance wait."""

    idempotency_key = f"acceptance-canary:{canary_id}"
    with _transaction(connection):
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                SET state = 'dead', leased_by = NULL, lease_token = NULL,
                    lease_expires_at = NULL, available_at = clock_timestamp(),
                    last_error = 'acceptance canary cancelled',
                    updated_at = clock_timestamp()
                WHERE id = %s AND job_kind = 'acceptance_canary'
                  AND idempotency_key = %s
                  AND state IN ('pending', 'paused', 'processing')
                """,
                (job_id, idempotency_key),
            )
            return cursor.rowcount == 1
