"""PostgreSQL state and shared migrated-data queries for the command plane."""

from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable, Mapping


DATA_SCHEMA = "cf_shadowglass_v7_tyler"
COMMAND_SCHEMA = "cf_shadowglass_v7_command"


class IdempotencyConflict(RuntimeError):
    """An idempotency key was reused for different immutable work."""


class DispatchInDoubt(RuntimeError):
    """A prior dispatch may have reached the provider and cannot be replayed safely."""


def connect(dsn: str) -> Any:
    if not dsn.strip():
        raise ValueError("database DSN is required")
    import psycopg2
    from psycopg2.extras import RealDictCursor

    return psycopg2.connect(dsn, cursor_factory=RealDictCursor)


def _transaction(connection: Any) -> Any:
    return connection if hasattr(connection, "__enter__") else nullcontext(connection)


def _mapping(row: Any, columns: tuple[str, ...]) -> dict[str, Any]:
    if isinstance(row, Mapping):
        return dict(row)
    if row is None:
        raise LookupError("expected a database row")
    return dict(zip(columns, row, strict=True))


@dataclass(frozen=True, slots=True)
class DispatchReservation:
    receipt_id: int
    created: bool
    state: str


class CommandStore:
    """Fixed-query store; callers never select identifiers or SQL."""

    def __init__(self, dsn: str, connector: Callable[[str], Any] = connect) -> None:
        self.dsn = dsn
        self.connector = connector

    def _open(self) -> Any:
        return self.connector(self.dsn)

    def rate_limit(self, subject_sha256: str, action: str, limit: int) -> bool:
        if not 1 <= limit <= 10_000:
            raise ValueError("rate limit is outside safe bounds")
        connection = self._open()
        try:
            with _transaction(connection):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        INSERT INTO {COMMAND_SCHEMA}.rate_windows
                          (subject_sha256, action, window_started_at, request_count)
                        VALUES (%s, %s, date_trunc('minute', clock_timestamp()), 1)
                        ON CONFLICT (subject_sha256, action, window_started_at)
                        DO UPDATE SET request_count =
                          {COMMAND_SCHEMA}.rate_windows.request_count + 1
                        RETURNING request_count
                        """,
                        (subject_sha256, action),
                    )
                    row = _mapping(cursor.fetchone(), ("request_count",))
            return int(row["request_count"]) <= limit
        finally:
            connection.close()

    def reserve_dispatch(
        self, *, idempotency_key: str, target: str, action: str, payload: Mapping[str, Any]
    ) -> DispatchReservation:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
        connection = self._open()
        try:
            with _transaction(connection):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        INSERT INTO {COMMAND_SCHEMA}.dispatch_receipts
                          (idempotency_key, target_queue, action, payload_sha256, state)
                        VALUES (%s, %s, %s, %s, 'dispatching')
                        ON CONFLICT (idempotency_key) DO NOTHING
                        RETURNING id
                        """,
                        (idempotency_key, target, action, payload_sha256),
                    )
                    created = cursor.fetchone()
                    if created is not None:
                        return DispatchReservation(
                            int(_mapping(created, ("id",))["id"]), True, "dispatching"
                        )
                    cursor.execute(
                        f"""
                        SELECT id, target_queue, action, payload_sha256, state
                        FROM {COMMAND_SCHEMA}.dispatch_receipts
                        WHERE idempotency_key = %s
                        FOR UPDATE
                        """,
                        (idempotency_key,),
                    )
                    row = _mapping(
                        cursor.fetchone(),
                        ("id", "target_queue", "action", "payload_sha256", "state"),
                    )
                    if (
                        row["target_queue"] != target
                        or row["action"] != action
                        or row["payload_sha256"] != payload_sha256
                    ):
                        raise IdempotencyConflict("idempotency key is bound to different work")
                    state = str(row["state"])
                    if state == "dispatching":
                        raise DispatchInDoubt("prior provider dispatch is unresolved")
                    return DispatchReservation(int(row["id"]), False, state)
        finally:
            connection.close()

    def mark_dispatched(self, receipt_id: int) -> None:
        connection = self._open()
        try:
            with _transaction(connection):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        UPDATE {COMMAND_SCHEMA}.dispatch_receipts
                        SET state = 'dispatched', dispatched_at = clock_timestamp(),
                            updated_at = clock_timestamp()
                        WHERE id = %s AND state = 'dispatching'
                        """,
                        (receipt_id,),
                    )
                    if cursor.rowcount != 1:
                        raise LookupError("dispatch receipt no longer owns its transition")
        finally:
            connection.close()

    def mark_failed(self, receipt_id: int, error_class: str) -> None:
        connection = self._open()
        try:
            with _transaction(connection):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        UPDATE {COMMAND_SCHEMA}.dispatch_receipts
                        SET state = 'failed', error_class = %s,
                            updated_at = clock_timestamp()
                        WHERE id = %s AND state = 'dispatching'
                        """,
                        (error_class[:80], receipt_id),
                    )
        finally:
            connection.close()

    def query(self, statement: str, params: tuple[Any, ...], *, limit: int = 500) -> list[dict[str, Any]]:
        approved = {
            "ping": "SELECT 1 AS ok",
            "counties": f"SELECT id, name, platform, is_active FROM {DATA_SCHEMA}.counties ORDER BY name LIMIT %s",
            "stats": f"SELECT (SELECT count(*) FROM {DATA_SCHEMA}.counties) AS counties, (SELECT count(*) FROM {DATA_SCHEMA}.instrument_types) AS instrument_types, (SELECT greatest(reltuples, 0)::bigint FROM pg_class WHERE oid='{DATA_SCHEMA}.deed_records'::regclass) AS records, (SELECT count(*) FROM {DATA_SCHEMA}.scrape_jobs) AS jobs",
            "status_all": f"SELECT j.id, c.name AS county, i.name AS instrument_type, j.status, j.total_records, j.scraped_records, j.last_page, j.updated_at FROM {DATA_SCHEMA}.scrape_jobs j JOIN {DATA_SCHEMA}.counties c ON c.id=j.county_id JOIN {DATA_SCHEMA}.instrument_types i ON i.id=j.instrument_type_id ORDER BY j.updated_at DESC NULLS LAST LIMIT %s",
            "status_county": f"SELECT j.id, c.name AS county, i.name AS instrument_type, j.status, j.total_records, j.scraped_records, j.last_page, j.updated_at FROM {DATA_SCHEMA}.scrape_jobs j JOIN {DATA_SCHEMA}.counties c ON c.id=j.county_id JOIN {DATA_SCHEMA}.instrument_types i ON i.id=j.instrument_type_id WHERE lower(c.name)=lower(%s) ORDER BY i.name LIMIT %s",
            "record": f"SELECT id, external_id, county, instrument_type, grantor, grantee, recorded_date, filing_date, legal_description, book, page_num, doc_number, consideration, source_url, r2_key FROM {DATA_SCHEMA}.deed_records WHERE id=%s OR external_id=%s LIMIT 1",
            "search": f"SELECT id, external_id, county, instrument_type, grantor, grantee, recorded_date, legal_description, doc_number FROM {DATA_SCHEMA}.deed_records WHERE grantor ILIKE %s OR grantee ILIKE %s OR doc_number ILIKE %s OR legal_description ILIKE %s ORDER BY id DESC LIMIT %s",
            "schedules": f"SELECT id, action, target_queue, payload, idempotency_prefix FROM {COMMAND_SCHEMA}.schedules WHERE enabled IS TRUE AND next_run_at <= clock_timestamp() ORDER BY priority, id FOR UPDATE SKIP LOCKED LIMIT %s",
        }
        sql = approved.get(statement)
        if sql is None:
            raise ValueError("query is not allowlisted")
        connection = self._open()
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql, params)
                columns = tuple(item[0] for item in cursor.description or ())
                return [_mapping(row, columns) for row in cursor.fetchall()[:limit]]
        finally:
            connection.close()

    def set_job_state(self, county: str, state: str) -> int:
        if state not in {"paused", "pending"}:
            raise ValueError("unsupported job state")
        connection = self._open()
        try:
            with _transaction(connection):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        UPDATE {DATA_SCHEMA}.scrape_jobs AS jobs
                        SET status=%s, updated_at=clock_timestamp()::text
                        FROM {DATA_SCHEMA}.counties AS counties
                        WHERE jobs.county_id=counties.id AND lower(counties.name)=lower(%s)
                          AND jobs.status NOT IN ('completed','failed')
                        """,
                        (state, county),
                    )
                    changed = max(cursor.rowcount, 0)
            return changed
        finally:
            connection.close()

    def resolve_context(
        self, county: str, instrument_type: str, platform: str
    ) -> dict[str, Any]:
        """Resolve queue identities from imported state, never from caller IDs."""

        connection = self._open()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT counties.id AS county_id, counties.name AS county,
                           instruments.id AS instrument_type_id,
                           instruments.name AS instrument_type,
                           lower(counties.platform) AS platform
                    FROM {DATA_SCHEMA}.counties AS counties
                    CROSS JOIN {DATA_SCHEMA}.instrument_types AS instruments
                    WHERE lower(counties.name)=lower(%s)
                      AND lower(instruments.name)=lower(%s)
                      AND lower(counties.platform)=lower(%s)
                      AND counties.is_active <> 0
                    LIMIT 1
                    """,
                    (county, instrument_type, platform),
                )
                row = cursor.fetchone()
                if row is None:
                    raise LookupError("county, instrument, and platform are not active")
                columns = tuple(item[0] for item in cursor.description or ())
                return _mapping(row, columns)
        finally:
            connection.close()

    def resolve_contexts(
        self,
        counties: list[str],
        platform: str,
        instrument_type: str | None,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Resolve a bounded all/multi request against canonical imported IDs."""

        if not counties or not 1 <= limit <= 100:
            raise ValueError("context resolution bounds are invalid")
        connection = self._open()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT counties.id AS county_id, counties.name AS county,
                           instruments.id AS instrument_type_id,
                           instruments.name AS instrument_type,
                           lower(counties.platform) AS platform
                    FROM {DATA_SCHEMA}.counties AS counties
                    CROSS JOIN {DATA_SCHEMA}.instrument_types AS instruments
                    WHERE lower(counties.name) = ANY(%s)
                      AND lower(counties.platform)=lower(%s)
                      AND counties.is_active <> 0
                      AND (%s IS NULL OR lower(instruments.name)=lower(%s))
                    ORDER BY counties.name, instruments.name
                    LIMIT %s
                    """,
                    ([item.lower() for item in counties], platform, instrument_type, instrument_type, limit),
                )
                columns = tuple(item[0] for item in cursor.description or ())
                return [_mapping(row, columns) for row in cursor.fetchall()]
        finally:
            connection.close()

    def advance_schedule(self, schedule_id: int) -> None:
        connection = self._open()
        try:
            with _transaction(connection):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        UPDATE {COMMAND_SCHEMA}.schedules
                        SET last_run_at=clock_timestamp(),
                            next_run_at=clock_timestamp()+make_interval(secs=>interval_seconds),
                            updated_at=clock_timestamp()
                        WHERE id=%s AND enabled IS TRUE
                        """,
                        (schedule_id,),
                    )
        finally:
            connection.close()
