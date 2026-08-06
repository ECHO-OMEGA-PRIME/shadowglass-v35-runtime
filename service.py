"""Domain service over the isolated PostgreSQL replacement schema."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import storage


SCHEMA = storage.SCHEMA


def credential_text(name: str) -> str:
    credential_dir = os.getenv("CREDENTIALS_DIRECTORY", "")
    explicit = os.getenv(f"SG_{name.upper()}_FILE", "")
    path = explicit or (str(Path(credential_dir) / name) if credential_dir else "")
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


class ServiceUnavailable(RuntimeError):
    """A required private-cluster dependency is unavailable."""


class NotFound(LookupError):
    """A requested county, instrument, record, or job does not exist."""


class JobStateConflict(RuntimeError):
    """A queue job exists but cannot make the requested state transition."""


class ShadowglassService:
    @contextmanager
    def connection(self) -> Iterator[Any]:
        dsn = credential_text("database_url")
        if not dsn:
            raise ServiceUnavailable("database credential unavailable")
        connection = storage.connect(dsn)
        try:
            yield connection
        finally:
            connection.close()

    def health(self) -> dict[str, Any]:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 AS healthy")
            row = cursor.fetchone()
        if not row:
            raise ServiceUnavailable("database health query failed")
        return {"database": "healthy"}

    def stats(self) -> dict[str, Any]:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                  (SELECT count(*) FROM {SCHEMA}.counties) AS counties,
                  (SELECT count(*) FROM {SCHEMA}.instrument_types) AS instrument_types,
                  (SELECT count(*) FROM {SCHEMA}.deed_records) AS deed_records,
                  (SELECT count(*) FROM {SCHEMA}.scrape_jobs) AS scrape_jobs,
                  (SELECT count(*) FROM {SCHEMA}.scrape_logs) AS scrape_logs,
                  (SELECT count(*) FROM {SCHEMA}.r2_uploads) AS r2_uploads,
                  (SELECT count(*) FROM {SCHEMA}.work_queue WHERE state = 'pending') AS queue_pending,
                  (SELECT count(*) FROM {SCHEMA}.work_queue WHERE state = 'processing') AS queue_processing,
                  (SELECT count(*) FROM {SCHEMA}.work_queue WHERE state = 'dead') AS queue_dead
                """
            )
            return dict(cursor.fetchone())

    def counties(self) -> list[dict[str, Any]]:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT id, name, state, platform, is_active
                FROM {SCHEMA}.counties
                ORDER BY name, id
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def search(
        self,
        *,
        query: str | None,
        county: str | None,
        instrument_type: str | None,
        grantor: str | None,
        grantee: str | None,
        from_date: str | None,
        to_date: str | None,
        section: str | None,
        block: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if query:
            clauses.append(
                "(grantor ILIKE %s OR grantee ILIKE %s OR legal_description ILIKE %s "
                "OR doc_number ILIKE %s)"
            )
            token = f"%{query}%"
            params.extend((token, token, token, token))
        for column, value in (
            ("county", county),
            ("instrument_type", instrument_type),
            ("grantor", grantor),
            ("grantee", grantee),
            ("section", section),
            ("block", block),
        ):
            if value:
                clauses.append(f"{column} ILIKE %s")
                params.append(f"%{value}%")
        if from_date:
            clauses.append("recorded_date >= %s")
            params.append(from_date)
        if to_date:
            clauses.append("recorded_date <= %s")
            params.append(to_date)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT count(*) AS count FROM {SCHEMA}.deed_records{where}",
                tuple(params),
            )
            total = int(cursor.fetchone()["count"])
            cursor.execute(
                f"""
                SELECT id, external_id, county, instrument_type, grantor, grantee,
                       recorded_date, filing_date, legal_description, section, block,
                       book, page_num, volume, doc_number, consideration, source_url,
                       created_at
                FROM {SCHEMA}.deed_records
                {where}
                ORDER BY recorded_date DESC NULLS LAST, id DESC
                LIMIT %s OFFSET %s
                """,
                (*params, limit, offset),
            )
            records = [dict(row) for row in cursor.fetchall()]
        return {"records": records, "total": total, "limit": limit, "offset": offset}

    def record(self, record_id: int) -> dict[str, Any]:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT id, external_id, county, instrument_type, instrument_type_id,
                       grantor, grantee, recorded_date, filing_date, legal_description,
                       legal_normalized, section, block, book, page_num, volume,
                       doc_number, consideration, source_url, created_at
                FROM {SCHEMA}.deed_records WHERE id = %s
                """,
                (record_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise NotFound("record not found")
        return dict(row)

    def jobs(self, county: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT id AS queue_job_id, payload->>'county' AS county,
                       payload->>'instrumentType' AS instrument_type,
                       state AS status, attempts, max_attempts, last_error,
                       created_at, completed_at, updated_at, 'queue' AS source
                FROM {SCHEMA}.work_queue
                WHERE (%s IS NULL OR payload->>'county' ILIKE %s)
                ORDER BY id DESC
                LIMIT %s
                """,
                (county, county, limit),
            )
            # Imported scrape_jobs rows are historical checkpoints, not live
            # queue controls.  Mixing their numeric IDs into this operational
            # feed made /pause/{id} ambiguous and advertised jobs that could
            # never transition.  Keep the control surface queue-only.
            return [dict(row) for row in cursor.fetchall()]

    def _resolve_county(self, cursor: Any, county: str) -> dict[str, Any]:
        cursor.execute(
            f"SELECT id, name, platform FROM {SCHEMA}.counties WHERE name ILIKE %s AND is_active <> 0 ORDER BY id LIMIT 1",
            (county,),
        )
        row = cursor.fetchone()
        if row is None:
            raise NotFound("active county not found")
        return dict(row)

    def _resolve_instrument(self, cursor: Any, instrument: str) -> dict[str, Any]:
        cursor.execute(
            f"SELECT id, name FROM {SCHEMA}.instrument_types WHERE name ILIKE %s ORDER BY id LIMIT 1",
            (instrument,),
        )
        row = cursor.fetchone()
        if row is None:
            raise NotFound("instrument type not found")
        return dict(row)

    def enqueue_scrape(
        self,
        *,
        county: str,
        instrument_type: str,
        start_page: int,
        end_page: int,
        idempotency_key: str,
        priority: int = 100,
    ) -> tuple[int, bool]:
        with self.connection() as connection, connection.cursor() as cursor:
            county_row = self._resolve_county(cursor, county)
            instrument_row = self._resolve_instrument(cursor, instrument_type)
            payload = {
                "type": "scrape",
                "county": county_row["name"],
                "countyId": county_row["id"],
                "instrumentType": instrument_row["name"],
                "instrumentTypeId": instrument_row["id"],
                "startPage": start_page,
                "endPage": end_page,
                "platform": county_row.get("platform") or "",
                "retry": 0,
            }
            return storage.enqueue_job(
                connection,
                job_kind="scrape",
                payload=payload,
                idempotency_key=idempotency_key,
                priority=priority,
            )

    def enqueue_county(
        self, *, county: str, idempotency_key: str, priority: int = 100
    ) -> list[tuple[int, bool]]:
        with self.connection() as connection, connection.cursor() as cursor:
            county_row = self._resolve_county(cursor, county)
            cursor.execute(f"SELECT id, name FROM {SCHEMA}.instrument_types ORDER BY id")
            instruments = [dict(row) for row in cursor.fetchall()]
            results: list[tuple[int, bool]] = []
            for instrument in instruments:
                payload = {
                    "type": "discover",
                    "county": county_row["name"],
                    "countyId": county_row["id"],
                    "instrumentType": instrument["name"],
                    "instrumentTypeId": instrument["id"],
                    "startPage": 0,
                    "endPage": 0,
                    "platform": county_row.get("platform") or "",
                    "retry": 0,
                }
                results.append(
                    storage.enqueue_job(
                        connection,
                        job_kind="discover",
                        payload=payload,
                        idempotency_key=f"{idempotency_key}:{instrument['id']}",
                        priority=priority,
                    )
                )
            return results

    def enqueue_discovery(
        self, *, county: str, idempotency_key: str
    ) -> list[tuple[int, bool]]:
        with self.connection() as connection, connection.cursor() as cursor:
            county_row = self._resolve_county(cursor, county)
            cursor.execute(f"SELECT id, name FROM {SCHEMA}.instrument_types ORDER BY id")
            results = []
            for instrument in cursor.fetchall():
                item = dict(instrument)
                payload = {
                    "type": "discover",
                    "county": county_row["name"],
                    "countyId": county_row["id"],
                    "instrumentType": item["name"],
                    "instrumentTypeId": item["id"],
                    "startPage": 0,
                    "endPage": 0,
                    "platform": county_row.get("platform") or "",
                    "retry": 0,
                }
                results.append(
                    storage.enqueue_job(
                        connection,
                        job_kind="discover",
                        payload=payload,
                        idempotency_key=f"{idempotency_key}:{item['id']}",
                        priority=50,
                    )
                )
            return results

    def set_paused(self, job_id: int, paused: bool) -> dict[str, Any]:
        desired = "paused" if paused else "pending"
        required = "pending" if paused else "paused"
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {SCHEMA}.work_queue
                   SET state = %s, updated_at = clock_timestamp()
                 WHERE id = %s AND state = %s
                RETURNING id AS queue_job_id, state AS status
                """,
                (desired, job_id, required),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    f"SELECT id AS queue_job_id, state AS status FROM {SCHEMA}.work_queue WHERE id = %s",
                    (job_id,),
                )
                current = cursor.fetchone()
                if current is None:
                    raise NotFound("queue job not found")
                state = dict(current)
                if state["status"] != desired:
                    raise JobStateConflict("queue job cannot transition from its current state")
                row = current
            connection.commit()
        return dict(row)
