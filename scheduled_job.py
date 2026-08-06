"""Hourly database-driven scheduler for ShadowGlass scrape work."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

import storage

# A service-specific, stable signed bigint; never derived from Python's randomized hash().
SCHEDULER_ADVISORY_LOCK = 0x5347563853434845


@dataclass(frozen=True, slots=True)
class ScheduleResult:
    lock_acquired: bool
    candidates: int
    enqueued: int
    existing: int


def _row(row: Any) -> Mapping[str, Any]:
    if isinstance(row, Mapping):
        return row
    names = ("county_id", "county_name", "platform", "instrument_id", "instrument_name")
    return dict(zip(names, row, strict=True))


def run_hourly(
    connection: storage.Connection,
    *,
    now: datetime | None = None,
    max_attempts: int = 5,
    probe: bool = False,
) -> ScheduleResult:
    """Enqueue at most one eligible county/instrument discovery per UTC hour.

    A transaction-scoped advisory lock prevents overlapping timer processes.  The
    scheduler also refuses to add work while any queue item is runnable or paused.
    This preserves the recovered one-at-a-time progression and avoids flooding a
    direct county endpoint after an operator pause.  Queue uniqueness provides the
    second idempotency layer across retries and process restarts.
    """

    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("scheduler time must be timezone-aware")
    if not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")
    bucket = instant.astimezone(timezone.utc).strftime("%Y%m%d%H")

    transaction = storage._transaction(connection)
    with transaction:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_xact_lock(%s) AS acquired", (SCHEDULER_ADVISORY_LOCK,))
            lock_row = cursor.fetchone()
            acquired = bool(lock_row["acquired"] if isinstance(lock_row, Mapping) else lock_row[0])
            if not acquired:
                return ScheduleResult(False, 0, 0, 0)

            cursor.execute(
                f"""
                SELECT EXISTS (
                    SELECT 1 FROM {storage.SCHEMA}.work_queue
                    WHERE state IN ('pending', 'paused', 'processing')
                ) AS busy
                """
            )
            busy_row = cursor.fetchone()
            busy = bool(busy_row["busy"] if isinstance(busy_row, Mapping) else busy_row[0])
            if busy:
                return ScheduleResult(True, 0, 0, 0)

            cursor.execute(
                f"""
                SELECT counties.id AS county_id, counties.name AS county_name,
                       COALESCE(counties.platform, '') AS platform,
                       instruments.id AS instrument_id,
                       instruments.name AS instrument_name
                FROM {storage.SCHEMA}.counties AS counties
                CROSS JOIN {storage.SCHEMA}.instrument_types AS instruments
                LEFT JOIN {storage.SCHEMA}.scrape_jobs AS jobs
                  ON jobs.county_id = counties.id
                 AND jobs.instrument_type_id = instruments.id
                WHERE COALESCE(counties.is_active, 1) = 1
                  AND COALESCE(jobs.status, '') NOT IN ('running', 'pending', 'paused')
                  AND (
                    jobs.completed_at IS NULL
                    OR jobs.completed_at::timestamptz <= %s - interval '24 hours'
                  )
                ORDER BY jobs.completed_at::timestamptz NULLS FIRST,
                         counties.id, instruments.id
                LIMIT 1
                """,
                (instant,),
            )
            candidate_row = cursor.fetchone()
            if candidate_row is None:
                return ScheduleResult(True, 0, 0, 0)
            pair = _row(candidate_row)
            payload = {
                "type": "discover",
                "county": str(pair["county_name"]),
                "countyId": int(pair["county_id"]),
                "instrumentType": str(pair["instrument_name"]),
                "instrumentTypeId": int(pair["instrument_id"]),
                "startPage": 0,
                "endPage": 0,
                "platform": str(pair["platform"]),
                "retry": 0,
            }
            key = (
                f"hourly:{bucket}:county:{pair['county_id']}:"
                f"instrument:{pair['instrument_id']}"
            )
            if probe:
                return ScheduleResult(True, 1, 0, 0)
            cursor.execute(
                f"""
                INSERT INTO {storage.SCHEMA}.work_queue
                    (job_kind, payload, payload_version, idempotency_key,
                     priority, max_attempts)
                VALUES (%s, %s::jsonb, %s, %s, %s, %s)
                ON CONFLICT (idempotency_key) DO NOTHING
                RETURNING id
                """,
                (
                    "discover",
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    storage.SUPPORTED_PAYLOAD_VERSION,
                    key,
                    100,
                    max_attempts,
                ),
            )
            enqueued = 1 if cursor.fetchone() is not None else 0
    return ScheduleResult(True, 1, enqueued, 1 - enqueued)


def _database_url() -> str:
    from service import credential_text

    return credential_text("database_url") or os.getenv("DATABASE_URL", "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--require-one-candidate", action="store_true")
    args = parser.parse_args()
    if args.require_one_candidate and not args.probe:
        parser.error("--require-one-candidate requires --probe")
    dsn = _database_url()
    if not dsn:
        parser.error("database credential is required")
    connection = storage.connect(dsn)
    try:
        result = run_hourly(connection, probe=args.probe)
    finally:
        connection.close()
    print(
        json.dumps(
            {
                "lock_acquired": result.lock_acquired,
                "candidates": result.candidates,
                "enqueued": result.enqueued,
                "existing": result.existing,
                "probe": args.probe,
            },
            sort_keys=True,
        )
    )
    if args.require_one_candidate and result != ScheduleResult(True, 1, 0, 0):
        raise SystemExit("scheduler probe did not prove exactly one eligible candidate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
