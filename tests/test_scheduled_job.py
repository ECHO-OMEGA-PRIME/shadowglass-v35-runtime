from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import scheduled_job


PAIR = {
    "county_id": 1,
    "county_name": "Midland",
    "platform": "tyler",
    "instrument_id": 2,
    "instrument_name": "Deed",
}


class SchedulerCursor(AbstractContextManager["SchedulerCursor"]):
    def __init__(
        self,
        *,
        acquired: bool,
        candidate: dict[str, Any] | None = None,
        busy: bool = False,
        inserted: bool = True,
    ) -> None:
        self.acquired = acquired
        self.candidate = candidate
        self.busy = busy
        self.inserted = inserted
        self.kind = ""
        self.executions: list[tuple[str, tuple[Any, ...]]] = []

    def __enter__(self) -> "SchedulerCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        self.executions.append((query, params))
        if "pg_try_advisory_xact_lock" in query:
            self.kind = "lock"
        elif "SELECT EXISTS" in query:
            self.kind = "busy"
        elif "CROSS JOIN" in query:
            self.kind = "candidate"
        elif "INSERT INTO" in query:
            self.kind = "insert"
        else:
            raise AssertionError("unexpected SQL")

    def fetchone(self) -> Any:
        if self.kind == "lock":
            return {"acquired": self.acquired}
        if self.kind == "busy":
            return {"busy": self.busy}
        if self.kind == "candidate":
            return self.candidate
        if self.kind == "insert":
            return {"id": 1} if self.inserted else None
        raise AssertionError("fetchone in wrong cursor state")


class Connection:
    def __init__(self, cursor: SchedulerCursor) -> None:
        self.value = cursor

    def cursor(self) -> SchedulerCursor:
        return self.value


def test_overlapping_timer_exits_without_enqueuing() -> None:
    cursor = SchedulerCursor(acquired=False)
    result = scheduled_job.run_hourly(Connection(cursor))
    assert result == scheduled_job.ScheduleResult(False, 0, 0, 0)
    assert len(cursor.executions) == 1


def test_hourly_jobs_have_deterministic_idempotency_keys() -> None:
    instant = datetime(2026, 8, 3, 10, 37, tzinfo=timezone.utc)
    first = SchedulerCursor(acquired=True, candidate=PAIR, inserted=True)
    second = SchedulerCursor(acquired=True, candidate=PAIR, inserted=False)
    first_result = scheduled_job.run_hourly(Connection(first), now=instant)
    second_result = scheduled_job.run_hourly(Connection(second), now=instant)
    assert first_result == scheduled_job.ScheduleResult(True, 1, 1, 0)
    assert second_result == scheduled_job.ScheduleResult(True, 1, 0, 1)
    first_key = [params[3] for sql, params in first.executions if "INSERT INTO" in sql][0]
    second_key = [params[3] for sql, params in second.executions if "INSERT INTO" in sql][0]
    assert first_key == second_key == "hourly:2026080310:county:1:instrument:2"


def test_scheduler_preserves_backlog_and_operator_pauses() -> None:
    cursor = SchedulerCursor(acquired=True, candidate=PAIR, busy=True)
    result = scheduled_job.run_hourly(Connection(cursor))
    assert result == scheduled_job.ScheduleResult(True, 0, 0, 0)
    assert not any("INSERT INTO" in query for query, _ in cursor.executions)


def test_scheduler_enqueues_only_one_candidate() -> None:
    cursor = SchedulerCursor(acquired=True, candidate=PAIR, inserted=True)
    result = scheduled_job.run_hourly(Connection(cursor))
    assert result == scheduled_job.ScheduleResult(True, 1, 1, 0)
    assert sum("INSERT INTO" in query for query, _ in cursor.executions) == 1


def test_scheduler_probe_proves_candidate_without_enqueuing() -> None:
    cursor = SchedulerCursor(acquired=True, candidate=PAIR, inserted=True)
    result = scheduled_job.run_hourly(Connection(cursor), probe=True)
    assert result == scheduled_job.ScheduleResult(True, 1, 0, 0)
    assert not any("INSERT INTO" in query for query, _ in cursor.executions)


def test_scheduler_role_can_read_every_table_used_by_candidate_query() -> None:
    schema = (Path(__file__).resolve().parents[1] / "schema.sql").read_text(
        encoding="utf-8"
    )
    scheduler_grants = schema[
        schema.index("rolname = 'cf_shadowglass_v35_scheduler'") :
    ]
    grant_start = scheduler_grants.index("GRANT SELECT ON")
    grant_select = scheduler_grants[
        grant_start : scheduler_grants.index("TO cf_shadowglass", grant_start)
    ]
    for table in ("counties", "instrument_types", "scrape_jobs", "work_queue"):
        assert f"cf_shadowglass_v35.{table}" in grant_select
    revoke = scheduler_grants[scheduler_grants.index("REVOKE ALL ON") :]
    assert "cf_shadowglass_v35.scrape_jobs" not in revoke
