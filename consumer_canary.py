#!/usr/bin/env python3
"""Enqueue and verify a real consumer release canary without provider traffic."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Callable

import storage
from object_store import PageObjectStore
from service import credential_text


class CanaryError(RuntimeError):
    """The candidate consumer failed its state or object acceptance contract."""


@dataclass(frozen=True, slots=True)
class CanaryResult:
    job_id: int
    canary_id: str
    attempts: int
    object_sha256: str
    cleaned_up: bool


def run_acceptance_canary(
    connection: storage.Connection,
    object_store: PageObjectStore,
    *,
    target_worker_id: str,
    canary_id: str | None = None,
    timeout_seconds: float = 90.0,
    poll_seconds: float = 0.25,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> CanaryResult:
    """Enqueue, wait, verify one-attempt completion, and remove the object."""

    identity = canary_id or uuid.uuid4().hex
    if not target_worker_id.strip() or len(target_worker_id) > 128:
        raise ValueError("target_worker_id must be a non-empty bounded identifier")
    if not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout_seconds must be between 1 and 600")
    if not 0.01 <= poll_seconds <= 5:
        raise ValueError("poll_seconds must be between 0.01 and 5")
    # PageObjectStore performs the canonical identity validation without writing.
    object_store.canary_key(identity)
    job_id, _ = storage.enqueue_job(
        connection,
        job_kind="acceptance_canary",
        payload={"canaryId": identity, "targetWorkerId": target_worker_id.strip()},
        idempotency_key=f"acceptance-canary:{identity}",
        priority=-1000,
        max_attempts=1,
    )
    deadline = monotonic() + timeout_seconds
    terminal: storage.QueueJobState | None = None
    should_cleanup = False
    try:
        while monotonic() < deadline:
            state = storage.get_queue_job_state(connection, job_id=job_id)
            if state.state in {"completed", "dead"}:
                terminal = state
                break
            if state.state not in {"pending", "processing"}:
                raise CanaryError("canary entered an unexpected queue state")
            sleep(poll_seconds)
        if terminal is None:
            raise CanaryError(
                "candidate consumer did not complete the canary before timeout"
            )
        should_cleanup = terminal.state == "completed"
        if terminal.state != "completed" or terminal.dead_lettered:
            raise CanaryError("candidate consumer dead-lettered the acceptance canary")
        if terminal.attempts != 1 or terminal.max_attempts != 1:
            raise CanaryError("acceptance canary retried or was not single-attempt")
        stored = object_store.verify_canary(identity)
        return CanaryResult(job_id, identity, terminal.attempts, stored.sha256, True)
    finally:
        if not should_cleanup:
            storage.cancel_acceptance_canary(
                connection, job_id=job_id, canary_id=identity
            )
        try:
            object_store.remove_canary(identity)
        except Exception:
            if should_cleanup:
                raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--target-worker-id", required=True)
    parser.add_argument("--require-empty-queue", action="store_true")
    args = parser.parse_args()
    dsn = credential_text("database_url")
    if not dsn:
        parser.error("database credential is unavailable")
    connection = storage.connect(dsn)
    try:
        if args.require_empty_queue:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT count(*) AS count FROM {storage.SCHEMA}.work_queue "
                    "WHERE state IN ('pending','paused','processing')"
                )
                row = cursor.fetchone()
                count = int(row["count"] if hasattr(row, "keys") else row[0])
            if count:
                raise CanaryError("production queue is not empty before acceptance canary")
        result = run_acceptance_canary(
            connection,
            PageObjectStore(),
            target_worker_id=args.target_worker_id,
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
    finally:
        connection.close()
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
