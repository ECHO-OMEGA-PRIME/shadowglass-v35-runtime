"""Durable consumer: scrape, persist object+rows, then atomically ACK."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import time
import re
from typing import Any, Callable, Mapping, Protocol

import storage
from object_store import PageObjectStore
from scraper import Discovery, ScrapedPage, Scraper, page_document


LOGGER = logging.getLogger(__name__)
ALLOWED_JOB_KINDS = frozenset({"scrape", "discover", "acceptance_canary"})
ALLOWED_PAYLOAD_FIELDS = frozenset(
    {
        "type",
        "county",
        "countyId",
        "instrumentType",
        "instrumentTypeId",
        "startPage",
        "endPage",
        "platform",
        "retry",
    }
)


class PermanentJobError(ValueError):
    """The job is malformed and retrying cannot repair it."""


class ScraperLike(Protocol):
    def discover(
        self,
        context: storage.JobContext,
        heartbeat: Callable[[], None] | None = None,
    ) -> Discovery: ...

    def scrape(
        self,
        context: storage.JobContext,
        start_page: int,
        end_page: int,
        heartbeat: Callable[[], None] | None = None,
    ) -> list[ScrapedPage]: ...


class StoreLike(Protocol):
    def page_key(
        self, *, county: str, instrument_type: str, page: int, platform: str
    ) -> str: ...

    def put_page(
        self,
        *,
        county: str,
        instrument_type: str,
        instrument_type_id: int,
        page: int,
        platform: str,
        document: Mapping[str, Any],
        fence: storage.LeaseWriteFence,
    ) -> Any: ...

    def canary_key(self, canary_id: str) -> str: ...

    def put_canary(
        self, *, canary_id: str, fence: storage.LeaseWriteFence
    ) -> Any: ...


def validate_payload(
    job_kind: str, version: int, payload: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the instrument-specific, zero-based recovered queue contract."""

    if job_kind not in ALLOWED_JOB_KINDS:
        raise PermanentJobError("unsupported job kind")
    if version != storage.SUPPORTED_PAYLOAD_VERSION:
        raise PermanentJobError("unsupported payload version")
    if not isinstance(payload, Mapping):
        raise PermanentJobError("payload must be an object")
    if job_kind == "acceptance_canary":
        if set(payload) != {"canaryId", "targetWorkerId"}:
            raise PermanentJobError("canary payload shape is invalid")
        canary_id = payload["canaryId"]
        target_worker = payload["targetWorkerId"]
        if not isinstance(canary_id, str) or not re.fullmatch(r"[a-f0-9]{32}", canary_id):
            raise PermanentJobError("canary identity is invalid")
        if (
            not isinstance(target_worker, str)
            or not target_worker.strip()
            or len(target_worker) > 128
        ):
            raise PermanentJobError("canary target worker is invalid")
        return {"canaryId": canary_id, "targetWorkerId": target_worker.strip()}
    unknown = set(payload) - ALLOWED_PAYLOAD_FIELDS
    if unknown:
        raise PermanentJobError("payload contains unsupported fields")
    required = ("county", "countyId", "instrumentType", "instrumentTypeId")
    if any(field not in payload for field in required):
        raise PermanentJobError("payload is missing required fields")
    county = payload["county"]
    county_id = payload["countyId"]
    instrument = payload["instrumentType"]
    instrument_id = payload["instrumentTypeId"]
    if not isinstance(county, str) or not county.strip() or len(county) > 200:
        raise PermanentJobError("county must be a non-empty bounded string")
    if isinstance(county_id, bool) or not isinstance(county_id, int) or county_id < 1:
        raise PermanentJobError("countyId must be a positive integer")
    if not isinstance(instrument, str) or not instrument.strip() or len(instrument) > 200:
        raise PermanentJobError("instrumentType must be a non-empty bounded string")
    if (
        isinstance(instrument_id, bool)
        or not isinstance(instrument_id, int)
        or instrument_id < 1
    ):
        raise PermanentJobError("instrumentTypeId must be a positive integer")
    platform = payload.get("platform", "")
    if not isinstance(platform, str) or len(platform) > 64:
        raise PermanentJobError("platform must be a bounded string")
    start_page = payload.get("startPage", 0)
    end_page = payload.get("endPage", start_page)
    if (
        isinstance(start_page, bool)
        or not isinstance(start_page, int)
        or isinstance(end_page, bool)
        or not isinstance(end_page, int)
        or start_page < 0
        or end_page < start_page
        or end_page - start_page > 999
    ):
        raise PermanentJobError("page range must be zero-based, ordered, and bounded")
    retry = payload.get("retry", 0)
    if isinstance(retry, bool) or not isinstance(retry, int) or not 0 <= retry <= 100:
        raise PermanentJobError("retry must be an integer from 0 through 100")
    return {
        "type": job_kind,
        "county": county.strip(),
        "countyId": county_id,
        "instrumentType": instrument.strip(),
        "instrumentTypeId": instrument_id,
        "startPage": start_page,
        "endPage": end_page,
        "platform": platform.strip(),
        "retry": retry,
    }


def process_once(
    connection: storage.Connection,
    scraper: ScraperLike,
    object_store: StoreLike,
    *,
    worker_id: str,
    lease_seconds: int = 180,
    claim_kind: str | None = None,
) -> str:
    """Claim and fully persist at most one queue item."""

    job = storage.claim_job(
        connection,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        claim_kind=claim_kind,
    )
    if job is None:
        return "idle"
    try:
        payload = validate_payload(job.job_kind, job.payload_version, job.payload)
        context = (
            None
            if job.job_kind == "acceptance_canary"
            else storage.load_job_context(connection, payload)
        )
    except (PermanentJobError, ValueError, LookupError) as exc:
        storage.dead_letter_job(
            connection, job_id=job.id, lease_token=job.lease_token, error=str(exc)
        )
        LOGGER.warning("dead-lettered invalid queue job id=%s", job.id)
        return "dead"

    def heartbeat() -> None:
        if not storage.extend_lease(
            connection,
            job_id=job.id,
            lease_token=job.lease_token,
            lease_seconds=lease_seconds,
        ):
            raise RuntimeError("queue lease expired during remote work")

    try:
        if job.job_kind == "acceptance_canary":
            canary_id = str(payload["canaryId"])
            if payload["targetWorkerId"] != worker_id:
                raise storage.LeaseFenceRejected("canary was claimed by a non-target worker")
            key = object_store.canary_key(canary_id)
            with storage.lease_write_fence(
                connection,
                job_id=job.id,
                lease_token=job.lease_token,
                object_key=key,
            ) as fence:
                object_store.put_canary(canary_id=canary_id, fence=fence)
            if not storage.complete_job(
                connection, job_id=job.id, lease_token=job.lease_token
            ):
                raise storage.LeaseFenceRejected(
                    "canary lease expired before completion"
                )
            LOGGER.info("completed acceptance canary job id=%s", job.id)
            return "completed"

        assert context is not None
        if job.job_kind == "discover":
            result = scraper.discover(context, heartbeat)
            storage.complete_discovery(
                connection,
                job=job,
                context=context,
                total_records=result.total_records,
                page_count=result.page_count,
            )
            LOGGER.info(
                "completed discovery job id=%s queued_pages=%s",
                job.id,
                result.page_count,
            )
            return "completed"

        scraped = scraper.scrape(
            context,
            int(payload["startPage"]),
            int(payload["endPage"]),
            heartbeat,
        )
        persisted: list[dict[str, Any]] = []
        for page in scraped:
            heartbeat()
            document = page_document(context, page)
            key = object_store.page_key(
                county=context.county,
                instrument_type=context.instrument_type,
                page=page.page,
                platform=context.platform,
            )
            with storage.lease_write_fence(
                connection,
                job_id=job.id,
                lease_token=job.lease_token,
                object_key=key,
            ) as fence:
                stored = object_store.put_page(
                    county=context.county,
                    instrument_type=context.instrument_type,
                    instrument_type_id=context.instrument_type_id,
                    page=page.page,
                    platform=context.platform,
                    document=document,
                    fence=fence,
                )
            persisted.append(
                {
                    "page": page.page,
                    "records": page.records,
                    "object_key": stored.key,
                    "sha256": stored.sha256,
                    "etag": stored.etag,
                }
            )
        storage.complete_scrape(
            connection,
            job=job,
            context=context,
            pages=persisted,
        )
        LOGGER.info("completed scrape job id=%s pages=%s", job.id, len(persisted))
        return "completed"
    except storage.LeaseFenceRejected:
        LOGGER.warning("queue job id=%s lost its lease fence", job.id)
        return "stale"
    except Exception as exc:
        safe_error = f"work failed ({type(exc).__name__})"
        state = storage.fail_job(
            connection,
            job_id=job.id,
            lease_token=job.lease_token,
            error=safe_error,
        )
        LOGGER.warning("queue job id=%s failed; state=%s", job.id, state)
        return state


def _credential(name: str) -> str:
    from service import credential_text

    value = credential_text(name)
    if not value:
        raise RuntimeError(f"required {name} credential is unavailable")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--worker-id", default="forge-shadowglass-v35")
    parser.add_argument("--idle-seconds", type=float, default=2.0)
    parser.add_argument("--lease-seconds", type=int, default=180)
    parser.add_argument("--claim-kind", choices=("acceptance_canary",))
    args = parser.parse_args()
    if not 0.2 <= args.idle_seconds <= 30:
        parser.error("--idle-seconds must be between 0.2 and 30")
    if not 30 <= args.lease_seconds <= 3600:
        parser.error("--lease-seconds must be between 30 and 3600")
    stopping = False

    def stop(_: int, __: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    connection = storage.connect(_credential("database_url"))
    object_store = PageObjectStore()
    object_store.probe()
    scraper = Scraper()
    try:
        while not stopping:
            status = process_once(
                connection,
                scraper,
                object_store,
                worker_id=args.worker_id,
                lease_seconds=args.lease_seconds,
                claim_kind=args.claim_kind,
            )
            if not args.loop:
                print(json.dumps({"status": status}, sort_keys=True))
                return 0
            if status == "idle":
                time.sleep(args.idle_seconds)
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
