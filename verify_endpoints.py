#!/usr/bin/env python3
"""Verify every activated county endpoint without emitting public-record rows."""

from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any, Mapping

import storage
from apply_endpoint_overrides import DEFAULT_MANIFEST, load_manifest
from relay import RelayClient
from scraper import TylerAdapter, parse_public_search, public_search_url


PUBLICSEARCH_MARKERS = (
    "publicsearch",
    "department",
    "recordeddaterange",
    "searchtype",
    "results",
    "table",
)


def _verify_publicsearch(payload: Mapping[str, Any]) -> str:
    html = payload.get("html") or payload.get("content")
    if not isinstance(html, str) or len(html) < 1_000:
        raise RuntimeError("PublicSearch response is not a full provider document")
    lowered = html.casefold()
    if any(marker not in lowered for marker in PUBLICSEARCH_MARKERS):
        raise RuntimeError("PublicSearch response lacks provider semantics")
    interstitial_markers = (
        "<title>access denied",
        "error 1020",
        "attention required! | cloudflare",
        "cf-chl-captcha",
        "cf-chl-widget",
        "g-recaptcha",
        "hcaptcha",
        "captcha-container",
        "challenge-platform",
        "verify you are human",
    )
    if any(marker in lowered for marker in interstitial_markers):
        raise RuntimeError("PublicSearch response is an interstitial")
    # Parsing is still required even when the deliberately broad DEED query
    # returns no rows; provider-shell markers alone are not sufficient.
    parse_public_search(payload)
    return hashlib.sha256(html.encode("utf-8")).hexdigest()


def verify(*, relay: RelayClient | None = None) -> dict[str, Any]:
    manifest = load_manifest(DEFAULT_MANIFEST)
    browser = relay or RelayClient(timeout_seconds=60)
    publicsearch_count = 0
    tyler_count = 0
    evidence: list[dict[str, str]] = []
    for index, entry in enumerate(manifest.entries, start=1):
        if not entry.active:
            continue
        context = storage.JobContext(
            county_id=index,
            county=entry.name,
            base_url=entry.base_url or "",
            platform=entry.platform or "",
            instrument_type_id=1,
            instrument_type="DEED",
        )
        if entry.platform == "TYLER_TECH":
            raw = TylerAdapter(context).verify_live()
            evidence.append(
                {
                    "county": entry.name,
                    "platform": entry.platform,
                    "evidence_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
            tyler_count += 1
        else:
            payload = browser.browse(
                public_search_url(context, 0), "table tbody tr"
            )
            evidence.append(
                {
                    "county": entry.name,
                    "platform": entry.platform,
                    "evidence_sha256": _verify_publicsearch(payload),
                }
            )
            publicsearch_count += 1
    active_count = publicsearch_count + tyler_count
    expected = sum(1 for entry in manifest.entries if entry.active)
    if active_count != expected:
        raise RuntimeError("active county endpoint coverage is incomplete")
    return {
        "active_count": active_count,
        "counties": evidence,
        "ok": True,
        "publicsearch_count": publicsearch_count,
        "tyler_count": tyler_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(verify(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
