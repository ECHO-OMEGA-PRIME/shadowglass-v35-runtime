#!/usr/bin/env python3
"""Live, value-redacted smoke suite for staging and production releases."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


REQUIRED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
}


def call(
    base: str,
    path: str,
    *,
    method: str = "GET",
    token: str = "",
    body: dict[str, Any] | None = None,
    idempotency: str = "",
    smoke_token: str = "",
) -> tuple[int, dict[str, str], Any]:
    headers = {"Accept": "application/json", "User-Agent": "shadowglass-v35-smoke/35"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if idempotency:
        headers["X-Idempotency-Key"] = idempotency
    if smoke_token:
        headers["X-Shadowglass-Smoke-Token"] = smoke_token
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(base.rstrip("/") + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(1_000_000)
            status = response.status
            response_headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read(1_000_000)
        status = exc.code
        response_headers = {key.lower(): value for key, value in exc.headers.items()}
    try:
        payload = json.loads(raw) if raw else None
    except (UnicodeDecodeError, ValueError):
        payload = raw.decode("utf-8", "replace")[:200]
    return status, response_headers, payload


def require_headers(headers: dict[str, str]) -> None:
    for name, value in REQUIRED_HEADERS.items():
        if headers.get(name) != value:
            raise AssertionError(f"missing security header: {name}")


def require(condition: bool, label: str, status: int) -> None:
    if not condition:
        raise AssertionError({"check": label, "status": status})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--read-token-file", required=True)
    parser.add_argument("--write-token-file", required=True)
    parser.add_argument("--smoke-token-file", required=True)
    parser.add_argument("--force-fail", action="store_true")
    args = parser.parse_args()
    read_token = Path(args.read_token_file).read_text(encoding="utf-8").strip()
    write_token = Path(args.write_token_file).read_text(encoding="utf-8").strip()
    smoke_token = Path(args.smoke_token_file).read_text(encoding="utf-8").strip()
    if not read_token or not write_token or not smoke_token:
        raise SystemExit("smoke credentials are unavailable")
    checks = 0

    status, headers, payload = call(args.base, "/health")
    require(status == 200 and isinstance(payload, dict) and payload.get("status") == "healthy", "health", status)
    require_headers(headers)
    checks += 1

    status, headers, _ = call(args.base, "/stats")
    require(status == 401, "anonymous read", status)
    require_headers(headers)
    checks += 1
    status, headers, _ = call(args.base, "/stats", token="definitely-invalid")
    require(status == 403, "invalid read", status)
    require_headers(headers)
    checks += 1

    reads = (
        "/",
        "/dashboard",
        "/stats",
        "/counties",
        "/search?q=lease&limit=5",
        "/record/1",
        "/status?limit=5",
        "/status/Reeves?limit=5",
        "/test/tyler?county=Reeves",
    )
    for path in reads:
        status, headers, payload = call(args.base, path, token=read_token)
        expected = {200, 404} if path.startswith("/record/") else {200}
        require(status in expected, path, status)
        if path.startswith("/record/") and status == 200:
            require(
                isinstance(payload, dict)
                and isinstance(payload.get("record"), dict)
                and "r2_key" not in payload["record"],
                "record response shape",
                status,
            )
        require_headers(headers)
        checks += 1

    seed = uuid.uuid4().hex
    writes = (
        ("/scrape", {"county": "Reeves", "instrumentType": "Deed", "startPage": 1}),
        ("/scrape/all", {"county": "Reeves"}),
        ("/scrape/multi", {"counties": ["Reeves", "Ward"]}),
        ("/discover", {"county": "Reeves"}),
        ("/pause/1", None),
        ("/resume/1", None),
        ("/scrape/direct", {"county": "Reeves", "instrumentType": "Deed", "pages": 2}),
    )
    for index, (path, body) in enumerate(writes):
        status, headers, payload = call(
            args.base,
            path,
            method="POST",
            token=write_token,
            body=body,
            idempotency=f"smoke-{seed}-{index}",
            smoke_token=smoke_token,
        )
        require(status in {200, 202} and "preview" in str(payload), path, status)
        require_headers(headers)
        checks += 1

    status, headers, _ = call(
        args.base,
        "/scrape",
        method="POST",
        token=read_token,
        body={"county": "Reeves", "instrumentType": "Deed", "startPage": 1},
        idempotency=f"smoke-{seed}-scope",
        smoke_token=smoke_token,
    )
    require(status == 403, "read credential cannot write", status)
    require_headers(headers)
    checks += 1

    status, headers, _ = call(args.base, "/missing", token=read_token)
    require(status == 404, "404", status)
    require_headers(headers)
    checks += 1
    if args.force_fail:
        print(json.dumps({"ok": False, "checks": checks, "forced_failure": True}, sort_keys=True))
        return 9
    print(json.dumps({"ok": True, "checks": checks}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
