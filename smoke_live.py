#!/usr/bin/env python3
"""Live HTTP smoke for staging and production without dispatching queue work."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def request(
    base_url: str,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    data = None if body is None else json.dumps(body).encode()
    incoming = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        incoming["Content-Type"] = "application/json"
    call = urllib.request.Request(base_url + path, data=data, headers=incoming, method=method)
    try:
        with urllib.request.urlopen(call, timeout=15) as response:
            return response.status, {key.lower(): value for key, value in response.headers.items()}, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {key.lower(): value for key, value in exc.headers.items()}, exc.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8287")
    parser.add_argument(
        "--credential-dir",
        type=Path,
        default=Path("/etc/echo/credentials/shadowglass-v7-command"),
    )
    args = parser.parse_args()
    key = (args.credential_dir / "command-key").read_text().strip()
    if not key:
        raise RuntimeError("command credential is unavailable")
    auth = {"X-Echo-Command-Key": key}
    checks: list[dict[str, Any]] = []

    def check(name: str, method: str, path: str, expected: int, **kwargs: Any) -> None:
        status, headers, body = request(args.base_url, method, path, **kwargs)
        passed = status == expected
        if expected == 200:
            passed = passed and headers.get("x-content-type-options") == "nosniff"
            passed = passed and headers.get("x-frame-options") == "DENY"
        checks.append({"name": name, "passed": passed, "status": status, "bytes": len(body)})

    for path in ("/", "/counties", "/dashboard", "/health", "/stats"):
        check("public:" + path, "GET", path, 200)
    for path in ("/status", "/record/does-not-exist", "/search?q=deed"):
        check("auth-denial:" + path, "GET", path, 401)
    check("authenticated-status", "GET", "/status", 200, headers=auth)
    check(
        "cors-allowed",
        "OPTIONS",
        "/scrape",
        204,
        headers={"Origin": "https://throne.echo-op.com"},
    )
    check(
        "cors-denied",
        "OPTIONS",
        "/scrape",
        403,
        headers={"Origin": "https://example.invalid"},
    )
    single = {"county": "Midland", "instrument_type": "Deed", "platform": "tyler"}
    mutation_bodies = {
        "/discover": single,
        "/scrape": single,
        "/scrape/all": {"counties": ["Midland"], "instrument_type": "Deed", "platform": "tyler"},
        "/scrape/multi": {"jobs": [single]},
        "/scrape/platform": {"counties": ["Midland"], "instrument_type": "Deed", "platform": "tyler"},
    }
    for path, mutation_body in mutation_bodies.items():
        check("mutation-auth-denial:" + path, "POST", path, 401, body=mutation_body)
    for path in ("/pause/invalid", "/resume/invalid"):
        check("mutation-auth-denial:" + path, "POST", path, 401)
    check("test-auth-denial", "GET", "/test/tyler", 401)

    passed = all(item["passed"] for item in checks)
    print(json.dumps({"ok": passed, "checks": checks}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
