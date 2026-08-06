#!/usr/bin/env python3
"""Apply reviewed, fail-closed county endpoint corrections after D1 import."""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import storage


DEFAULT_MANIFEST = Path(__file__).with_name("endpoint_overrides.json")
EXPECTED_COUNTIES = frozenset(
    {
        "MIDLAND",
        "ECTOR",
        "REEVES",
        "MARTIN",
        "HOWARD",
        "ANDREWS",
        "WARD",
        "CRANE",
        "PECOS",
        "LOVING",
        "UPTON",
        "WINKLER",
        "GLASSCOCK",
        "DAWSON",
        "GAINES",
        "STERLING",
        "CULBERSON",
        "TAYLOR",
    }
)
ALLOWED_PLATFORMS = frozenset({"PUBLICSEARCH", "TYLER_TECH"})


@dataclass(frozen=True, slots=True)
class EndpointOverride:
    name: str
    active: bool
    platform: str | None
    base_url: str | None
    official_source: str
    reason: str


@dataclass(frozen=True, slots=True)
class EndpointManifest:
    source_sha256: str
    state_digest: str
    verified_at: str
    entries: tuple[EndpointOverride, ...]


def _exact_https_url(value: str, *, provider: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise ValueError("endpoint manifest contains a non-exact HTTPS URL")
    if provider and parsed.path not in {"", "/", "/web", "/web/"}:
        raise ValueError("provider base URL contains an unsupported path")
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path or "/", "", ""))


def load_manifest(path: Path = DEFAULT_MANIFEST) -> EndpointManifest:
    raw = path.read_bytes()
    document = json.loads(raw)
    if document.get("version") != 1 or not isinstance(document.get("verified_at"), str):
        raise ValueError("endpoint manifest version is unsupported")
    rows = document.get("counties")
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_COUNTIES):
        raise ValueError("endpoint manifest county count is invalid")
    entries: list[EndpointOverride] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("endpoint manifest entry is invalid")
        name = str(row.get("name", "")).strip().upper()
        active = row.get("active")
        platform = row.get("platform")
        base_url = row.get("base_url")
        official_source = str(row.get("official_source", "")).strip()
        reason = str(row.get("reason", "")).strip()
        if not name or not isinstance(active, bool) or len(reason) < 20:
            raise ValueError("endpoint manifest entry is incomplete")
        official_source = _exact_https_url(official_source, provider=False)
        if active:
            if platform not in ALLOWED_PLATFORMS or not isinstance(base_url, str):
                raise ValueError("active endpoint is missing a supported provider")
            base_url = _exact_https_url(base_url, provider=True)
            provider_host = urllib.parse.urlsplit(base_url).hostname or ""
            if platform == "PUBLICSEARCH" and not provider_host.endswith(".publicsearch.us"):
                raise ValueError("PublicSearch endpoint uses the wrong provider domain")
            if platform == "TYLER_TECH" and not provider_host.endswith(".tylerhost.net"):
                raise ValueError("Tyler endpoint uses the wrong provider domain")
        elif platform is not None or base_url is not None:
            raise ValueError("inactive endpoint must not declare a provider")
        entries.append(
            EndpointOverride(
                name,
                active,
                platform,
                base_url,
                official_source,
                reason,
            )
        )
    names = [entry.name for entry in entries]
    if frozenset(names) != EXPECTED_COUNTIES or len(names) != len(set(names)):
        raise ValueError("endpoint manifest county identities are invalid")
    canonical = [
        {
            "active": entry.active,
            "base_url": entry.base_url,
            "name": entry.name,
            "platform": entry.platform,
        }
        for entry in sorted(entries, key=lambda item: item.name)
    ]
    digest = hashlib.sha256(
        json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return EndpointManifest(
        source_sha256=hashlib.sha256(raw).hexdigest(),
        state_digest=digest,
        verified_at=document["verified_at"],
        entries=tuple(entries),
    )


def _row_mapping(row: Any) -> Mapping[str, Any]:
    if not isinstance(row, Mapping):
        raise ValueError("endpoint query did not return named columns")
    return row


def _state_matches(rows: list[Any], entries: tuple[EndpointOverride, ...]) -> bool:
    current = {str(_row_mapping(row)["name"]).upper(): _row_mapping(row) for row in rows}
    if not EXPECTED_COUNTIES.issubset(current):
        return False
    if any(
        bool(int(row["is_active"] or 0))
        for name, row in current.items()
        if name not in EXPECTED_COUNTIES
    ):
        return False
    for entry in entries:
        row = current[entry.name]
        if bool(int(row["is_active"] or 0)) != entry.active:
            return False
        if entry.active and (
            str(row["base_url"]) != entry.base_url
            or str(row["platform"]) != entry.platform
        ):
            return False
    return True


def apply_manifest(connection: Any, manifest: EndpointManifest) -> str:
    identity = f"county-endpoints-v1:{manifest.source_sha256}"
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"LOCK TABLE {storage.SCHEMA}.counties IN SHARE ROW EXCLUSIVE MODE"
            )
            cursor.execute(
                f"SELECT name, base_url, platform, is_active "
                f"FROM {storage.SCHEMA}.counties ORDER BY id"
            )
            before = cursor.fetchall()
            imported_names = {
                str(_row_mapping(row)["name"]).upper() for row in before
            }
            if not EXPECTED_COUNTIES.issubset(imported_names):
                raise ValueError("imported county identities do not match the reviewed manifest")
            cursor.execute(
                f"SELECT 1 FROM {storage.SCHEMA}.migration_receipts "
                "WHERE source_kind = %s AND source_identity = %s",
                ("endpoint-overrides", identity),
            )
            existing = cursor.fetchone()
            if existing:
                if not _state_matches(before, manifest.entries):
                    raise ValueError("endpoint receipt exists but active county state drifted")
                # A no-op re-verification is evidence too. Refresh only the
                # verification time after the full installed state comparison
                # succeeds so finalization can require recent proof.
                cursor.execute(
                    f"UPDATE {storage.SCHEMA}.migration_receipts "
                    "SET completed_at = clock_timestamp() "
                    "WHERE source_kind = %s AND source_identity = %s",
                    ("endpoint-overrides", identity),
                )
                if cursor.rowcount != 1:
                    raise ValueError("endpoint receipt refresh did not update exactly one row")
                return "already_applied"
            cursor.execute(f"UPDATE {storage.SCHEMA}.counties SET is_active = 0")
            if cursor.rowcount != len(before):
                raise ValueError("county fail-closed reset did not update every imported row")
            for entry in manifest.entries:
                if entry.active:
                    cursor.execute(
                        f"UPDATE {storage.SCHEMA}.counties "
                        "SET base_url = %s, platform = %s, is_active = 1 "
                        "WHERE UPPER(name) = %s",
                        (entry.base_url, entry.platform, entry.name),
                    )
                else:
                    cursor.execute(
                        f"UPDATE {storage.SCHEMA}.counties SET is_active = 0 "
                        "WHERE UPPER(name) = %s",
                        (entry.name,),
                    )
                if cursor.rowcount != 1:
                    raise ValueError("endpoint override did not update exactly one county")
            cursor.execute(
                f"SELECT name, base_url, platform, is_active "
                f"FROM {storage.SCHEMA}.counties ORDER BY id"
            )
            after = cursor.fetchall()
            if not _state_matches(after, manifest.entries):
                raise ValueError("endpoint override verification failed")
            active_count = sum(1 for entry in manifest.entries if entry.active)
            cursor.execute(
                f"INSERT INTO {storage.SCHEMA}.migration_receipts "
                "(source_kind, source_identity, source_sha256, source_count, target_count, "
                " source_digest, target_digest, details) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
                (
                    "endpoint-overrides",
                    identity,
                    manifest.source_sha256,
                    len(manifest.entries),
                    len(after),
                    manifest.state_digest,
                    manifest.state_digest,
                    json.dumps(
                        {
                            "active_count": active_count,
                            "inactive_count": len(manifest.entries) - active_count,
                            "verified_at": manifest.verified_at,
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                ),
            )
    return "applied"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    if args.validate_only:
        status = "validated"
    else:
        dsn = args.dsn_file.read_text(encoding="utf-8").strip()
        connection = storage.connect(dsn)
        try:
            status = apply_manifest(connection, manifest)
        finally:
            connection.close()
    print(
        json.dumps(
            {
                "active_count": sum(1 for entry in manifest.entries if entry.active),
                "county_count": len(manifest.entries),
                "ok": True,
                "source_sha256": manifest.source_sha256,
                "status": status,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
