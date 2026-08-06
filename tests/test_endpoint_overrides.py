from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import apply_endpoint_overrides as endpoints


class FakeCursor:
    def __init__(self, rows: list[dict[str, Any]], *, receipt: bool = False) -> None:
        self.rows = rows
        self.receipt = receipt
        self.result: list[dict[str, Any]] = []
        self.rowcount = 0
        self.receipt_inserted = False
        self.receipt_refreshed = False

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        normalized = " ".join(query.split())
        self.rowcount = 0
        if normalized.startswith("LOCK TABLE"):
            return
        if normalized.startswith("SELECT name, base_url"):
            self.result = [dict(row) for row in self.rows]
            return
        if normalized.startswith("SELECT 1 FROM"):
            self.result = [{"one": 1}] if self.receipt else []
            return
        if normalized.startswith("UPDATE") and "migration_receipts" in normalized:
            self.receipt_refreshed = True
            self.rowcount = 1
            return
        if "UPDATE" in normalized and "SET base_url" in normalized:
            base_url, platform, name = params
            row = next(item for item in self.rows if item["name"] == name)
            row.update(base_url=base_url, platform=platform, is_active=1)
            self.rowcount = 1
            return
        if "UPDATE" in normalized and "SET is_active = 0" in normalized:
            if params:
                (name,) = params
                row = next(item for item in self.rows if item["name"] == name)
                row["is_active"] = 0
                self.rowcount = 1
            else:
                for row in self.rows:
                    row["is_active"] = 0
                self.rowcount = len(self.rows)
            return
        if normalized.startswith("INSERT INTO"):
            self.receipt_inserted = True
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self.result)

    def fetchone(self) -> dict[str, Any] | None:
        return self.result[0] if self.result else None


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self.fake_cursor = cursor

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def cursor(self) -> FakeCursor:
        return self.fake_cursor


def rescued_rows(manifest: endpoints.EndpointManifest) -> list[dict[str, Any]]:
    return [
        {
            "name": entry.name,
            "base_url": f"https://{entry.name.casefold()}county.publicsearch.us/",
            "platform": "PUBLICSEARCH",
            "is_active": 1,
        }
        for entry in manifest.entries
    ]


def test_reviewed_manifest_is_complete_and_provider_scoped() -> None:
    manifest = endpoints.load_manifest()
    assert len(manifest.entries) == 18
    assert sum(entry.active for entry in manifest.entries) == 7
    assert {entry.name for entry in manifest.entries} == endpoints.EXPECTED_COUNTIES
    assert all(entry.base_url is None for entry in manifest.entries if not entry.active)


def test_manifest_rejects_inactive_provider(tmp_path: Path) -> None:
    document = json.loads(endpoints.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    inactive = next(row for row in document["counties"] if not row["active"])
    inactive["base_url"] = "https://county.example/"
    path = tmp_path / "endpoints.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="inactive endpoint"):
        endpoints.load_manifest(path)


def test_apply_is_atomic_and_writes_a_receipt() -> None:
    manifest = endpoints.load_manifest()
    cursor = FakeCursor(rescued_rows(manifest))
    assert endpoints.apply_manifest(FakeConnection(cursor), manifest) == "applied"
    assert cursor.receipt_inserted
    assert endpoints._state_matches(cursor.rows, manifest.entries)


def test_apply_fails_closed_for_unreviewed_imported_county() -> None:
    manifest = endpoints.load_manifest()
    rows = rescued_rows(manifest)
    rows.append(
        {
            "name": "UNREVIEWED",
            "base_url": "https://unreviewed.example/",
            "platform": "UNKNOWN",
            "is_active": 1,
        }
    )
    cursor = FakeCursor(rows)
    assert endpoints.apply_manifest(FakeConnection(cursor), manifest) == "applied"
    assert rows[-1]["is_active"] == 0
    assert endpoints._state_matches(cursor.rows, manifest.entries)


def test_existing_receipt_fails_closed_on_state_drift() -> None:
    manifest = endpoints.load_manifest()
    cursor = FakeCursor(rescued_rows(manifest), receipt=True)
    with pytest.raises(ValueError, match="state drifted"):
        endpoints.apply_manifest(FakeConnection(cursor), manifest)


def test_existing_matching_receipt_refreshes_verification_time() -> None:
    manifest = endpoints.load_manifest()
    rows = rescued_rows(manifest)
    endpoints.apply_manifest(FakeConnection(FakeCursor(rows)), manifest)
    cursor = FakeCursor(rows, receipt=True)
    assert endpoints.apply_manifest(FakeConnection(cursor), manifest) == "already_applied"
    assert cursor.receipt_refreshed
