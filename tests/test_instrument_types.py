from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import seed_instrument_types as module


class FakeDatabase:
    def __init__(self, rows: list[tuple[int, str, int | None]] | None = None) -> None:
        self.rows = list(rows or [])
        self.inserted: list[tuple[int, str, int | None]] = []
        self.receipt_written = False

    def __enter__(self) -> FakeDatabase:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def cursor(self) -> FakeDatabase:
        return self

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        if "INSERT INTO cf_shadowglass_v35.migration_receipts" in query:
            self.receipt_written = True

    def executemany(
        self, query: str, rows: list[tuple[int, str, int | None]]
    ) -> None:
        assert "INSERT INTO cf_shadowglass_v35.instrument_types" in query
        self.inserted.extend(rows)
        self.rows.extend(rows)

    def fetchall(self) -> list[tuple[int, str, int | None]]:
        return list(self.rows)


def test_manifest_is_exactly_source_bound() -> None:
    rows = module.load_manifest()
    assert len(rows) == 21
    assert [row["id"] for row in rows] == list(range(1, 22))
    assert module._canonical_digest(rows) == module.TAXONOMY_SHA256


def test_manifest_tamper_fails_closed(tmp_path: Path) -> None:
    document = json.loads(module.MANIFEST_PATH.read_text(encoding="utf-8"))
    document["instrument_types"][0]["name"] = "CHANGED"
    path = tmp_path / "instrument_types.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256"):
        module.load_manifest(path)


def test_seed_is_atomic_and_receipted() -> None:
    database = FakeDatabase()
    result = module.seed_taxonomy(database)
    assert result.status == "seeded"
    assert result.source_count == result.target_count == 21
    assert len(database.inserted) == 21
    assert database.receipt_written


def test_seed_rejects_conflicting_operational_state() -> None:
    database = FakeDatabase([(1, "WRONG", None)])
    with pytest.raises(RuntimeError, match="conflicts"):
        module.seed_taxonomy(database)
