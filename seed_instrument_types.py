"""Seed and attest the exact instrument taxonomy embedded in rescued v35 source."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import storage

MANIFEST_PATH = Path(__file__).with_name("instrument_types.json")
MANIFEST_SHA256 = "86c93f6e15decdd3cdfb5aaad59d23ec6a23129c38e6f65fc8299611892771a9"
SOURCE_WORKER_SHA256 = "c17f54dc2e9ce9829cf9bf845dfa36a11e6b8bbf044bfc01446e4c00f28c7735"
TAXONOMY_SHA256 = "fadc787a2cb6457384740fbd0ef42e73cfba7311840ddbd628dead23528da863"
EXPECTED_COUNT = 21


@dataclass(frozen=True, slots=True)
class SeedResult:
    status: str
    source_count: int
    target_count: int
    source_digest: str
    target_digest: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    serialized = json.dumps(
        list(rows), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def load_manifest(path: Path = MANIFEST_PATH) -> list[dict[str, Any]]:
    if sha256_file(path) != MANIFEST_SHA256:
        raise ValueError("instrument taxonomy manifest SHA256 mismatch")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ValueError("unsupported instrument taxonomy schema")
    if document.get("source_worker_sha256") != SOURCE_WORKER_SHA256:
        raise ValueError("instrument taxonomy source identity mismatch")
    rows = document.get("instrument_types")
    if not isinstance(rows, list) or len(rows) != EXPECTED_COUNT:
        raise ValueError("instrument taxonomy must contain exactly 21 rows")
    expected_ids = list(range(1, EXPECTED_COUNT + 1))
    if [row.get("id") for row in rows] != expected_ids:
        raise ValueError("instrument taxonomy IDs must be contiguous and ordered")
    names = [row.get("name") for row in rows]
    if any(not isinstance(name, str) or not name or name != name.upper() for name in names):
        raise ValueError("instrument taxonomy contains an invalid name")
    if len(set(names)) != EXPECTED_COUNT or any(row.get("code") is not None for row in rows):
        raise ValueError("instrument taxonomy names/codes are not canonical")
    if _canonical_digest(rows) != TAXONOMY_SHA256:
        raise ValueError("instrument taxonomy semantic digest mismatch")
    return rows


def seed_taxonomy(
    connection: storage.Connection, *, manifest_path: Path = MANIFEST_PATH
) -> SeedResult:
    rows = load_manifest(manifest_path)
    expected = [(row["id"], row["name"], row["code"]) for row in rows]
    with storage._transaction(connection), connection.cursor() as cursor:
        cursor.execute(
            f"SELECT id, name, code FROM {storage.SCHEMA}.instrument_types ORDER BY id"
        )
        existing_raw = cursor.fetchall()
        existing = [
            (
                int(row["id"]),
                str(row["name"]),
                row["code"],
            )
            if isinstance(row, Mapping)
            else (int(row[0]), str(row[1]), row[2])
            for row in existing_raw
        ]
        if not existing:
            cursor.executemany(
                f"INSERT INTO {storage.SCHEMA}.instrument_types "
                "(id, name, code, created_at) VALUES (%s, %s, %s, NULL)",
                expected,
            )
            cursor.execute(
                "SELECT setval(pg_get_serial_sequence(%s, 'id'), %s, true)",
                (f"{storage.SCHEMA}.instrument_types", EXPECTED_COUNT),
            )
            status = "seeded"
            existing = expected
        else:
            by_id = {row[0]: row for row in existing}
            if any(by_id.get(row[0]) != row for row in expected):
                raise RuntimeError("instrument taxonomy target conflicts with rescued source")
            status = "no-op" if len(existing) == EXPECTED_COUNT else "preserved-operational-state"

        target_subset = [row for row in existing if 1 <= row[0] <= EXPECTED_COUNT]
        target_rows = [
            {"id": row[0], "name": row[1], "code": row[2]} for row in target_subset
        ]
        target_digest = _canonical_digest(target_rows)
        if len(target_rows) != EXPECTED_COUNT or target_digest != TAXONOMY_SHA256:
            raise RuntimeError("instrument taxonomy subset verification failed")
        cursor.execute(
            f"""
            INSERT INTO {storage.SCHEMA}.migration_receipts
                (source_kind, source_identity, source_sha256, source_count,
                 target_count, source_digest, target_digest, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (source_kind, source_identity) DO UPDATE SET
                source_sha256 = EXCLUDED.source_sha256,
                source_count = EXCLUDED.source_count,
                target_count = EXCLUDED.target_count,
                source_digest = EXCLUDED.source_digest,
                target_digest = EXCLUDED.target_digest,
                completed_at = clock_timestamp(), details = EXCLUDED.details
            """,
            (
                "source-taxonomy-v1",
                "shadowglass-v35-instrument-types",
                MANIFEST_SHA256,
                EXPECTED_COUNT,
                EXPECTED_COUNT,
                TAXONOMY_SHA256,
                target_digest,
                json.dumps(
                    {
                        "source_worker_sha256": SOURCE_WORKER_SHA256,
                        "identity": "id+name+code",
                        "version": 1,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
    return SeedResult(
        status=status,
        source_count=EXPECTED_COUNT,
        target_count=len(existing),
        source_digest=TAXONOMY_SHA256,
        target_digest=target_digest,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args(argv)
    dsn = args.dsn_file.read_text(encoding="utf-8").strip()
    if not dsn:
        parser.error("--dsn-file is empty")
    connection = storage.connect(dsn)
    try:
        result = seed_taxonomy(connection, manifest_path=args.manifest)
    finally:
        connection.close()
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
