"""Hash-pinned, count- and digest-verified D1-to-PostgreSQL importer."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import storage

D1_PATH = Path(
    "/mnt/cf_d1/d1_databases/shadowglass-scraper/shadowglass-scraper.sqlite3"
)
D1_SHA256 = "72926ce6bf1605d577f5e38c43e2ef4376021b63422dfedc0c5a11b3ab53f200"

TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "counties": ("id", "name", "state", "base_url", "platform", "is_active", "created_at"),
    "deed_records": (
        "id",
        "external_id",
        "county",
        "instrument_type",
        "instrument_type_id",
        "grantor",
        "grantee",
        "recorded_date",
        "filing_date",
        "legal_description",
        "legal_normalized",
        "section",
        "block",
        "book",
        "page_num",
        "volume",
        "doc_number",
        "consideration",
        "source_url",
        "r2_key",
        "created_at",
    ),
    "instrument_types": ("id", "name", "code", "created_at"),
    "r2_uploads": (
        "id",
        "r2_key",
        "county_id",
        "instrument_type_id",
        "page_number",
        "record_count",
        "uploaded_at",
    ),
    "scrape_jobs": (
        "id",
        "county_id",
        "instrument_type_id",
        "status",
        "total_records",
        "scraped_records",
        "last_page",
        "started_at",
        "completed_at",
        "updated_at",
    ),
    "scrape_logs": ("id", "job_id", "level", "message", "metadata", "created_at"),
}

SOURCE_TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "counties": (
        "id", "name", "state", "base_url", "is_active", "total_instruments",
        "last_scraped_at", "created_at", "platform",
    ),
    "deed_records": (
        "id", "county", "instrument_type", "doc_id", "instrument_number",
        "recorded_date", "instrument_date", "year", "grantor", "grantee",
        "legal_description", "legal_normalized", "section", "block", "lot",
        "township", "survey", "book", "volume", "page", "book_volume_page",
        "consideration", "page_count", "download_link", "doc_type_code",
        "record_hash", "created_at", "data_quality_score", "subdivision",
        "platform", "source_url",
    ),
    "instrument_types": ("id", "name", "code"),
    "r2_uploads": (
        "id", "r2_key", "county_id", "file_size", "content_type", "uploaded_at",
    ),
    "scrape_jobs": (
        "id", "county_id", "instrument_type_id", "status", "total_records",
        "scraped_records", "last_page", "last_offset", "error_message",
        "started_at", "completed_at", "updated_at",
    ),
    "scrape_logs": ("id", "job_id", "level", "message", "metadata", "created_at"),
}

SOURCE_SELECT: dict[str, tuple[str, ...]] = {
    "counties": tuple(f'"{column}"' for column in TABLE_COLUMNS["counties"]),
    "deed_records": (
        '"id"',
        'COALESCE("instrument_number", "doc_id")',
        '"county"',
        '"instrument_type"',
        "NULL",
        '"grantor"',
        '"grantee"',
        '"recorded_date"',
        '"instrument_date"',
        '"legal_description"',
        '"legal_normalized"',
        '"section"',
        '"block"',
        '"book"',
        '"page"',
        '"volume"',
        'COALESCE("instrument_number", "doc_id")',
        '"consideration"',
        '"source_url"',
        "NULL",
        '"created_at"',
    ),
    "instrument_types": ('"id"', '"name"', '"code"', "NULL"),
    "r2_uploads": ('"id"', '"r2_key"', '"county_id"', "NULL", "NULL", "NULL", '"uploaded_at"'),
    "scrape_jobs": tuple(f'"{column}"' for column in TABLE_COLUMNS["scrape_jobs"]),
    "scrape_logs": tuple(f'"{column}"' for column in TABLE_COLUMNS["scrape_logs"]),
}

SOURCE_EXPRESSION_BY_TARGET: dict[str, dict[str, str]] = {
    table: dict(zip(TABLE_COLUMNS[table], expressions, strict=True))
    for table, expressions in SOURCE_SELECT.items()
}

# Mutable checkpoint/status columns are intentionally excluded.  These
# identities prove every rescued row is still present without treating later
# operational counters, endpoint activation, or timestamps as corruption.
IDENTITY_COLUMNS: dict[str, tuple[str, ...]] = {
    "counties": ("id", "name", "state", "created_at"),
    "deed_records": TABLE_COLUMNS["deed_records"],
    "instrument_types": TABLE_COLUMNS["instrument_types"],
    "r2_uploads": ("id", "r2_key", "county_id", "instrument_type_id", "page_number"),
    "scrape_jobs": ("id", "county_id", "instrument_type_id"),
    "scrape_logs": TABLE_COLUMNS["scrape_logs"],
}


@dataclass(frozen=True, slots=True)
class Fingerprint:
    count: int
    digest: str


@dataclass(frozen=True, slots=True)
class ImportResult:
    table: str
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


def _row_bytes(row: Sequence[Any]) -> bytes:
    return json.dumps(
        list(row), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"


def fingerprint_rows(rows: Iterable[Sequence[Any]]) -> Fingerprint:
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        digest.update(_row_bytes(row))
        count += 1
    return Fingerprint(count, digest.hexdigest())


def open_verified_d1(
    path: Path = D1_PATH, *, expected_sha256: str = D1_SHA256
) -> sqlite3.Connection:
    """Open the exact immutable rescue after checking bytes and SQLite integrity."""

    resolved = path.resolve(strict=True)
    actual_hash = sha256_file(resolved)
    if actual_hash != expected_sha256:
        raise ValueError("D1 rescue SHA256 mismatch")
    source = sqlite3.connect(f"{resolved.as_uri()}?mode=ro&immutable=1", uri=True)
    try:
        integrity = source.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",):
            raise ValueError("D1 rescue integrity_check failed")
        for table, expected_columns in SOURCE_TABLE_COLUMNS.items():
            # Table names are compile-time constants from SOURCE_TABLE_COLUMNS.
            actual_columns = tuple(row[1] for row in source.execute(f'PRAGMA table_info("{table}")'))
            if actual_columns != expected_columns:
                raise ValueError(f"D1 table shape mismatch: {table}")
    except Exception:
        source.close()
        raise
    return source


def _source_rows(source: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> Iterable[tuple[Any, ...]]:
    expressions = SOURCE_EXPRESSION_BY_TARGET[table]
    if not columns or any(column not in expressions for column in columns):
        raise ValueError("source projection is outside the target contract")
    projection = ", ".join(expressions[column] for column in columns)
    cursor = source.execute(f'SELECT {projection} FROM "{table}" ORDER BY "id"')
    while True:
        rows = cursor.fetchmany(2_000)
        if not rows:
            return
        yield from rows


def source_fingerprint(
    source: sqlite3.Connection, table: str, columns: tuple[str, ...]
) -> Fingerprint:
    return fingerprint_rows(_source_rows(source, table, columns))


def _target_fingerprint(connection: storage.Connection, table: str, columns: tuple[str, ...]) -> Fingerprint:
    quoted = ", ".join(columns)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {quoted} FROM {storage.SCHEMA}.{table} ORDER BY id")
        digest = hashlib.sha256()
        count = 0
        while True:
            rows = cursor.fetchmany(2_000)
            if not rows:
                break
            for raw in rows:
                if isinstance(raw, Mapping):
                    row = tuple(raw[column] for column in columns)
                else:
                    row = tuple(raw)
                digest.update(_row_bytes(row))
                count += 1
    return Fingerprint(count, digest.hexdigest())


def imported_subset_fingerprints(
    source: sqlite3.Connection,
    target: storage.Connection,
    *,
    table: str,
    batch_size: int = 2_000,
) -> tuple[Fingerprint, Fingerprint]:
    """Fingerprint immutable identities for exactly the rescued primary keys."""

    columns = IDENTITY_COLUMNS[table]
    source_fp = source_fingerprint(source, table, columns)
    digest = hashlib.sha256()
    count = 0
    ids = [int(row[0]) for row in _source_rows(source, table, ("id",))]
    quoted = ", ".join(columns)
    with target.cursor() as cursor:
        for offset in range(0, len(ids), batch_size):
            batch = ids[offset : offset + batch_size]
            cursor.execute(
                f"SELECT {quoted} FROM {storage.SCHEMA}.{table} "
                "WHERE id = ANY(%s) ORDER BY id",
                (batch,),
            )
            for raw in cursor.fetchall():
                if isinstance(raw, Mapping):
                    row = tuple(raw[column] for column in columns)
                else:
                    row = tuple(raw)
                digest.update(_row_bytes(row))
                count += 1
    return source_fp, Fingerprint(count, digest.hexdigest())


def verify_imported_subset(
    source: sqlite3.Connection,
    target: storage.Connection,
    *,
    table: str,
    source_sha256: str,
) -> Fingerprint:
    source_fp, target_fp = imported_subset_fingerprints(source, target, table=table)
    if target_fp != source_fp:
        raise RuntimeError(f"rescued imported subset changed or is missing: {table}")
    with target.cursor() as cursor:
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
                "d1_imported_subset_v1",
                table,
                source_sha256,
                source_fp.count,
                target_fp.count,
                source_fp.digest,
                target_fp.digest,
                json.dumps(
                    {"identity_columns": list(IDENTITY_COLUMNS[table]), "version": 1},
                    separators=(",", ":"),
                ),
            ),
        )
    return target_fp


def _matching_receipt(
    connection: storage.Connection,
    *,
    table: str,
    source_sha256: str,
    source: Fingerprint,
) -> bool:
    """Return whether a trusted receipt proves the immutable initial import.

    Operational tables are expected to diverge after cutover.  The receipt is
    intentionally checked against the rescued source, rather than the current
    mutable target, so a redeploy never overwrites newer live rows.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT source_count, target_count, source_digest, target_digest
            FROM {storage.SCHEMA}.migration_receipts
            WHERE source_kind = %s AND source_identity = %s AND source_sha256 = %s
            """,
            ("d1_table", table, source_sha256),
        )
        row = cursor.fetchone()
    if row is None:
        return False
    if isinstance(row, Mapping):
        values = (
            row["source_count"],
            row["target_count"],
            row["source_digest"],
            row["target_digest"],
        )
    else:
        values = tuple(row)
    return values == (source.count, source.count, source.digest, source.digest)


def _upsert_batch(cursor: Any, table: str, columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    if not rows:
        return
    column_sql = ", ".join(columns)
    placeholders = ", ".join("%s" for _ in columns)
    cursor.executemany(
        f"""
        INSERT INTO {storage.SCHEMA}.{table} ({column_sql})
        VALUES ({placeholders})
        ON CONFLICT (id) DO NOTHING
        """,
        rows,
    )


def import_table(
    source: sqlite3.Connection,
    target: storage.Connection,
    *,
    table: str,
    source_sha256: str,
    batch_size: int = 2_000,
) -> ImportResult:
    """Idempotently import and verify one allowlisted legacy table."""

    if table not in TABLE_COLUMNS:
        raise ValueError("table is not in the migration allowlist")
    if not 1 <= batch_size <= 20_000:
        raise ValueError("batch_size must be between 1 and 20000")
    columns = TABLE_COLUMNS[table]
    source_fp = source_fingerprint(source, table, columns)
    current_target = _target_fingerprint(target, table, columns)
    receipt_matches = _matching_receipt(
        target,
        table=table,
        source_sha256=source_sha256,
        source=source_fp,
    )
    if current_target == source_fp and receipt_matches:
        with storage._transaction(target):
            verify_imported_subset(
                source, target, table=table, source_sha256=source_sha256
            )
        return ImportResult(
            table, "no-op", source_fp.count, current_target.count, source_fp.digest, current_target.digest
        )
    if receipt_matches and current_target.count >= source_fp.count:
        with storage._transaction(target):
            verify_imported_subset(
                source, target, table=table, source_sha256=source_sha256
            )
        return ImportResult(
            table,
            "preserved-operational-state",
            source_fp.count,
            current_target.count,
            source_fp.digest,
            current_target.digest,
        )
    if current_target.count:
        raise RuntimeError(
            f"refusing to overwrite a non-matching operational table: {table}"
        )
    if receipt_matches:
        raise RuntimeError(f"trusted import receipt exists but target rows are missing: {table}")

    transaction = storage._transaction(target)
    with transaction:
        with target.cursor() as cursor:
            batch: list[tuple[Any, ...]] = []
            for row in _source_rows(source, table, columns):
                batch.append(row)
                if len(batch) >= batch_size:
                    _upsert_batch(cursor, table, columns, batch)
                    batch.clear()
            _upsert_batch(cursor, table, columns, batch)
            cursor.execute(
                f"""
                SELECT setval(
                    pg_get_serial_sequence(%s, 'id'),
                    COALESCE(MAX(id), 1),
                    EXISTS (SELECT 1 FROM {storage.SCHEMA}.{table})
                )
                FROM {storage.SCHEMA}.{table}
                """,
                (f"{storage.SCHEMA}.{table}",),
            )

        target_fp = _target_fingerprint(target, table, columns)
        if target_fp != source_fp:
            raise ValueError(f"D1 target verification failed: {table}")
        with target.cursor() as cursor:
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
                    "d1_table",
                    table,
                    source_sha256,
                    source_fp.count,
                    target_fp.count,
                    source_fp.digest,
                    target_fp.digest,
                    json.dumps({"table": table}, separators=(",", ":")),
                ),
            )
        verify_imported_subset(
            source, target, table=table, source_sha256=source_sha256
        )
    return ImportResult(
        table, "imported", source_fp.count, target_fp.count, source_fp.digest, target_fp.digest
    )


def import_database(
    target: storage.Connection,
    *,
    source_path: Path = D1_PATH,
    expected_sha256: str = D1_SHA256,
    batch_size: int = 2_000,
) -> list[ImportResult]:
    """Import all six tables after one immutable rescue verification."""

    source = open_verified_d1(source_path, expected_sha256=expected_sha256)
    try:
        return [
            import_table(
                source,
                target,
                table=table,
                source_sha256=expected_sha256,
                batch_size=batch_size,
            )
            for table in TABLE_COLUMNS
        ]
    finally:
        source.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=2_000)
    args = parser.parse_args(argv)
    dsn = args.dsn_file.read_text(encoding="utf-8").strip()
    if not dsn:
        parser.error("--dsn-file is empty")
    connection = storage.connect(dsn)
    try:
        results = import_database(connection, batch_size=args.batch_size)
    finally:
        connection.close()
    # The report deliberately contains only table names, counts, and digests.
    print(json.dumps([asdict(result) for result in results], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
