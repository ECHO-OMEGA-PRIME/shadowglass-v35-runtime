"""Fail-closed importer for the shared rescued DEDUP_KV namespace."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import storage

KV_ROOT = Path("/mnt/cf_kv_r2/kv_namespaces/shadowglass-v35-DEDUP_KV")
KV_INDEX = KV_ROOT / "keys.jsonl"
KV_VALUES = KV_ROOT / "values"
KV_INDEX_SHA256 = "5722a985d51eba21b56be703fded5954fafee6f6d552960ebe9ae3d6cb962731"
KV_VALUE_SHA256 = frozenset(
    {
        "1e0969d155de661a513b63a4222a42aa80a5540795a8665cadeb81a54bf32982",
        "3e50336c2ed0f99ca6c8488ff2355e9ebd635d8eca9f2976c1a9af82645417c0",
    }
)
KV_SCOPE = "shadowglass-v35"


@dataclass(frozen=True, slots=True)
class IndexEntry:
    key: str
    value_path: Path
    expected_sha256: str | None
    etag: str | None


@dataclass(frozen=True, slots=True)
class KVImportResult:
    status: str
    indexed_count: int
    blob_count: int
    owned_count: int
    source_digest: str
    target_digest: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_index_document(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        if path.suffix.lower() == ".jsonl":
            return [json.loads(line) for line in stream if line.strip()]
        return json.load(stream)


def _raw_entries(document: Any) -> list[tuple[str | None, Any]]:
    if isinstance(document, list):
        return [(None, item) for item in document]
    if not isinstance(document, Mapping):
        raise ValueError("KV index must be a JSON object or array")
    for container_name in ("entries", "items", "keys"):
        if container_name in document:
            container = document[container_name]
            if isinstance(container, list):
                return [(None, item) for item in container]
            if isinstance(container, Mapping):
                return [(str(key), value) for key, value in container.items()]
            raise ValueError("KV index entry container has an unsupported shape")
    return [(str(key), value) for key, value in document.items()]


def _resolve_blob(values_dir: Path, reference: str) -> Path:
    if not reference or "\x00" in reference:
        raise ValueError("KV value reference is invalid")
    relative = Path(reference.replace("\\", "/"))
    if relative.parts and relative.parts[0] == "values":
        relative = Path(*relative.parts[1:])
    if relative.is_absolute():
        raise ValueError("KV value reference must be relative")
    root = values_dir.resolve(strict=True)
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("KV value reference escapes the values directory") from exc
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("KV value reference is not a regular file")
    return candidate


def parse_verified_index(
    index_path: Path = KV_INDEX,
    values_dir: Path = KV_VALUES,
    *,
    expected_sha256: str = KV_INDEX_SHA256,
    expected_value_sha256: frozenset[str] = KV_VALUE_SHA256,
) -> list[IndexEntry]:
    """Verify the two-entry rescue index and both referenced value blobs."""

    resolved_index = index_path.resolve(strict=True)
    if sha256_file(resolved_index) != expected_sha256:
        raise ValueError("KV rescue index SHA256 mismatch")
    document = _load_index_document(resolved_index)
    entries: list[IndexEntry] = []
    actual_blob_hashes: set[str] = set()
    for key_hint, raw in _raw_entries(document):
        if isinstance(raw, str):
            raw = {"path": raw}
        if not isinstance(raw, Mapping):
            raise ValueError("KV index entry has an unsupported shape")
        key = raw.get("key", raw.get("name", key_hint))
        reference = raw.get(
            "value_path", raw.get("path", raw.get("file", raw.get("filename")))
        )
        # The verified Cloudflare rescue uses a 16-character opaque blob id in
        # ``hash`` and stores it as values/<id>.bin.  It is a locator, not a
        # content SHA256; content hashes are honored only from explicit SHA fields.
        if reference is None and isinstance(raw.get("hash"), str):
            reference = f"{raw['hash']}.bin"
        if not isinstance(key, str) or not key or len(key) > 1024:
            raise ValueError("KV index contains an invalid key")
        if not isinstance(reference, str):
            raise ValueError("KV index entry is missing its value reference")
        expected = raw.get("sha256", raw.get("value_sha256"))
        if expected is not None and (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected)
        ):
            raise ValueError("KV index contains an invalid value digest")
        blob = _resolve_blob(values_dir, reference)
        actual_blob_hash = sha256_file(blob)
        actual_blob_hashes.add(actual_blob_hash)
        if expected is not None and actual_blob_hash != expected.lower():
            raise ValueError("KV value blob SHA256 mismatch")
        etag = raw.get("etag")
        entries.append(
            IndexEntry(
                key=key,
                value_path=blob,
                expected_sha256=None if expected is None else expected.lower(),
                etag=None if etag is None else str(etag)[:256],
            )
        )

    if len(entries) != 2 or len({entry.value_path for entry in entries}) != 2:
        raise ValueError("KV rescue must contain exactly two indexed value blobs")
    if actual_blob_hashes != expected_value_sha256:
        raise ValueError("KV rescued value blob set SHA256 mismatch")
    regular_files = [path for path in values_dir.resolve(strict=True).rglob("*") if path.is_file()]
    if len(regular_files) != 2:
        raise ValueError("KV values directory must contain exactly two value blobs")
    return entries


def _digest_entries(entries: Iterable[tuple[str, bytes]]) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    for key, value in entries:
        key_bytes = key.encode("utf-8")
        digest.update(len(key_bytes).to_bytes(4, "big"))
        digest.update(key_bytes)
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
        count += 1
    return count, digest.hexdigest()


def _target_entries(connection: storage.Connection, scope: str) -> list[tuple[str, bytes]]:
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT key, value FROM {storage.SCHEMA}.dedup_kv WHERE scope = %s ORDER BY key",
            (scope,),
        )
        rows = cursor.fetchall()
    result: list[tuple[str, bytes]] = []
    for row in rows:
        if isinstance(row, Mapping):
            key, value = row["key"], row["value"]
        else:
            key, value = row
        result.append((str(key), bytes(value)))
    return result


def _verify_owned_subset(
    source_entries: list[tuple[str, bytes]], target_entries: list[tuple[str, bytes]]
) -> tuple[int, str]:
    target = dict(target_entries)
    rescued = [(key, target[key]) for key, value in source_entries if key in target and target[key] == value]
    if len(rescued) != len(source_entries):
        raise RuntimeError("rescued KV key/value subset changed or is missing")
    return _digest_entries(source_entries)


def _record_subset_receipt(
    connection: storage.Connection,
    *,
    scope: str,
    index_sha256: str,
    source_entries: list[tuple[str, bytes]],
) -> None:
    count, digest = _digest_entries(source_entries)
    with connection.cursor() as cursor:
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
                "kv_imported_subset_v1",
                scope,
                index_sha256,
                count,
                count,
                digest,
                digest,
                json.dumps({"identity": "scope+key+value", "version": 1}, separators=(",", ":")),
            ),
        )


def _receipt_matches(
    connection: storage.Connection,
    *,
    index_sha256: str,
    source_count: int,
    source_digest: str,
    target_count: int,
    target_digest: str,
) -> bool:
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT source_count, target_count, source_digest, target_digest
            FROM {storage.SCHEMA}.migration_receipts
            WHERE source_kind = %s AND source_identity = %s AND source_sha256 = %s
            """,
            ("kv_namespace", KV_SCOPE, index_sha256),
        )
        row = cursor.fetchone()
    if row is None:
        return False
    values = (
        (
            row["source_count"],
            row["target_count"],
            row["source_digest"],
            row["target_digest"],
        )
        if isinstance(row, Mapping)
        else tuple(row)
    )
    return values == (source_count, source_count, source_digest, source_digest)


def import_namespace(
    connection: storage.Connection,
    *,
    index_path: Path = KV_INDEX,
    values_dir: Path = KV_VALUES,
    expected_sha256: str = KV_INDEX_SHA256,
    owned_prefix: str | None = None,
    owned_key_predicate: Callable[[str], bool] | None = None,
    scope: str = KV_SCOPE,
) -> KVImportResult:
    """Import only explicitly owned keys from the shared namespace.

    The caller must provide exactly one ownership policy.  This intentionally
    fails closed instead of treating every key in the shared rescue as ours.
    """

    if (owned_prefix is None) == (owned_key_predicate is None):
        raise ValueError("provide exactly one explicit owned-key prefix or predicate")
    if owned_prefix is not None:
        if not owned_prefix:
            raise ValueError("owned-key prefix must be non-empty")

        def prefix_predicate(key: str) -> bool:
            return key.startswith(owned_prefix)

        predicate: Callable[[str], bool] = prefix_predicate
    else:
        assert owned_key_predicate is not None
        predicate = owned_key_predicate

    indexed = parse_verified_index(
        index_path, values_dir, expected_sha256=expected_sha256
    )
    owned = [entry for entry in indexed if predicate(entry.key)]
    if not owned:
        raise ValueError("ownership policy matched no rescued KV keys")
    source_entries = sorted(
        ((entry.key, entry.value_path.read_bytes()) for entry in owned), key=lambda item: item[0]
    )
    source_count, source_digest = _digest_entries(source_entries)
    current_target = _target_entries(connection, scope)
    target_count, target_digest = _digest_entries(current_target)
    receipt_matches = _receipt_matches(
        connection,
        index_sha256=expected_sha256,
        source_count=source_count,
        source_digest=source_digest,
        target_count=target_count,
        target_digest=target_digest,
    )
    if (target_count, target_digest) == (source_count, source_digest) and receipt_matches:
        _verify_owned_subset(source_entries, current_target)
        with storage._transaction(connection):
            _record_subset_receipt(
                connection,
                scope=scope,
                index_sha256=expected_sha256,
                source_entries=source_entries,
            )
        return KVImportResult(
            "no-op", len(indexed), 2, source_count, source_digest, target_digest
        )
    if receipt_matches and target_count >= source_count:
        _verify_owned_subset(source_entries, current_target)
        with storage._transaction(connection):
            _record_subset_receipt(
                connection,
                scope=scope,
                index_sha256=expected_sha256,
                source_entries=source_entries,
            )
        return KVImportResult(
            "preserved-operational-state",
            len(indexed),
            2,
            source_count,
            source_digest,
            target_digest,
        )
    if target_count:
        raise RuntimeError("refusing to overwrite non-matching imported KV state")
    if receipt_matches:
        raise RuntimeError("trusted KV import receipt exists but target rows are missing")

    etags = {entry.key: entry.etag for entry in owned}
    transaction = storage._transaction(connection)
    with transaction:
        with connection.cursor() as cursor:
            cursor.executemany(
                f"""
                INSERT INTO {storage.SCHEMA}.dedup_kv (scope, key, value, source_etag)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (scope, key) DO NOTHING
                """,
                [(scope, key, value, etags[key]) for key, value in source_entries],
            )
        verified_target = _target_entries(connection, scope)
        verified_count, verified_digest = _digest_entries(verified_target)
        if (verified_count, verified_digest) != (source_count, source_digest):
            raise ValueError("KV target verification failed")
        with connection.cursor() as cursor:
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
                    "kv_namespace",
                    scope,
                    expected_sha256,
                    source_count,
                    verified_count,
                    source_digest,
                    verified_digest,
                    json.dumps(
                        {"indexed_count": len(indexed), "owned_count": source_count},
                        separators=(",", ":"),
                    ),
                ),
            )
        _record_subset_receipt(
            connection,
            scope=scope,
            index_sha256=expected_sha256,
            source_entries=source_entries,
        )
    return KVImportResult(
        "imported", len(indexed), 2, source_count, source_digest, verified_digest
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn-file", type=Path, required=True)
    ownership = parser.add_mutually_exclusive_group(required=True)
    ownership.add_argument("--owned-prefix")
    ownership.add_argument("--owned-key-sha256", action="append")
    args = parser.parse_args(argv)
    dsn = args.dsn_file.read_text(encoding="utf-8").strip()
    if not dsn:
        parser.error("--dsn-file is empty")
    connection = storage.connect(dsn)
    try:
        if args.owned_key_sha256:
            approved = frozenset(str(value).lower() for value in args.owned_key_sha256)
            if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in approved):
                parser.error("--owned-key-sha256 values must be lowercase SHA-256 digests")

            def hash_predicate(key: str) -> bool:
                return hashlib.sha256(key.encode("utf-8")).hexdigest() in approved

            result = import_namespace(connection, owned_key_predicate=hash_predicate)
        else:
            result = import_namespace(connection, owned_prefix=args.owned_prefix)
    finally:
        connection.close()
    # Keys and values are intentionally absent from this receipt-only output.
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
