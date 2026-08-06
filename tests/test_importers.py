from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

import import_d1
import import_kv


def _create_d1(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        for table, columns in import_d1.SOURCE_TABLE_COLUMNS.items():
            definitions = []
            for column in columns:
                sql_type = "INTEGER" if column in {"id", "is_active"} else "TEXT"
                definitions.append(f'"{column}" {sql_type}')
            connection.execute(f'CREATE TABLE "{table}" ({", ".join(definitions)})')
        connection.commit()
    finally:
        connection.close()


def test_d1_opens_only_after_hash_and_integrity_verification(tmp_path: Path) -> None:
    rescue = tmp_path / "shadowglass-scraper.sqlite3"
    _create_d1(rescue)
    expected = import_d1.sha256_file(rescue)
    connection = import_d1.open_verified_d1(rescue, expected_sha256=expected)
    connection.close()
    with rescue.open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(ValueError, match="SHA256"):
        import_d1.open_verified_d1(rescue, expected_sha256=expected)


def test_d1_source_projection_supports_subset_identity_checks(tmp_path: Path) -> None:
    rescue = tmp_path / "shadowglass-scraper.sqlite3"
    _create_d1(rescue)
    with sqlite3.connect(rescue) as connection:
        connection.execute(
            'INSERT INTO "counties" '
            '("id", "name", "state", "base_url", "is_active", '
            '"total_instruments", "last_scraped_at", "created_at", "platform") '
            "VALUES (1, 'Test', 'TX', 'https://example.test/', 0, 0, NULL, NULL, NULL)"
        )
    with sqlite3.connect(rescue) as connection:
        assert list(import_d1._source_rows(connection, "counties", ("id",))) == [(1,)]
        projected = list(
            import_d1._source_rows(
                connection,
                "counties",
                import_d1.TABLE_COLUMNS["counties"],
            )
        )
    assert projected == [(1, "Test", "TX", "https://example.test/", None, 0, None)]


def test_d1_import_is_noop_when_receipt_and_target_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = import_d1.Fingerprint(18, "a" * 64)
    monkeypatch.setattr(import_d1, "source_fingerprint", lambda *args: fingerprint)
    monkeypatch.setattr(import_d1, "_target_fingerprint", lambda *args: fingerprint)
    monkeypatch.setattr(import_d1, "_matching_receipt", lambda *args, **kwargs: True)
    monkeypatch.setattr(import_d1, "verify_imported_subset", lambda *args, **kwargs: fingerprint)
    result = import_d1.import_table(
        object(), object(), table="counties", source_sha256="b" * 64
    )
    assert result.status == "no-op"
    assert result.source_count == result.target_count == 18


def test_d1_redeploy_preserves_newer_operational_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = import_d1.Fingerprint(18, "a" * 64)
    operational = import_d1.Fingerprint(19, "c" * 64)
    monkeypatch.setattr(import_d1, "source_fingerprint", lambda *args: source)
    monkeypatch.setattr(import_d1, "_target_fingerprint", lambda *args: operational)
    monkeypatch.setattr(import_d1, "_matching_receipt", lambda *args, **kwargs: True)
    monkeypatch.setattr(import_d1, "verify_imported_subset", lambda *args, **kwargs: source)
    result = import_d1.import_table(
        object(), object(), table="counties", source_sha256="b" * 64
    )
    assert result.status == "preserved-operational-state"
    assert result.target_count == 19


def test_d1_redeploy_blocks_missing_or_changed_rescued_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = import_d1.Fingerprint(18, "a" * 64)
    operational = import_d1.Fingerprint(19, "c" * 64)
    monkeypatch.setattr(import_d1, "source_fingerprint", lambda *args: source)
    monkeypatch.setattr(import_d1, "_target_fingerprint", lambda *args: operational)
    monkeypatch.setattr(import_d1, "_matching_receipt", lambda *args, **kwargs: True)

    def reject(*args: object, **kwargs: object) -> object:
        raise RuntimeError("rescued imported subset changed or is missing")

    monkeypatch.setattr(import_d1, "verify_imported_subset", reject)
    with pytest.raises(RuntimeError, match="rescued imported subset"):
        import_d1.import_table(
            object(), object(), table="counties", source_sha256="b" * 64
        )


def _create_kv_rescue(tmp_path: Path) -> tuple[Path, Path, str]:
    values = tmp_path / "values"
    values.mkdir()
    (values / "one.bin").write_bytes(b"first")
    (values / "two.bin").write_bytes(b"second")
    document = {
        "entries": [
            {
                "key": "sgv35:first",
                "path": "one.bin",
                "sha256": hashlib.sha256(b"first").hexdigest(),
            },
            {
                "key": "shared:second",
                "path": "two.bin",
                "sha256": hashlib.sha256(b"second").hexdigest(),
            },
        ]
    }
    index = tmp_path / "index.json"
    index.write_text(json.dumps(document), encoding="utf-8")
    return index, values, import_kv.sha256_file(index)


def _test_value_hashes() -> frozenset[str]:
    return frozenset(hashlib.sha256(value).hexdigest() for value in (b"first", b"second"))


def test_kv_verifies_exactly_two_indexed_value_blobs(tmp_path: Path) -> None:
    index, values, expected = _create_kv_rescue(tmp_path)
    entries = import_kv.parse_verified_index(
        index,
        values,
        expected_sha256=expected,
        expected_value_sha256=_test_value_hashes(),
    )
    assert len(entries) == 2
    (values / "unexpected.bin").write_bytes(b"extra")
    with pytest.raises(ValueError, match="exactly two"):
        import_kv.parse_verified_index(
            index,
            values,
            expected_sha256=expected,
            expected_value_sha256=_test_value_hashes(),
        )


def test_kv_accepts_verified_rescue_jsonl_shape(tmp_path: Path) -> None:
    values = tmp_path / "values"
    values.mkdir()
    (values / "aaaaaaaaaaaaaaaa.bin").write_bytes(b"first")
    (values / "bbbbbbbbbbbbbbbb.bin").write_bytes(b"second")
    index = tmp_path / "keys.jsonl"
    index.write_text(
        "\n".join(
            (
                json.dumps(
                    {"name": "sgv35:first", "hash": "aaaaaaaaaaaaaaaa", "expiration": 0, "metadata": None}
                ),
                json.dumps(
                    {"name": "shared:second", "hash": "bbbbbbbbbbbbbbbb", "expiration": 0, "metadata": None}
                ),
            )
        ),
        encoding="utf-8",
    )
    entries = import_kv.parse_verified_index(
        index,
        values,
        expected_sha256=import_kv.sha256_file(index),
        expected_value_sha256=_test_value_hashes(),
    )
    assert len(entries) == 2


def test_kv_import_requires_explicit_ownership_filter() -> None:
    with pytest.raises(ValueError, match="owned-key"):
        import_kv.import_namespace(object())


def test_kv_import_is_noop_without_exposing_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    index, values, expected = _create_kv_rescue(tmp_path)
    entries = import_kv.parse_verified_index(
        index,
        values,
        expected_sha256=expected,
        expected_value_sha256=_test_value_hashes(),
    )
    owned = [(entries[0].key, entries[0].value_path.read_bytes())]
    monkeypatch.setattr(import_kv, "parse_verified_index", lambda *args, **kwargs: entries)
    monkeypatch.setattr(import_kv, "_target_entries", lambda *args, **kwargs: owned)
    monkeypatch.setattr(import_kv, "_receipt_matches", lambda *args, **kwargs: True)
    monkeypatch.setattr(import_kv, "_record_subset_receipt", lambda *args, **kwargs: None)
    result = import_kv.import_namespace(
        object(),
        index_path=index,
        values_dir=values,
        expected_sha256=expected,
        owned_prefix="sgv35:",
    )
    assert result.status == "no-op" and result.owned_count == 1
    captured = capsys.readouterr()
    assert "sgv35:first" not in captured.out + captured.err


def test_kv_redeploy_preserves_newer_operational_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index, values, expected = _create_kv_rescue(tmp_path)
    entries = import_kv.parse_verified_index(
        index,
        values,
        expected_sha256=expected,
        expected_value_sha256=_test_value_hashes(),
    )
    operational = [
        (entries[0].key, entries[0].value_path.read_bytes()),
        ("runtime:new", b"newer"),
    ]
    monkeypatch.setattr(import_kv, "parse_verified_index", lambda *args, **kwargs: entries)
    monkeypatch.setattr(import_kv, "_target_entries", lambda *args, **kwargs: operational)
    monkeypatch.setattr(import_kv, "_receipt_matches", lambda *args, **kwargs: True)
    monkeypatch.setattr(import_kv, "_record_subset_receipt", lambda *args, **kwargs: None)
    result = import_kv.import_namespace(
        object(),
        index_path=index,
        values_dir=values,
        expected_sha256=expected,
        owned_prefix="sgv35:",
    )
    assert result.status == "preserved-operational-state"
    assert result.target_digest != result.source_digest


def test_kv_redeploy_rejects_missing_or_changed_owned_value() -> None:
    source = [("owned:key", b"rescued")]
    with pytest.raises(RuntimeError, match="KV key/value subset"):
        import_kv._verify_owned_subset(source, [("owned:key", b"changed"), ("runtime:new", b"new")])
    with pytest.raises(RuntimeError, match="KV key/value subset"):
        import_kv._verify_owned_subset(source, [("runtime:new", b"new")])
