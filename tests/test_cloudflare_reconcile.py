from __future__ import annotations

import base64
import io
import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

import cloudflare_reconcile as reconcile


QUEUE_ID = "queue_12345678"
LEGACY_FIXTURE = Path(__file__).parent / "fixtures" / "quarantine_worker.js"
CONSUMER = {
    "consumer_id": "consumer_12345678",
    "script_name": reconcile.WORKER,
    "type": "worker",
}


def legacy_worker_bytes() -> bytes:
    return LEGACY_FIXTURE.read_bytes()


@pytest.fixture(autouse=True)
def synthetic_legacy_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reconcile,
        "LEGACY_MODULE_SHA256",
        reconcile.hashlib.sha256(legacy_worker_bytes()).hexdigest(),
    )


def state(
    *,
    consumer: bool = True,
    cron: bool = True,
    subdomain: bool = True,
    legacy: bool = True,
    quarantined: bool = False,
) -> dict[str, Any]:
    consumers = [CONSUMER] if consumer else []
    return {
        "queue": {"queue_name": reconcile.QUEUE_NAME, "queue_id": QUEUE_ID},
        "queue_id": QUEUE_ID,
        "consumers": consumers,
        "matching_consumers": consumers,
        "metrics": {
            "backlog_count": 0,
            "backlog_bytes": 0,
            "oldest_message_timestamp_ms": 0,
        },
        "schedules": [{"cron": "0 * * * *"}] if cron else [],
        "domains": [],
        "subdomain": {"enabled": subdomain, "previews_enabled": False},
        "content": {
            "legacy": legacy,
            "quarantined": quarantined,
            "part_count": 1,
            "settings_match_backup": True,
        },
    }


def write_backup(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "worker": reconcile.WORKER,
                "queue_name": reconcile.QUEUE_NAME,
                "queue_id": QUEUE_ID,
                "matching_consumers": [CONSUMER],
                "schedules": [{"cron": "0 * * * *"}],
                "subdomain": {"enabled": True, "previews_enabled": False},
                "domains": [],
            }
        ),
        encoding="utf-8",
    )


def test_schedule_restore_payload_uses_api_objects() -> None:
    assert reconcile._schedule_payload([{"cron": "0 * * * *"}]) == [
        {"cron": "0 * * * *"}
    ]


def test_disable_is_idempotent_after_verified_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    monkeypatch.setattr(
        reconcile,
        "_state",
        lambda _: state(
            consumer=False,
            cron=True,
            subdomain=False,
            legacy=False,
            quarantined=True,
        ),
    )
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda *args, **kwargs: pytest.fail("idempotent disable must not mutate Cloudflare"),
    )
    monkeypatch.setattr(reconcile, "_load_content_backup", lambda: None)
    reconcile.disable("opaque")
    assert '"action": "already_disabled"' in capsys.readouterr().out


def test_disable_recovers_partial_prior_attempt_then_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    states = iter(
        [
            state(
                consumer=True,
                cron=True,
                subdomain=False,
                legacy=False,
                quarantined=True,
            ),
            state(),
            state(
                consumer=False,
                cron=True,
                subdomain=False,
                legacy=False,
                quarantined=True,
            ),
        ]
    )
    monkeypatch.setattr(reconcile, "_state", lambda _: next(states))
    restored: list[str] = []
    monkeypatch.setattr(reconcile, "restore", lambda key: restored.append(key))
    monkeypatch.setattr(reconcile, "_save_backup", lambda _: None)
    monkeypatch.setattr(reconcile, "_save_content_backup", lambda _: None)
    monkeypatch.setattr(reconcile, "_quarantine_content", lambda _: None)
    monkeypatch.setattr(reconcile, "_wait_for_stable_empty", lambda *args: None)
    calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda method, path, key, payload=None: calls.append((method, path, payload)),
    )
    reconcile.disable("opaque")
    assert restored == ["opaque"]
    assert [method for method, _, _ in calls] == ["DELETE", "DELETE"]


def test_partial_cutover_recovery_rejects_unrelated_queue_consumer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    changed = state(consumer=True, cron=False, subdomain=False)
    changed["consumers"] = [
        *changed["consumers"],
        {"consumer_id": "unrelated_12345678", "script_name": "other-worker"},
    ]
    assert not reconcile._recognized_partial_cutover(changed)


def test_restore_does_not_duplicate_existing_consumer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    write_content_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "a" * 64)
    monkeypatch.setattr(reconcile, "_state", lambda _: state())
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda method, path, key, payload=None: calls.append((method, payload)),
    )
    monkeypatch.setattr(reconcile, "_restore_content", lambda _: None)
    reconcile.restore("opaque")
    assert calls == []


def test_restore_rejects_missing_schedule_without_quota_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    monkeypatch.setattr(reconcile, "_state", lambda _: state(cron=False))
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda method, path, key, payload=None: calls.append((method, payload)),
    )
    with pytest.raises(RuntimeError, match="schedule drift"):
        reconcile.restore("opaque")
    assert calls == []


def test_restore_requires_content_backup_before_consumer_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    monkeypatch.setattr(
        reconcile,
        "CONTENT_BACKUP_PATH",
        tmp_path / "missing-content.multipart",
    )
    monkeypatch.setattr(
        reconcile,
        "CONTENT_BACKUP_META_PATH",
        tmp_path / "missing-content.json",
    )
    monkeypatch.setattr(
        reconcile,
        "_state",
        lambda _: state(
            consumer=False,
            subdomain=False,
            legacy=False,
            quarantined=True,
        ),
    )
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda method, path, key, payload=None: calls.append((method, path)),
    )
    with pytest.raises(RuntimeError, match="content recovery backup is missing"):
        reconcile.restore("opaque")
    assert calls == []


def test_cloudflare_http_error_reports_safe_api_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = urllib.error.HTTPError(
        "https://api.cloudflare.test/redacted",
        400,
        "Bad Request",
        {},
        io.BytesIO(
            json.dumps(
                {"errors": [{"code": 1000, "message": "invalid schedule payload"}]}
            ).encode("utf-8")
        ),
    )

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(reconcile.urllib.request, "urlopen", fail)
    with pytest.raises(
        RuntimeError,
        match=r"Cloudflare HTTP 400 \(1000: invalid schedule payload\)",
    ):
        reconcile._cf("PUT", "/redacted", "opaque", [])


def test_settings_digest_ignores_only_server_owned_version_annotations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = {
        "annotations": {
            "workers/triggered_by": "deployment",
            "workers/tag": "migration-baseline",
        },
        "compatibility_date": "2026-03-01",
        "bindings": [{"name": "DB", "type": "d1", "database_id": "db-one"}],
    }
    changed_annotation = {
        **baseline,
        "annotations": {
            "workers/triggered_by": "upload",
            "workers/tag": "migration-baseline",
        },
    }
    changed_user_annotation = {
        **changed_annotation,
        "annotations": {
            "workers/triggered_by": "upload",
            "workers/tag": "unexpected-tag-drift",
        },
    }
    changed_binding = {
        **changed_annotation,
        "bindings": [{"name": "DB", "type": "d1", "database_id": "db-two"}],
    }
    values = iter(
        (baseline, changed_annotation, changed_user_annotation, changed_binding)
    )
    monkeypatch.setattr(reconcile, "_cf", lambda *args, **kwargs: next(values))
    original = reconcile._settings_sha256("opaque")
    assert reconcile._settings_sha256("opaque") == original
    assert reconcile._settings_sha256("opaque") != original
    assert reconcile._settings_sha256("opaque") != original


def legacy_content() -> tuple[bytes, str]:
    worker = legacy_worker_bytes()
    assert reconcile.hashlib.sha256(worker).hexdigest() == reconcile.LEGACY_MODULE_SHA256
    return reconcile._multipart_upload([("worker.js", worker)])


def write_content_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[bytes, str]:
    raw, content_type = legacy_content()
    content = tmp_path / "content.multipart"
    metadata = tmp_path / "content.json"
    content.write_bytes(raw)
    metadata.write_text(
        json.dumps(
            {
                "worker": reconcile.WORKER,
                "content_type": content_type,
                "sha256": reconcile.hashlib.sha256(raw).hexdigest(),
                "module_sha256": reconcile.LEGACY_MODULE_SHA256,
                "main_module": "worker.js",
                "active_version_id": "68214043-218d-46d2-823c-8e944ab89643",
                "settings_sha256": "a" * 64,
                "settings_digest_version": 2,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(reconcile, "CONTENT_BACKUP_PATH", content)
    monkeypatch.setattr(reconcile, "CONTENT_BACKUP_META_PATH", metadata)
    return raw, content_type


def test_content_backup_is_exact_non_overwriting_and_restoreable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = legacy_worker_bytes()
    content = tmp_path / "content.multipart"
    metadata = tmp_path / "content.json"
    monkeypatch.setattr(reconcile, "CONTENT_BACKUP_PATH", content)
    monkeypatch.setattr(reconcile, "CONTENT_BACKUP_META_PATH", metadata)
    monkeypatch.setattr(
        reconcile,
        "_active_version_content",
        lambda _: {
            "legacy": True,
            "quarantined": False,
            "entry_point": "worker.js",
            "active_version_id": "68214043-218d-46d2-823c-8e944ab89643",
            "module_payloads": {"worker.js": worker},
        },
    )
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "a" * 64)
    monkeypatch.setattr(
        reconcile,
        "_content_state",
        lambda _: {"legacy": True, "quarantined": False},
    )

    reconcile._save_content_backup("opaque")
    original_content = content.read_bytes()
    original_metadata = metadata.read_bytes()
    reconcile._save_content_backup("opaque")

    assert content.read_bytes() == original_content
    assert metadata.read_bytes() == original_metadata
    assert reconcile._content_identity_from_parts(
        reconcile._multipart_parts(
            content.read_bytes(),
            json.loads(metadata.read_text(encoding="utf-8"))["content_type"],
        )
    )["legacy"]
    assert reconcile._content_backup_restoreable()


def test_quarantine_upload_preserves_legacy_module_and_proves_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_content_backup(tmp_path, monkeypatch)
    states = iter(
        [
            {"legacy": True, "quarantined": False},
            {
                "legacy": False,
                "quarantined": True,
                "settings_match_backup": True,
            },
        ]
    )
    monkeypatch.setattr(reconcile, "_content_state", lambda _: next(states))
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "a" * 64)
    uploaded: list[tuple[bytes, str]] = []
    monkeypatch.setattr(
        reconcile,
        "_put_content",
        lambda key, raw, content_type: uploaded.append((raw, content_type)),
    )

    reconcile._quarantine_content("opaque")

    assert len(uploaded) == 1
    parts = reconcile._multipart_parts(*uploaded[0])
    identity = reconcile._content_identity_from_parts(parts)
    assert identity["quarantined"]
    original = next(part for part in parts if part["filename"] == "original.js")
    assert original["sha256"] == reconcile.LEGACY_MODULE_SHA256


def test_restore_replays_exact_module_with_explicit_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_content_backup(tmp_path, monkeypatch)
    states = iter(
        [
            {
                "legacy": False,
                "quarantined": True,
                "settings_match_backup": True,
            },
            {
                "legacy": True,
                "quarantined": False,
                "settings_match_backup": True,
            },
        ]
    )
    monkeypatch.setattr(reconcile, "_content_state", lambda _: next(states))
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "a" * 64)
    uploaded: list[tuple[bytes, str]] = []
    monkeypatch.setattr(
        reconcile,
        "_put_content",
        lambda key, raw, content_type: uploaded.append((raw, content_type)),
    )

    reconcile._restore_content("opaque")

    assert len(uploaded) == 1
    restored = reconcile._content_identity_from_parts(
        reconcile._multipart_parts(*uploaded[0])
    )
    assert restored["legacy"]


def test_restore_content_rejects_legacy_bytes_with_settings_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_content_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(
        reconcile,
        "_content_state",
        lambda _: {
            "legacy": True,
            "quarantined": False,
            "settings_match_backup": False,
        },
    )
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "b" * 64)
    with pytest.raises(RuntimeError, match="settings drift"):
        reconcile._restore_content("opaque")


def test_quarantine_identity_rejects_swapped_main_module() -> None:
    worker = legacy_worker_bytes()
    raw, content_type = reconcile._multipart_upload(
        [
            ("original.js", worker),
            ("quarantine.js", reconcile.QUARANTINE_SOURCE_PATH.read_bytes()),
        ]
    )
    identity = reconcile._content_identity_from_parts(
        reconcile._multipart_parts(raw, content_type)
    )
    assert identity["entry_point"] == "original.js"
    assert not identity["legacy"]
    assert not identity["quarantined"]


def test_quarantine_identity_rejects_name_filename_inversion() -> None:
    worker = legacy_worker_bytes()
    quarantine = reconcile.QUARANTINE_SOURCE_PATH.read_bytes()
    parts = [
        {
            "name": "quarantine.js",
            "filename": "original.js",
            "payload": worker,
            "sha256": reconcile.hashlib.sha256(worker).hexdigest(),
        },
        {
            "name": "original.js",
            "filename": "quarantine.js",
            "payload": quarantine,
            "sha256": reconcile.hashlib.sha256(quarantine).hexdigest(),
        },
        {
            "name": "metadata",
            "filename": "",
            "payload": b'{"main_module":"quarantine.js"}',
            "sha256": reconcile.hashlib.sha256(
                b'{"main_module":"quarantine.js"}'
            ).hexdigest(),
        },
    ]
    with pytest.raises(RuntimeError, match="name/filename identity mismatch"):
        reconcile._content_identity_from_parts(parts)


def test_live_identity_hashes_modules_from_exact_active_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = legacy_worker_bytes()
    version_id = "68214043-218d-46d2-823c-8e944ab89643"
    monkeypatch.setattr(reconcile, "_WORKER_ID", None)
    monkeypatch.setattr(reconcile, "_CONTENT_BY_VERSION", {})
    monkeypatch.setattr(
        reconcile, "CONTENT_BACKUP_PATH", tmp_path / "missing-content.multipart"
    )
    monkeypatch.setattr(
        reconcile, "CONTENT_BACKUP_META_PATH", tmp_path / "missing-content.json"
    )
    calls: list[str] = []

    def request(method: str, path: str, key: str, payload: Any = None) -> Any:
        calls.append(path)
        if path.endswith("/deployments"):
            return {
                "deployments": [
                    {
                        "versions": [
                            {"version_id": version_id, "percentage": 100}
                        ]
                    }
                ]
            }
        if "/scripts-search?" in path:
            return [
                {
                    "id": "7b0aad69a8f84e29ad512d1d06dfd992",
                    "script_name": reconcile.WORKER,
                }
            ]
        if f"/versions/{version_id}?include=modules" in path:
            return {
                "id": version_id,
                "main_module": "worker.js",
                "modules": [
                    {
                        "name": "worker.js",
                        "content_type": "application/javascript+module",
                        "content_base64": base64.b64encode(worker).decode("ascii"),
                    }
                ],
            }
        raise AssertionError(path)

    monkeypatch.setattr(reconcile, "_cf", request)
    identity = reconcile._content_state("opaque")
    assert identity["legacy"]
    assert identity["active_version_id"] == version_id
    assert not any("/content/v2" in path for path in calls)


def test_worker_identity_rejects_sole_partial_name_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reconcile, "_WORKER_ID", None)
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda *args, **kwargs: [
            {
                "id": "7b0aad69a8f84e29ad512d1d06dfd992",
                "script_name": f"{reconcile.WORKER}-lookalike",
            }
        ],
    )
    with pytest.raises(RuntimeError, match="immutable identity is ambiguous"):
        reconcile._worker_id("opaque")


def test_quarantine_wrapper_exposes_only_inert_fetch_and_schedule() -> None:
    source = reconcile.QUARANTINE_SOURCE_PATH.read_text(encoding="utf-8")
    assert 'import legacy from "./original.js"' in source
    assert "return legacy.queue(batch, env, ctx);" in source
    assert "status: 410" in source
    scheduled = source[source.index("async scheduled()") :]
    assert "legacy.scheduled" not in scheduled


def test_existing_backup_must_match_queue_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    payload = json.loads(backup.read_text(encoding="utf-8"))
    payload["queue_id"] = "wrong_queue_1234"
    backup.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    with pytest.raises(RuntimeError, match="backup identity"):
        reconcile._save_backup(state())


def test_existing_backup_must_match_full_trigger_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    changed = state()
    changed["schedules"] = [{"cron": "15 * * * *"}]
    with pytest.raises(RuntimeError, match="cron contract"):
        reconcile._save_backup(changed)


def test_incomplete_backup_is_never_accepted_for_disabled_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    backup.write_text(
        json.dumps(
            {
                "worker": reconcile.WORKER,
                "queue_name": reconcile.QUEUE_NAME,
                "queue_id": QUEUE_ID,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    disabled = state(consumer=False, cron=False, subdomain=False)
    with pytest.raises(RuntimeError, match="one legacy consumer"):
        reconcile._save_backup(disabled)


@pytest.mark.parametrize(
    ("field", "value"),
    [("script_name", "unexpected-other-worker"), ("type", "http_pull")],
)
def test_restore_backup_requires_exact_legacy_worker_consumer_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    payload = json.loads(backup.read_text(encoding="utf-8"))
    payload["matching_consumers"][0][field] = value
    backup.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    with pytest.raises(RuntimeError, match="consumer identity"):
        reconcile._load_backup(QUEUE_ID)
    assert not reconcile._backup_restoreable(QUEUE_ID)


def test_restoreable_backup_allows_idempotent_redeploy_after_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    original = backup.read_bytes()
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    reconcile._save_backup(
        state(
            consumer=False,
            cron=True,
            subdomain=False,
            legacy=False,
            quarantined=True,
        )
    )
    assert backup.read_bytes() == original


@pytest.mark.parametrize(
    "metrics",
    [
        {},
        {"backlog_count": 0, "backlog_bytes": 0},
        {
            "backlog_count": "0",
            "backlog_bytes": 0,
            "oldest_message_timestamp_ms": 0,
        },
        {
            "backlog_count": 0,
            "backlog_bytes": -1,
            "oldest_message_timestamp_ms": 0,
        },
    ],
)
def test_metrics_are_required_exact_nonnegative_numbers(metrics: Any) -> None:
    with pytest.raises(RuntimeError, match="metric"):
        reconcile._metric_snapshot(metrics)


def test_disabled_state_requires_post_detach_queue_to_remain_empty() -> None:
    changed = state(consumer=False, cron=False, subdomain=False)
    changed["metrics"]["backlog_count"] = 1
    assert not reconcile._is_disabled(changed)


def test_disabled_state_requires_zero_total_consumers() -> None:
    changed = state(consumer=False, cron=False, subdomain=False)
    changed["consumers"] = [{"consumer_id": "unexpected", "script_name": "other-worker"}]
    assert not reconcile._is_disabled(changed)


def test_unrecognized_cron_drift_is_never_mutated_or_auto_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    changed = state()
    changed["schedules"] = [{"cron": "15 * * * *"}]
    monkeypatch.setattr(reconcile, "_state", lambda _: changed)
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda *args, **kwargs: pytest.fail("baseline drift must not mutate Cloudflare"),
    )
    with pytest.raises(RuntimeError, match="cron contract"):
        reconcile.disable("opaque")


def test_quiet_window_requires_sustained_zero_with_producers_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quiet = state(
        consumer=True,
        cron=True,
        subdomain=False,
        legacy=False,
        quarantined=True,
    )
    monkeypatch.setattr(reconcile, "_state", lambda _: quiet)
    monkeypatch.setattr(
        reconcile,
        "_cf",
        lambda *args, **kwargs: {
            "backlog_count": 0,
            "backlog_bytes": 0,
            "oldest_message_timestamp_ms": 0,
        },
    )
    samples = iter((0.0, 0.0, 0.0, 60.0, 60.0))
    monkeypatch.setattr(reconcile.time, "monotonic", lambda: next(samples))
    monkeypatch.setattr(reconcile.time, "sleep", lambda _: None)
    monkeypatch.setenv("SG_CF_QUIET_SECONDS", "60")
    reconcile._wait_for_stable_empty("opaque", QUEUE_ID)


def test_restore_never_reposts_consumer_after_ambiguous_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    write_content_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "a" * 64)
    disabled = state(
        consumer=False,
        cron=True,
        subdomain=False,
        legacy=False,
        quarantined=True,
    )
    restored_private = state(
        consumer=False,
        cron=True,
        subdomain=False,
        legacy=True,
        quarantined=False,
    )
    states = iter((disabled, restored_private, restored_private))
    monkeypatch.setattr(reconcile, "_state", lambda _: next(states))
    calls: list[tuple[str, str]] = []

    def request(method: str, path: str, key: str, payload: Any = None) -> None:
        calls.append((method, path))
        if method == "POST" and path.endswith("/consumers"):
            raise TimeoutError("ambiguous response")

    monkeypatch.setattr(reconcile, "_cf", request)
    monkeypatch.setattr(reconcile, "_restore_content", lambda _: None)
    samples = iter((0.0, 100.0))
    monkeypatch.setattr(reconcile.time, "monotonic", lambda: next(samples))
    with pytest.raises(RuntimeError, match="response remained ambiguous"):
        reconcile.restore("opaque")
    assert sum(method == "POST" and path.endswith("/consumers") for method, path in calls) == 1


def test_restore_verifies_content_before_creating_consumer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = tmp_path / "backup.json"
    write_backup(backup)
    monkeypatch.setattr(reconcile, "BACKUP_PATH", backup)
    write_content_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(reconcile, "_settings_sha256", lambda _: "a" * 64)
    disabled = state(
        consumer=False,
        subdomain=False,
        legacy=False,
        quarantined=True,
    )
    private_legacy = state(consumer=False, subdomain=False)
    private_with_consumer = state(consumer=True, subdomain=False)
    restored = state()
    states = iter(
        (
            disabled,
            private_legacy,
            private_with_consumer,
            private_with_consumer,
            restored,
        )
    )
    monkeypatch.setattr(reconcile, "_state", lambda _: next(states))
    order: list[str] = []
    monkeypatch.setattr(
        reconcile, "_restore_content", lambda _: order.append("content")
    )

    def request(method: str, path: str, key: str, payload: Any = None) -> None:
        if method == "POST" and path.endswith("/consumers"):
            order.append("consumer")
        elif method == "POST" and path.endswith("/subdomain"):
            order.append("subdomain")

    monkeypatch.setattr(reconcile, "_cf", request)
    reconcile.restore("opaque")
    assert order == ["content", "consumer", "subdomain"]
