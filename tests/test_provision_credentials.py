from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import provision_credentials as provision


def test_minio_configuration_uses_vault_when_legacy_dropin_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def environment(path: Path) -> dict[str, str]:
        if path == provision.MINIO_ENDPOINT_CONFIG:
            return {"MINIO_ENDPOINT": "http://minio.internal:9000"}
        return {}

    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(provision, "_systemd_environment", environment)
    monkeypatch.setattr(
        provision,
        "_vault_secret",
        lambda service, username, **_: calls.append((service, username))
        or "admin-secret",
    )
    assert provision._minio_configuration() == (
        "http://minio.internal:9000",
        provision.MINIO_ADMIN_USERNAME,
        "admin-secret",
    )
    assert calls == [(provision.MINIO_ADMIN_SERVICE, provision.MINIO_ADMIN_USERNAME)]


def test_minio_runtime_policy_is_output_bucket_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy: dict[str, Any] = {}
    calls: list[list[str]] = []

    def read_or_create(path: Path, factory: Any) -> str:
        return "runtime-access" if path.name == "minio-access-key" else "runtime-secret"

    def run_mc(arguments: list[str], **_: Any) -> None:
        calls.append(arguments)
        if arguments[:4] == ["admin", "policy", "create", "sgv35admin"]:
            policy.update(json.loads(Path(arguments[-1]).read_text(encoding="utf-8")))

    monkeypatch.setattr(provision, "_read_or_create", read_or_create)
    monkeypatch.setattr(provision, "_run_mc", run_mc)
    monkeypatch.setattr(provision, "_atomic_write", lambda *args, **kwargs: None)
    provision._provision_minio_consumer(
        tmp_path,
        endpoint="http://minio.invalid:9000",
        admin_access="admin-access",
        admin_secret="admin-secret",
    )
    serialized = json.dumps(policy, sort_keys=True)
    assert f"arn:aws:s3:::{provision.OUTPUT_BUCKET}" in serialized
    assert "s3:PutObject" in serialized
    archive_statements = [
        statement
        for statement in policy["Statement"]
        if "arn:aws:s3:::shadowglass/*" in statement["Resource"]
    ]
    assert archive_statements == [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::shadowglass/*"],
        }
    ]
    assert any(call[:3] == ["admin", "user", "add"] for call in calls)
    assert any(call[:3] == ["admin", "policy", "attach"] for call in calls)


def test_staging_cleanup_is_idempotent_when_bucket_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "credentials"
    directory.mkdir()
    calls: list[list[str]] = []

    def run(arguments: list[str], **_: Any) -> Any:
        calls.append(arguments)
        return type("Result", (), {"returncode": 1, "stdout": "0\n"})()

    monkeypatch.setattr(provision, "STAGING_DIRECTORY", directory)
    monkeypatch.setattr(provision.subprocess, "run", run)
    provision._staging_cleanup(
        directory,
        database="sgv35_stage_012345abcdef",
        bucket="shadowglass-v35-stage-012345abcdef",
        minio_endpoint="http://minio.invalid:9000",
        minio_access="admin-access",
        minio_secret="admin-secret",
    )
    assert not directory.exists()
    assert sum(call[:2] == ["mc", "--quiet"] for call in calls) == 7
    assert any("dropdb" in call for call in calls)
    assert any("dropuser" in call for call in calls)


def test_staging_minio_identity_is_scoped_to_disposable_bucket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy: dict[str, Any] = {}

    def run_mc(arguments: list[str], **_: Any) -> None:
        if arguments[:4] == ["admin", "policy", "create", "sgv35admin"]:
            policy.update(json.loads(Path(arguments[-1]).read_text(encoding="utf-8")))

    monkeypatch.setattr(provision, "_run_mc", run_mc)
    provision._provision_staging_minio(
        tmp_path,
        bucket="shadowglass-v35-stage-012345abcdef",
        endpoint="http://minio.invalid:9000",
        admin_access="admin-access",
        admin_secret="admin-secret",
    )
    serialized = json.dumps(policy, sort_keys=True)
    assert "shadowglass-v35-stage-012345abcdef" in serialized
    assert f'arn:aws:s3:::{provision.OUTPUT_BUCKET}"' not in serialized
    assert f'arn:aws:s3:::{provision.OUTPUT_BUCKET}/*' not in serialized
    assert (tmp_path / "minio-access-key").read_text(encoding="utf-8").startswith(
        "sgv35-stage-012345abcdef"
    )
