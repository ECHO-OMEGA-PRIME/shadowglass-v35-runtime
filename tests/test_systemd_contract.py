from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_service_executes_auditor_attested_read_only_release() -> None:
    unit = (ROOT / "ops" / "shadowglass-v7-command.service").read_text()
    assert "ProtectHome=true" in unit
    assert "WorkingDirectory=/opt/shadowglass-v7-command" in unit
    assert "BindReadOnlyPaths=/home/forge/shadowglass-v7-command/current:/opt/shadowglass-v7-command:rbind" in unit
    assert "ExecStart=/opt/shadowglass-v7-command/.venv/bin/python -m uvicorn app:app" in unit
    assert "InaccessiblePaths=/etc/echo/credentials/shadowglass-v7-command" in unit
    assert unit.count("LoadCredential=") == 8
    assert "--host 127.0.0.1 --port 8287" in unit


def test_scheduler_has_same_credential_boundary() -> None:
    unit = (ROOT / "ops" / "shadowglass-v7-command-scheduler.service").read_text()
    assert "ProtectHome=true" in unit
    assert "WorkingDirectory=/opt/shadowglass-v7-command" in unit
    assert "BindReadOnlyPaths=/home/forge/shadowglass-v7-command/current:/opt/shadowglass-v7-command:rbind" in unit
    assert "InaccessiblePaths=/etc/echo/credentials/shadowglass-v7-command" in unit
    assert unit.count("LoadCredential=") == 8
