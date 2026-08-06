from __future__ import annotations

from pathlib import Path

import app


def test_systemd_credential_directory_precedes_root_source(tmp_path: Path, monkeypatch) -> None:
    broker = tmp_path / "broker"
    broker.mkdir()
    (broker / "command-key").write_text("broker-value\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(broker))
    monkeypatch.delenv("COMMAND_KEY", raising=False)
    assert app._credential("command-key", "COMMAND_KEY") == "broker-value"


def test_environment_precedes_systemd_credential(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "command-key").write_text("broker-value\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("COMMAND_KEY", "test-value")
    assert app._credential("command-key", "COMMAND_KEY") == "test-value"
