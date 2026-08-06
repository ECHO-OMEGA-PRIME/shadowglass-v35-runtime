from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

import relay


def configure(monkeypatch: Any, tmp_path: Path, origin: str, allowed: str) -> None:
    (tmp_path / "relay_url").write_text(origin, encoding="utf-8")
    (tmp_path / "relay_allowed_hosts").write_text(allowed, encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))


def test_exact_origin_and_dns_pin(monkeypatch: Any, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path, "https://relay.example", "relay.example")
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: frozenset({"203.0.113.10"}))
    client = relay.RelayClient()
    assert client.origin == "https://relay.example"
    assert client.addresses == frozenset({"203.0.113.10"})


@pytest.mark.parametrize(
    "origin",
    (
        "file:///etc/passwd",
        "http://user:pass@relay.example",
        "https://relay.example/path",
        "https://other.example",
        "javascript:alert(1)",
    ),
)
def test_unsafe_origins_fail_closed(monkeypatch: Any, tmp_path: Path, origin: str) -> None:
    configure(monkeypatch, tmp_path, origin, "relay.example")
    with pytest.raises(relay.RelayConfigurationError):
        relay.RelayClient()


def test_dns_change_fails_before_request(monkeypatch: Any, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path, "https://relay.example", "relay.example")
    answers = iter((frozenset({"203.0.113.10"}), frozenset({"203.0.113.11"})))
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: next(answers))
    client = relay.RelayClient()
    with pytest.raises(relay.RelayRequestError, match="DNS changed"):
        client.call("browser", {"url": "https://county.example", "wait_for": "table"})


def test_call_rejects_unknown_action(monkeypatch: Any, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path, "https://relay.example", "relay.example")
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: frozenset({"203.0.113.10"}))
    with pytest.raises(relay.RelayRequestError, match="unsupported"):
        relay.RelayClient().call("arbitrary", {})


def test_request_connects_to_the_prevalidated_address(monkeypatch: Any, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path, "http://relay.example", "relay.example")
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: frozenset({"203.0.113.10"}))
    connections: list[tuple[tuple[str, int], float]] = []

    def create_connection(target: tuple[str, int], timeout: float) -> object:
        connections.append((target, timeout))
        return object()

    class FakeResponse:
        status = 200

        def read(self, _: int) -> bytes:
            return b"{}"

    class FakeConnection:
        sock: object | None = None

        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port) == ("relay.example", 80)
            assert timeout == 20.0

        def request(self, method: str, path: str, **_: Any) -> None:
            assert (method, path) == ("GET", "/health")

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(relay.socket, "create_connection", create_connection)
    monkeypatch.setattr(relay.http.client, "HTTPConnection", FakeConnection)
    assert relay.RelayClient().probe() == {}
    assert connections == [(('203.0.113.10', 80), 20.0)]


def test_browse_reads_validated_master_artifact(monkeypatch: Any, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path, "http://127.0.0.1:8088", "127.0.0.1")
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: frozenset({"127.0.0.1"}))
    monkeypatch.setattr(
        relay.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    class ObjectResponse(io.BytesIO):
        def release_conn(self) -> None:
            pass

    class FakeMinio:
        def get_object(self, bucket: str, key: str) -> ObjectResponse:
            assert bucket == "shadowglass"
            assert key == "2026/08/03/0123456789abcdef.html"
            return ObjectResponse(b"<html><table></table></html>")

    client = relay.RelayClient()
    monkeypatch.setattr(
        client,
        "call",
        lambda action, payload: {
            "ok": True,
            "validated": True,
            "run_id": "0123456789abcdef",
            "artifacts": {"html_key": "2026/08/03/0123456789abcdef.html"},
        },
    )
    monkeypatch.setattr(relay, "configured_client", lambda: (FakeMinio(), "unused"))
    result = client.browse("https://county.example/results", "table")
    assert result == {"html": "<html><table></table></html>"}


def test_browse_rejects_untrusted_artifact_key(monkeypatch: Any, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path, "http://127.0.0.1:8088", "127.0.0.1")
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: frozenset({"127.0.0.1"}))
    monkeypatch.setattr(
        relay.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    client = relay.RelayClient()
    monkeypatch.setattr(
        client,
        "call",
        lambda action, payload: {
            "ok": True,
            "validated": True,
            "run_id": "0123456789abcdef",
            "artifacts": {"html_key": "../../private.html"},
        },
    )
    with pytest.raises(relay.RelayRequestError, match="valid HTML artifact"):
        client.browse("https://county.example/results", "table")


def test_browse_uses_pinned_direct_body_for_validated_l0(
    monkeypatch: Any, tmp_path: Path
) -> None:
    configure(monkeypatch, tmp_path, "http://127.0.0.1:8088", "127.0.0.1")
    monkeypatch.setattr(relay, "_pin_addresses", lambda _: frozenset({"127.0.0.1"}))
    monkeypatch.setattr(
        relay.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(
        relay,
        "_direct_public_get",
        lambda url, addresses, timeout_seconds: "<html>validated L0</html>",
    )
    client = relay.RelayClient()
    monkeypatch.setattr(
        client,
        "call",
        lambda action, payload: {
            "ok": True,
            "validated": True,
            "rung": "L0",
            "run_id": "0123456789abcdef",
            "artifacts": {"html_key": None},
        },
    )
    assert client.browse("https://county.example/results", "table") == {
        "html": "<html>validated L0</html>"
    }
