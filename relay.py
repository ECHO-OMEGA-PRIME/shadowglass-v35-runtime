"""Fixed-origin relay client with fail-closed SSRF and redirect controls."""

from __future__ import annotations

import ipaddress
import http.client
import json
import os
import re
import socket
import urllib.parse
import ssl
from pathlib import Path
from typing import Any

from object_store import configured_client


MAX_RESPONSE_BYTES = 2_000_000
FIXED_PATHS = {
    "browser": "/scrape",
    "probe": "/health",
}

MASTER_ARTIFACT_BUCKET = "shadowglass"
MASTER_ARTIFACT_KEY = re.compile(r"\A\d{4}/\d{2}/\d{2}/[0-9a-f]{16}\.html\Z")


class RelayConfigurationError(RuntimeError):
    """The relay is missing or violates its exact-origin policy."""


class RelayRequestError(RuntimeError):
    """The fixed-origin relay request failed safely."""


def _direct_public_get(
    target_url: str,
    addresses: frozenset[str],
    *,
    timeout_seconds: float,
) -> str:
    """Retrieve an L0 page only after ShadowGlass validated that exact URL."""

    parsed = urllib.parse.urlsplit(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        current = frozenset(
            answer[4][0]
            for answer in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
    except OSError as exc:
        raise RelayRequestError("browser target DNS revalidation failed") from exc
    if current != addresses:
        raise RelayRequestError("browser target DNS changed during operation")
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    last_error: Exception | None = None
    for address in sorted(addresses):
        connection: http.client.HTTPConnection | None = None
        try:
            transport = socket.create_connection((address, port), timeout=timeout_seconds)
            if parsed.scheme == "https":
                transport = ssl.create_default_context().wrap_socket(
                    transport, server_hostname=host
                )
            connection = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
            connection.sock = transport
            connection.request(
                "GET",
                path,
                headers={
                    "Accept": "text/html,application/xhtml+xml",
                    "Host": host,
                    "User-Agent": "shadowglass-v35-forge/35",
                },
            )
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise RelayRequestError("validated page exceeded the byte limit")
            if 300 <= response.status < 400:
                raise RelayRequestError("validated page redirects are forbidden")
            if not 200 <= response.status < 300:
                raise RelayRequestError("validated page returned a non-success status")
            try:
                html = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RelayRequestError("validated page is not UTF-8") from exc
            if not html.strip():
                raise RelayRequestError("validated page is empty")
            return html
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if connection is not None:
                connection.close()
    raise RelayRequestError("validated page retrieval failed") from last_error


def _credential_text(name: str) -> str:
    credential_dir = os.getenv("CREDENTIALS_DIRECTORY", "")
    explicit = os.getenv(f"SG_{name.upper()}_FILE", "")
    path = explicit or (str(Path(credential_dir) / name) if credential_dir else "")
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _validated_origin() -> str:
    raw = _credential_text("relay_url")
    allowlist = {
        item.strip().casefold()
        for item in _credential_text("relay_allowed_hosts").split(",")
        if item.strip()
    }
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        raise RelayConfigurationError("relay origin is invalid") from exc
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or host not in allowlist
    ):
        raise RelayConfigurationError("relay origin is not exactly allowlisted")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RelayConfigurationError("relay port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise RelayConfigurationError("relay port is invalid")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _pin_addresses(origin: str) -> frozenset[str]:
    parsed = urllib.parse.urlsplit(origin)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RelayConfigurationError("relay DNS resolution failed") from exc
    addresses = frozenset(answer[4][0] for answer in answers)
    if not addresses:
        raise RelayConfigurationError("relay DNS returned no addresses")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if address.is_multicast or address.is_unspecified:
            raise RelayConfigurationError("relay resolved to a forbidden address")
    return addresses


class RelayClient:
    """Calls only fixed paths on one root-configured, DNS-pinned origin."""

    def __init__(self, timeout_seconds: float = 20.0) -> None:
        self.origin = _validated_origin()
        self.addresses = _pin_addresses(self.origin)
        self.timeout_seconds = max(1.0, min(float(timeout_seconds), 60.0))
        parsed = urllib.parse.urlsplit(self.origin)
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.secure = parsed.scheme == "https"

    def _assert_dns_pin(self) -> None:
        if _pin_addresses(self.origin) != self.addresses:
            raise RelayRequestError("relay DNS changed during operation")

    def call(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        path = FIXED_PATHS.get(action)
        if path is None:
            raise RelayRequestError("unsupported relay action")
        self._assert_dns_pin()
        idempotency_key = str(payload.get("idempotency_key", ""))[:160]
        body_payload = {key: value for key, value in payload.items() if key != "idempotency_key"}
        body = json.dumps(body_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(body) > 128_000:
            raise RelayRequestError("relay payload is too large")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "shadowglass-v35-forge/35",
            "X-Idempotency-Key": idempotency_key,
        }
        raw: bytes | None = None
        status = 0
        last_error: Exception | None = None
        for address in sorted(self.addresses):
            connection: http.client.HTTPConnection | None = None
            try:
                transport = socket.create_connection(
                    (address, self.port), timeout=self.timeout_seconds
                )
                if self.secure:
                    transport = ssl.create_default_context().wrap_socket(
                        transport, server_hostname=self.host
                    )
                connection = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout_seconds
                )
                connection.sock = transport
                connection.request(
                    "GET" if action == "probe" else "POST",
                    path,
                    body=None if action == "probe" else body,
                    headers=headers,
                )
                response = connection.getresponse()
                status = int(response.status)
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                break
            except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
            finally:
                if connection is not None:
                    connection.close()
        if raw is None:
            raise RelayRequestError("relay request failed") from last_error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RelayRequestError("relay response exceeded the byte limit")
        if 300 <= status < 400:
            raise RelayRequestError("relay redirects are forbidden")
        if status < 200 or status >= 300:
            raise RelayRequestError("relay returned a non-success status")
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError as exc:
            raise RelayRequestError("relay returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise RelayRequestError("relay returned an invalid response shape")
        if parsed.get("error"):
            raise RelayRequestError("relay reported a browser error")
        return parsed

    def probe(self) -> dict[str, Any]:
        return self.call("probe", {})

    def browse(self, target_url: str, wait_for: str) -> dict[str, Any]:
        """Fetch one validated public county URL through local ShadowGlass Master.

        The Master returns only bounded metadata over loopback and persists the full
        rendered HTML in its private MinIO bucket.  This client accepts only the
        Master's deterministic artifact-key shape before reading that object.
        """

        try:
            parsed = urllib.parse.urlsplit(target_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise RelayRequestError("browser target URL is invalid") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or not wait_for
            or len(wait_for) > 200
        ):
            raise RelayRequestError("browser target URL is invalid")
        try:
            answers = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
            addresses = frozenset(answer[4][0] for answer in answers)
        except (OSError, ValueError) as exc:
            raise RelayRequestError("browser target DNS validation failed") from exc
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise RelayRequestError("browser target is not exclusively public")
        result = self.call(
            "browser",
            {
                "url": target_url,
                "wait_selector": wait_for,
                "screenshot": False,
                "ingest": False,
                "max_rung": "L6",
                "min_len": 500,
            },
        )
        if not result.get("ok") or not result.get("validated"):
            raise RelayRequestError("ShadowGlass Master did not validate the page")
        artifacts = result.get("artifacts")
        artifact_key = artifacts.get("html_key") if isinstance(artifacts, dict) else None
        if not isinstance(artifact_key, str) or not MASTER_ARTIFACT_KEY.fullmatch(artifact_key):
            if result.get("rung") != "L0":
                raise RelayRequestError("ShadowGlass Master returned no valid HTML artifact")
            return {
                "html": _direct_public_get(
                    target_url,
                    addresses,
                    timeout_seconds=self.timeout_seconds,
                )
            }
        run_id = str(result.get("run_id", ""))
        if not artifact_key.endswith(f"/{run_id}.html"):
            raise RelayRequestError("ShadowGlass Master artifact identity is inconsistent")
        try:
            client, _ = configured_client()
            response = client.get_object(MASTER_ARTIFACT_BUCKET, artifact_key)
            try:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            finally:
                close = getattr(response, "close", None)
                release = getattr(response, "release_conn", None)
                if callable(close):
                    close()
                if callable(release):
                    release()
        except Exception as exc:
            raise RelayRequestError("ShadowGlass Master artifact could not be read") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RelayRequestError("ShadowGlass Master artifact exceeded the byte limit")
        try:
            html = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RelayRequestError("ShadowGlass Master artifact is not UTF-8") from exc
        if not html.strip():
            raise RelayRequestError("ShadowGlass Master artifact is empty")
        return {"html": html}
