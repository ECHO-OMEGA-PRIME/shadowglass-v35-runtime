#!/usr/bin/env python3
"""Redacted, reversible inspection/cutover for the legacy Queue and cron."""

from __future__ import annotations

import argparse
import base64
import email.parser
import email.policy
import hashlib
import json
import os
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


WORKER = "shadowglass-v35"
QUEUE_NAME = "shadowglass-v35-queue"
ACCOUNT_ID = ""
CF_API = os.getenv("CF_API_BASE", "https://api.cloudflare.com/client/v4").rstrip("/")
SDK_URL = os.getenv("ECHO_SDK_URL", "http://127.0.0.1:8000/sdk/invoke")
KEY_FILE = Path(os.getenv("ECHO_SOVEREIGN_KEY_FILE", "/home/forge/.echo_sovereign_key"))
CREDENTIAL_DIR = Path(
    os.getenv(
        "SG_V35_CREDENTIAL_DIR",
        "/etc/echo/credentials/shadowglass-v35",
    )
)
BACKUP_PATH = Path(
    os.getenv(
        "SG_V35_CF_BACKUP",
        "/home/forge/shadowglass-v35/cloudflare-trigger-backup.json",
    )
)
RECOVERY_PATH = Path(
    os.getenv(
        "SG_V35_RECOVERY_MARKER",
        "/home/forge/shadowglass-v35/RECOVERY_REQUIRED.json",
    )
)
CONTENT_BACKUP_PATH = Path(
    os.getenv(
        "SG_V35_CF_CONTENT_BACKUP",
        "/home/forge/shadowglass-v35/cloudflare-worker-content-backup-v2.multipart",
    )
)
CONTENT_BACKUP_META_PATH = Path(
    os.getenv(
        "SG_V35_CF_CONTENT_BACKUP_META",
        "/home/forge/shadowglass-v35/cloudflare-worker-content-backup-v2.json",
    )
)
QUARANTINE_SOURCE_PATH = Path(__file__).with_name("legacy_quarantine.js")
LEGACY_MODULE_SHA256 = "c17f54dc2e9ce9829cf9bf845dfa36a11e6b8bbf044bfc01446e4c00f28c7735"
_WORKER_ID: str | None = None
_CONTENT_BY_VERSION: dict[str, dict[str, Any]] = {}


def _clear_recovery_marker() -> None:
    if not RECOVERY_PATH.exists():
        return
    RECOVERY_PATH.unlink()
    descriptor = os.open(RECOVERY_PATH.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sovereign_key() -> str:
    match = re.search(r"SOVEREIGN_KEY\s*=\s*(\S+)", KEY_FILE.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError("SDK credential unavailable")
    return match.group(1)


def _cloudflare_token() -> str:
    payload = {
        "envelope_version": 1,
        "capability": "echo.vault.get",
        "params": {
            "command": "get",
            "service": "cloudflare_shadowglass_v35_cutover_token",
            "username": "queue-worker-triggers",
        },
        "context": {
            "bypass_reason": (
                "Inspect and reversibly cut over the verified ShadowGlass v35 "
                "Cloudflare queue consumer and hourly trigger after staging passes."
            )
        },
    }
    request = urllib.request.Request(
        SDK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Echo-API-Key": _sovereign_key()},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.loads(response.read())
    secret = ((result.get("result") or {}).get("body") or {}).get("secret")
    if not secret:
        raise RuntimeError("Cloudflare credential unavailable")
    return str(secret)


def _load_identity() -> None:
    global ACCOUNT_ID
    account_id = (CREDENTIAL_DIR / "cloudflare-account-id").read_text(
        encoding="utf-8"
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{32}", account_id):
        raise RuntimeError("Cloudflare account identity is invalid")
    ACCOUNT_ID = account_id


def _cf(method: str, path: str, key: str, payload: Any = None) -> Any:
    request = urllib.request.Request(
        f"{CF_API}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw_error = exc.read()
        details: list[str] = []
        try:
            error_payload = json.loads(raw_error)
        except (TypeError, ValueError):
            error_payload = {}
        for item in error_payload.get("errors") or []:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            message = str(item.get("message") or "").strip()
            if code is not None or message:
                details.append(f"{code}: {message}".strip(": "))
        suffix = f" ({'; '.join(details[:3])})" if details else ""
        raise RuntimeError(f"Cloudflare HTTP {exc.code}{suffix}") from exc
    result = json.loads(raw) if raw else {"success": True, "result": None}
    if not result.get("success"):
        raise RuntimeError("Cloudflare operation failed")
    return result.get("result")


def _cf_raw(
    method: str,
    path: str,
    key: str,
    *,
    payload: bytes | None = None,
    content_type: str | None = None,
    accept: str | None = None,
) -> tuple[bytes, str]:
    headers = {"Authorization": f"Bearer {key}"}
    if content_type:
        headers["Content-Type"] = content_type
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(
        f"{CF_API}{path}", data=payload, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read(), str(response.headers.get("Content-Type") or "")
    except urllib.error.HTTPError as exc:
        raw_error = exc.read()
        details: list[str] = []
        try:
            error_payload = json.loads(raw_error)
        except (TypeError, ValueError):
            error_payload = {}
        for item in error_payload.get("errors") or []:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            message = str(item.get("message") or "").strip()
            if code is not None or message:
                details.append(f"{code}: {message}".strip(": "))
        suffix = f" ({'; '.join(details[:3])})" if details else ""
        raise RuntimeError(f"Cloudflare HTTP {exc.code}{suffix}") from exc


def _content_path(suffix: str = "") -> str:
    return (
        f"/accounts/{ACCOUNT_ID}/workers/scripts/"
        f"{urllib.parse.quote(WORKER)}/content{suffix}"
    )


def _multipart_parts(raw: bytes, content_type: str) -> list[dict[str, Any]]:
    if not content_type.casefold().startswith("multipart/form-data;"):
        raise RuntimeError("Cloudflare Worker content is not multipart")
    header = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    ).encode("ascii")
    message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        header + raw
    )
    if not message.is_multipart():
        raise RuntimeError("Cloudflare Worker content multipart is malformed")
    parts: list[dict[str, Any]] = []
    for part in message.iter_parts():
        payload = part.get_payload(decode=True) or b""
        parts.append(
            {
                "name": str(
                    part.get_param("name", header="content-disposition") or ""
                ),
                "filename": str(part.get_filename() or ""),
                "content_type": part.get_content_type(),
                "payload": payload,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if not parts:
        raise RuntimeError("Cloudflare Worker content multipart has no files")
    return parts


def _content_identity_from_parts(
    parts: list[dict[str, Any]], *, entry_point: str | None = None
) -> dict[str, Any]:
    module_parts = [part for part in parts if part["filename"]]
    module_names = [str(part["filename"]) for part in module_parts]
    if len(module_names) != len(set(module_names)):
        raise RuntimeError("Cloudflare Worker content has duplicate module names")
    multipart_names = [str(part["name"]) for part in module_parts]
    if len(multipart_names) != len(set(multipart_names)):
        raise RuntimeError("Cloudflare Worker content has duplicate multipart names")
    if any(part["name"] != part["filename"] for part in module_parts):
        raise RuntimeError("Cloudflare Worker module name/filename identity mismatch")
    metadata_parts = [
        part for part in parts if part["name"] == "metadata" and not part["filename"]
    ]
    if len(metadata_parts) > 1:
        raise RuntimeError("Cloudflare Worker content has duplicate metadata parts")
    if metadata_parts:
        try:
            metadata = json.loads(metadata_parts[0]["payload"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Cloudflare Worker content metadata is malformed") from exc
        if not isinstance(metadata, dict):
            raise RuntimeError("Cloudflare Worker content metadata is not an object")
        selectors = [
            str(metadata[name])
            for name in ("main_module", "body_part")
            if metadata.get(name)
        ]
        if len(selectors) != 1:
            raise RuntimeError("Cloudflare Worker content metadata entrypoint is ambiguous")
        if entry_point is not None and entry_point != selectors[0]:
            raise RuntimeError("Cloudflare Worker content entrypoint sources disagree")
        entry_point = selectors[0]
    if not entry_point:
        raise RuntimeError("Cloudflare Worker content entrypoint is unavailable")
    identities = {
        str(part["filename"]): str(part["sha256"])
        for part in module_parts
    }
    quarantine_sha = hashlib.sha256(QUARANTINE_SOURCE_PATH.read_bytes()).hexdigest()
    return {
        "legacy": entry_point == "worker.js"
        and identities == {"worker.js": LEGACY_MODULE_SHA256},
        "quarantined": identities
        == {
            "quarantine.js": quarantine_sha,
            "original.js": LEGACY_MODULE_SHA256,
        }
        and entry_point == "quarantine.js",
        "part_count": len(module_parts),
        "entry_point": entry_point,
    }


def _worker_id(key: str) -> str:
    global _WORKER_ID
    if _WORKER_ID:
        return _WORKER_ID
    query = urllib.parse.urlencode({"name": WORKER, "per_page": 2})
    results = list(
        _cf(
            "GET",
            f"/accounts/{ACCOUNT_ID}/workers/scripts-search?{query}",
            key,
        )
        or []
    )
    matches = [item for item in results if item.get("script_name") == WORKER]
    if len(matches) != 1:
        raise RuntimeError("Cloudflare Worker immutable identity is ambiguous")
    worker_id = str(matches[0].get("id") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", worker_id):
        raise RuntimeError("Cloudflare Worker immutable identity is unavailable")
    _WORKER_ID = worker_id
    return worker_id


def _active_version_content(key: str) -> dict[str, Any]:
    worker_path = (
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}"
    )
    result = _cf("GET", f"{worker_path}/deployments", key) or {}
    deployments = list(result.get("deployments") or [])
    if not deployments:
        raise RuntimeError("Cloudflare Worker has no active deployment")
    versions = list(deployments[0].get("versions") or [])
    if len(versions) != 1 or float(versions[0].get("percentage") or 0) != 100:
        raise RuntimeError("Cloudflare Worker active deployment is not singular")
    version_id = str(versions[0].get("version_id") or "")
    if not re.fullmatch(r"[0-9a-f-]{36}", version_id):
        raise RuntimeError("Cloudflare Worker active version identity is unavailable")
    if version_id not in _CONTENT_BY_VERSION:
        detail = _cf(
            "GET",
            f"/accounts/{ACCOUNT_ID}/workers/workers/{_worker_id(key)}"
            f"/versions/{version_id}?include=modules",
            key,
        ) or {}
        main_module = str(detail.get("main_module") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", main_module):
            raise RuntimeError("Cloudflare Worker active entrypoint is unavailable")
        modules = list(detail.get("modules") or [])
        parts: list[dict[str, Any]] = []
        for module in modules:
            name = str(module.get("name") or "")
            encoded = str(module.get("content_base64") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not encoded:
                raise RuntimeError("Cloudflare Worker active module is malformed")
            try:
                payload = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as exc:
                raise RuntimeError(
                    "Cloudflare Worker active module content is malformed"
                ) from exc
            parts.append(
                {
                    "name": name,
                    "filename": name,
                    "content_type": str(module.get("content_type") or ""),
                    "payload": payload,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        identity = _content_identity_from_parts(parts, entry_point=main_module)
        identity["active_version_id"] = version_id
        identity["module_payloads"] = {
            str(part["filename"]): part["payload"] for part in parts
        }
        _CONTENT_BY_VERSION[version_id] = identity
    return dict(_CONTENT_BY_VERSION[version_id])


def _content_state(key: str) -> dict[str, Any]:
    identity = _active_version_content(key)
    identity.pop("module_payloads", None)
    try:
        _, _, _, metadata = _load_content_backup()
    except RuntimeError:
        identity["settings_match_backup"] = False
    else:
        identity["settings_match_backup"] = (
            _settings_sha256(key) == metadata["settings_sha256"]
        )
    return identity


def _atomic_exclusive_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
    except PermissionError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _settings_sha256(key: str) -> str:
    settings = _cf(
        "GET",
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/settings",
        key,
    ) or {}
    # `workers/triggered_by` is a server-owned version annotation and changes
    # on every content-only upload. It is not Worker configuration. Hash every
    # actual setting/binding while deliberately excluding that volatile field.
    normalized = dict(settings)
    annotations = dict(normalized.get("annotations") or {})
    annotations.pop("workers/triggered_by", None)
    if annotations:
        normalized["annotations"] = annotations
    else:
        normalized.pop("annotations", None)
    encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _load_content_backup(
) -> tuple[bytes, str, list[dict[str, Any]], dict[str, Any]]:
    if not CONTENT_BACKUP_PATH.exists() or not CONTENT_BACKUP_META_PATH.exists():
        raise RuntimeError("legacy Worker content recovery backup is missing")
    try:
        raw = CONTENT_BACKUP_PATH.read_bytes()
        metadata = json.loads(CONTENT_BACKUP_META_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("legacy Worker content recovery backup is unreadable") from exc
    content_type = str(metadata.get("content_type") or "")
    if (
        metadata.get("worker") != WORKER
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(metadata.get("settings_sha256") or "")
        )
        or not re.fullmatch(
            r"[0-9a-f-]{36}", str(metadata.get("active_version_id") or "")
        )
        or metadata.get("settings_digest_version") != 2
    ):
        raise RuntimeError("legacy Worker content recovery metadata mismatch")
    if hashlib.sha256(raw).hexdigest() != str(metadata.get("sha256") or ""):
        raise RuntimeError("legacy Worker content recovery backup digest mismatch")
    parts = _multipart_parts(raw, content_type)
    entry_point = str(metadata.get("main_module") or "")
    if entry_point != "worker.js" or not _content_identity_from_parts(
        parts, entry_point=entry_point
    )["legacy"]:
        raise RuntimeError("legacy Worker content recovery backup identity mismatch")
    return raw, content_type, parts, metadata


def _save_content_backup(key: str) -> None:
    if CONTENT_BACKUP_PATH.exists() or CONTENT_BACKUP_META_PATH.exists():
        if not (CONTENT_BACKUP_PATH.exists() and CONTENT_BACKUP_META_PATH.exists()):
            raise RuntimeError("legacy Worker content recovery backup is incomplete")
        _, _, _, metadata = _load_content_backup()
        current = _content_state(key)
        if not (current["legacy"] or current["quarantined"]):
            raise RuntimeError("unexpected Worker content prevents backup reuse")
        if _settings_sha256(key) != metadata["settings_sha256"]:
            raise RuntimeError("legacy Worker settings drift prevents backup reuse")
        return
    content = _active_version_content(key)
    if not content["legacy"]:
        raise RuntimeError("live legacy Worker content identity mismatch")
    entry_point = str(content["entry_point"])
    worker_payload = content["module_payloads"].get("worker.js")
    if not isinstance(worker_payload, bytes):
        raise RuntimeError("live legacy Worker module bytes are unavailable")
    raw, content_type = _multipart_upload([("worker.js", worker_payload)])
    metadata = json.dumps(
        {
            "worker": WORKER,
            "content_type": content_type,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "module_sha256": LEGACY_MODULE_SHA256,
            "main_module": entry_point,
            "active_version_id": content["active_version_id"],
            "settings_sha256": _settings_sha256(key),
            "settings_digest_version": 2,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    _atomic_exclusive_write(CONTENT_BACKUP_PATH, raw)
    try:
        _atomic_exclusive_write(CONTENT_BACKUP_META_PATH, metadata)
    except Exception:
        CONTENT_BACKUP_PATH.unlink(missing_ok=True)
        raise


def _content_backup_restoreable() -> bool:
    try:
        _load_content_backup()
    except RuntimeError:
        return False
    return True


def _multipart_upload(files: list[tuple[str, bytes]]) -> tuple[bytes, str]:
    boundary = f"echo-sgv8-{os.urandom(16).hex()}"
    chunks: list[bytes] = []
    metadata = json.dumps(
        {"main_module": files[0][0]}, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="metadata"\r\n',
            b"Content-Type: application/json\r\n\r\n",
            metadata,
            b"\r\n",
        ]
    )
    for name, payload in files:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise RuntimeError("invalid Worker module filename")
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; '
                    f'filename="{name}"\r\n'
                ).encode(),
                b"Content-Type: application/javascript+module\r\n\r\n",
                payload,
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _put_content(key: str, raw: bytes, content_type: str) -> None:
    response, _ = _cf_raw(
        "PUT",
        _content_path(),
        key,
        payload=raw,
        content_type=content_type,
    )
    result = json.loads(response) if response else {"success": True}
    if not result.get("success"):
        raise RuntimeError("Cloudflare Worker content update failed")


def _wait_for_content_identity(key: str, identity: str) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    while True:
        current = _content_state(key)
        if current.get(identity):
            return current
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Cloudflare Worker {identity} content identity did not converge"
            )
        time.sleep(2)


def _quarantine_content(key: str) -> None:
    current = _content_state(key)
    if current["quarantined"]:
        return
    if not current["legacy"]:
        raise RuntimeError("unexpected Worker content prevents quarantine")
    _, _, parts, metadata = _load_content_backup()
    legacy = next(part["payload"] for part in parts if part["filename"] == "worker.js")
    raw, content_type = _multipart_upload(
        [("quarantine.js", QUARANTINE_SOURCE_PATH.read_bytes()), ("original.js", legacy)]
    )
    _put_content(key, raw, content_type)
    quarantined = _wait_for_content_identity(key, "quarantined")
    if not quarantined.get("settings_match_backup"):
        raise RuntimeError("legacy Worker settings changed during content quarantine")
    if _settings_sha256(key) != metadata["settings_sha256"]:
        raise RuntimeError("legacy Worker settings changed during content quarantine")


def _restore_content(key: str) -> None:
    current = _content_state(key)
    if current["legacy"]:
        _, _, _, metadata = _load_content_backup()
        if not current.get("settings_match_backup") or (
            _settings_sha256(key) != metadata["settings_sha256"]
        ):
            raise RuntimeError("legacy Worker settings drift prevents recovery")
        return
    if not current["quarantined"]:
        raise RuntimeError("unexpected Worker content prevents recovery")
    _, _, parts, metadata = _load_content_backup()
    legacy = next(part["payload"] for part in parts if part["filename"] == "worker.js")
    raw, content_type = _multipart_upload([("worker.js", legacy)])
    _put_content(key, raw, content_type)
    restored = _wait_for_content_identity(key, "legacy")
    if not restored.get("settings_match_backup") or (
        _settings_sha256(key) != metadata["settings_sha256"]
    ):
        raise RuntimeError("legacy Worker settings changed during content restore")


def _validate_identity(key: str) -> None:
    token = _cf("GET", "/user/tokens/verify", key) or {}
    if str(token.get("status") or "").casefold() != "active":
        raise RuntimeError("Cloudflare scoped token is not active")


def _state(key: str) -> dict[str, Any]:
    queues = list(_cf("GET", f"/accounts/{ACCOUNT_ID}/queues", key) or [])
    matches = [queue for queue in queues if queue.get("queue_name") == QUEUE_NAME]
    if len(matches) != 1:
        raise RuntimeError("expected exactly one legacy queue")
    queue = matches[0]
    queue_id = str(queue.get("queue_id") or queue.get("queue_id_string") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", queue_id):
        raise RuntimeError("legacy queue identity is unavailable")
    consumers = list(
        _cf("GET", f"/accounts/{ACCOUNT_ID}/queues/{queue_id}/consumers", key) or []
    )
    metrics = _cf("GET", f"/accounts/{ACCOUNT_ID}/queues/{queue_id}/metrics", key) or {}
    schedules = _cf(
        "GET",
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/schedules",
        key,
    ) or []
    if isinstance(schedules, dict):
        schedules = schedules.get("schedules") or []
    domains = list(
        _cf(
            "GET",
            f"/accounts/{ACCOUNT_ID}/workers/domains?service={urllib.parse.quote(WORKER)}",
            key,
        )
        or []
    )
    subdomain = _cf(
        "GET",
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/subdomain",
        key,
    ) or {}
    content = _content_state(key)
    matching_consumers = [
        item
        for item in consumers
        if (item.get("script") or item.get("script_name")) == WORKER
    ]
    return {
        "queue": queue,
        "queue_id": queue_id,
        "consumers": consumers,
        "matching_consumers": matching_consumers,
        "metrics": metrics,
        "schedules": schedules,
        "domains": [item for item in domains if item.get("service") == WORKER],
        "subdomain": subdomain,
        "content": content,
    }


def _summary(state: dict[str, Any]) -> dict[str, Any]:
    backlog_count, backlog_bytes, oldest_timestamp_ms = _metric_snapshot(
        state["metrics"]
    )
    return {
        "worker": WORKER,
        "queue_exists": bool(state["queue_id"]),
        "consumer_count": len(state["consumers"]),
        "matching_worker_consumers": len(state["matching_consumers"]),
        "backlog_count": backlog_count,
        "backlog_bytes": backlog_bytes,
        "oldest_message_timestamp_ms": oldest_timestamp_ms,
        "crons": sorted(str(item.get("cron")) for item in state["schedules"]),
        "custom_domain_count": len(state["domains"]),
        "workers_dev_enabled": bool(state["subdomain"].get("enabled")),
        "worker_content_legacy": bool(state["content"].get("legacy")),
        "worker_quarantined": bool(state["content"].get("quarantined")),
        "worker_settings_match_backup": bool(
            state["content"].get("settings_match_backup")
        ),
    }


def _metric_snapshot(metrics: Any) -> tuple[int, int, int]:
    if not isinstance(metrics, dict):
        raise RuntimeError("legacy queue metrics response is not an object")
    values: list[int] = []
    for name in ("backlog_count", "backlog_bytes", "oldest_message_timestamp_ms"):
        value = metrics.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuntimeError(f"legacy queue metric is missing or malformed: {name}")
        if value < 0 or int(value) != value:
            raise RuntimeError(f"legacy queue metric is outside its valid range: {name}")
        values.append(int(value))
    return values[0], values[1], values[2]


def _save_backup(state: dict[str, Any]) -> None:
    if BACKUP_PATH.exists():
        existing = _load_backup(state["queue_id"])
        if _is_disabled(state):
            return
        _assert_disable_baseline(state)
        if (
            [_consumer_payload(item) for item in existing["matching_consumers"]]
            != [_consumer_payload(item) for item in state["matching_consumers"]]
            or _schedule_payload(list(existing["schedules"]))
            != _schedule_payload(list(state["schedules"]))
            or dict(existing["subdomain"]) != dict(state["subdomain"])
            or sorted(existing["domains"], key=lambda item: json.dumps(item, sort_keys=True))
            != sorted(state["domains"], key=lambda item: json.dumps(item, sort_keys=True))
        ):
            raise RuntimeError("existing backup differs from the current legacy trigger baseline")
        return
    _assert_disable_baseline(state)
    BACKUP_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "worker": WORKER,
        "queue_name": QUEUE_NAME,
        "queue_id": state["queue_id"],
        "matching_consumers": state["matching_consumers"],
        "schedules": state["schedules"],
        "subdomain": state["subdomain"],
        "domains": state["domains"],
        "summary": _summary(state),
    }
    descriptor = os.open(
        BACKUP_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory_descriptor = os.open(BACKUP_PATH.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _load_backup(queue_id: str) -> dict[str, Any]:
    if not BACKUP_PATH.exists():
        raise RuntimeError("legacy trigger recovery backup is missing")
    try:
        backup = json.loads(BACKUP_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("legacy trigger recovery backup is unreadable") from exc
    if not isinstance(backup, dict) or (
        backup.get("worker") != WORKER
        or backup.get("queue_name") != QUEUE_NAME
        or str(backup.get("queue_id") or "") != queue_id
    ):
        raise RuntimeError("existing backup identity mismatch")
    consumers = list(backup.get("matching_consumers") or [])
    schedules = list(backup.get("schedules") or [])
    subdomain = backup.get("subdomain")
    domains = backup.get("domains")
    if len(consumers) != 1:
        raise RuntimeError("backup does not contain one legacy consumer")
    consumer_payload = _consumer_payload(consumers[0])
    if (
        consumer_payload.get("script_name") != WORKER
        or consumer_payload.get("type") != "worker"
    ):
        raise RuntimeError("backup legacy consumer identity mismatch")
    if _schedule_payload(schedules) != [{"cron": "0 * * * *"}]:
        raise RuntimeError("backup does not contain the recovered hourly schedule")
    if not isinstance(subdomain, dict) or subdomain.get("enabled") is not True:
        raise RuntimeError("backup does not contain the enabled workers.dev baseline")
    if not isinstance(domains, list) or domains:
        raise RuntimeError("backup custom-domain baseline is invalid")
    return backup


def _backup_restoreable(queue_id: str) -> bool:
    try:
        _load_backup(queue_id)
    except RuntimeError:
        return False
    return True


def _consumer_payload(item: dict[str, Any]) -> dict[str, Any]:
    script_name = item.get("script_name") or item.get("script")
    if not script_name:
        raise RuntimeError("legacy consumer script identity is unavailable")
    payload: dict[str, Any] = {
        "script_name": str(script_name),
        "type": str(item.get("type") or "worker"),
    }
    for name in ("dead_letter_queue", "settings"):
        if item.get(name) not in (None, ""):
            payload[name] = item[name]
    return payload


def _schedule_payload(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    result = []
    for item in items:
        cron = str(item.get("cron") or "")
        if not cron:
            raise RuntimeError("legacy schedule is missing its cron expression")
        result.append({"cron": cron})
    return result


def _wait_for_stable_empty(key: str, queue_id: str) -> None:
    quiet_seconds = int(os.getenv("SG_CF_QUIET_SECONDS", "900"))
    if not 60 <= quiet_seconds <= 1800:
        raise RuntimeError("Cloudflare quiet window must be between 60 and 1800 seconds")
    beginning = _state(key)
    if not _producers_quiesced(beginning):
        raise RuntimeError("legacy producers are not quiesced at quiet-window start")
    if len(beginning["consumers"]) != 1 or len(beginning["matching_consumers"]) != 1:
        raise RuntimeError("legacy consumer must remain attached while the queue drains")
    quiet_started: float | None = None
    deadline = time.monotonic() + quiet_seconds + 600
    while time.monotonic() < deadline:
        metrics = _cf("GET", f"/accounts/{ACCOUNT_ID}/queues/{queue_id}/metrics", key) or {}
        count, size, oldest = _metric_snapshot(metrics)
        now = time.monotonic()
        if count == 0 and size == 0 and oldest == 0:
            if quiet_started is None:
                quiet_started = now
            if now - quiet_started >= quiet_seconds:
                ending = _state(key)
                if (
                    not _producers_quiesced(ending)
                    or len(ending["consumers"]) != 1
                    or len(ending["matching_consumers"]) != 1
                ):
                    raise RuntimeError("legacy producer/consumer state changed during quiet window")
                final_count, final_bytes, final_oldest = _metric_snapshot(
                    ending["metrics"]
                )
                if final_count or final_bytes or final_oldest:
                    raise RuntimeError("legacy queue changed at quiet-window completion")
                return
        else:
            quiet_started = None
        time.sleep(10)
    raise RuntimeError("legacy queue did not sustain an empty propagation window")


def _producers_quiesced(state: dict[str, Any]) -> bool:
    crons = _schedule_payload(list(state["schedules"] or []))
    cron_inert = not crons or (
        crons == [{"cron": "0 * * * *"}]
        and bool(state["content"].get("quarantined"))
    )
    return bool(
        cron_inert
        and not state["subdomain"].get("enabled")
        and not state["domains"]
        and bool(state["content"].get("quarantined"))
        and bool(state["content"].get("settings_match_backup"))
    )


def _is_disabled(state: dict[str, Any]) -> bool:
    count, size, oldest = _metric_snapshot(state["metrics"])
    return bool(
        not state["consumers"]
        and _producers_quiesced(state)
        and count == size == oldest == 0
    )


def _assert_disable_baseline(state: dict[str, Any]) -> None:
    summary = _summary(state)
    if (
        summary["backlog_count"] != 0
        or summary["backlog_bytes"] != 0
        or summary["oldest_message_timestamp_ms"] != 0
    ):
        raise RuntimeError("legacy queue backlog is not empty")
    if len(state["consumers"]) != 1 or len(state["matching_consumers"]) != 1:
        raise RuntimeError("expected one matching legacy consumer")
    if summary["crons"] != ["0 * * * *"]:
        raise RuntimeError("legacy cron contract differs from the recovered schedule")
    if summary["custom_domain_count"] != 0:
        raise RuntimeError("legacy Worker has custom domains and cannot be safely detached")
    if not summary["workers_dev_enabled"]:
        raise RuntimeError("legacy workers.dev ingress is already disabled")
    if not summary["worker_content_legacy"] or summary["worker_quarantined"]:
        raise RuntimeError("legacy Worker content differs from the recovered deployment")


def _recognized_partial_cutover(state: dict[str, Any]) -> bool:
    if not BACKUP_PATH.exists():
        return False
    try:
        backup = _load_backup(state["queue_id"])
    except RuntimeError:
        return False
    expected_consumers = [
        _consumer_payload(item) for item in backup.get("matching_consumers") or []
    ]
    current_consumers = [_consumer_payload(item) for item in state["matching_consumers"]]
    expected_schedules = _schedule_payload(list(backup.get("schedules") or []))
    current_schedules = _schedule_payload(list(state["schedules"] or []))
    saved_subdomain = dict(backup.get("subdomain") or {})
    current_subdomain = dict(state["subdomain"])
    consumer_known = (
        current_consumers in ([], expected_consumers)
        and len(state["consumers"]) == len(state["matching_consumers"])
    )
    schedule_known = current_schedules == expected_schedules
    subdomain_known = current_subdomain == saved_subdomain or not current_subdomain.get(
        "enabled"
    )
    domains_known = sorted(state["domains"], key=lambda item: json.dumps(item, sort_keys=True)) == sorted(
        backup.get("domains") or [], key=lambda item: json.dumps(item, sort_keys=True)
    )
    content_known = bool(
        state["content"].get("legacy") or state["content"].get("quarantined")
    )
    count, size, oldest = _metric_snapshot(state["metrics"])
    return bool(
        consumer_known
        and schedule_known
        and subdomain_known
        and domains_known
        and content_known
        and count == size == oldest == 0
        and (
            current_consumers != expected_consumers
            or current_schedules != expected_schedules
            or current_subdomain != saved_subdomain
            or not state["content"].get("legacy")
        )
    )


def disable(key: str) -> None:
    state = _state(key)
    if _is_disabled(state):
        _load_backup(state["queue_id"])
        _load_content_backup()
        print(json.dumps({"action": "already_disabled", **_summary(state)}, sort_keys=True))
        return
    try:
        _assert_disable_baseline(state)
    except RuntimeError:
        if not _recognized_partial_cutover(state):
            raise
        restore(key)
        state = _state(key)
        _assert_disable_baseline(state)
    _save_backup(state)
    _save_content_backup(key)
    consumer_id = str(state["matching_consumers"][0].get("consumer_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", consumer_id):
        raise RuntimeError("legacy consumer identity is unavailable")
    subdomain_path = (
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/subdomain"
    )
    try:
        _quarantine_content(key)
        if state["subdomain"].get("enabled"):
            _cf("DELETE", subdomain_path, key)
        _wait_for_stable_empty(key, state["queue_id"])
        _cf(
            "DELETE",
            f"/accounts/{ACCOUNT_ID}/queues/{state['queue_id']}/consumers/{consumer_id}",
            key,
        )
    except Exception:
        restore(key)
        raise
    after = _state(key)
    if not _is_disabled(after):
        restore(key)
        raise RuntimeError("legacy trigger cutover did not converge")
    print(json.dumps({"action": "disabled", **_summary(after)}, sort_keys=True))


def restore(key: str) -> None:
    state = _state(key)
    backup = _load_backup(state["queue_id"])
    consumers = list(backup.get("matching_consumers") or [])
    if len(consumers) != 1:
        raise RuntimeError("backup does not contain one legacy consumer")
    if len(state["consumers"]) > 1 or (
        state["consumers"] and len(state["matching_consumers"]) != 1
    ):
        raise RuntimeError("unexpected legacy queue consumers prevent safe restore")
    schedules = _schedule_payload(list(backup.get("schedules") or []))
    if _schedule_payload(list(state["schedules"] or [])) != schedules:
        raise RuntimeError("legacy schedule drift prevents quota-safe restore")
    if not (state["content"].get("legacy") or state["content"].get("quarantined")):
        raise RuntimeError("unexpected Worker content prevents safe restore")
    _, _, _, content_metadata = _load_content_backup()
    if _settings_sha256(key) != content_metadata["settings_sha256"]:
        raise RuntimeError("legacy Worker settings drift prevents safe restore")
    expected_consumer = _consumer_payload(consumers[0])
    if state["matching_consumers"] and (
        _consumer_payload(state["matching_consumers"][0]) != expected_consumer
    ):
        raise RuntimeError("legacy queue consumer drift prevents safe restore")
    # Restore and verify the exact Worker content/settings before enabling any
    # queue consumption or public edge. The still-private legacy cron may
    # enqueue during this window, but the durable queue safely retains it.
    _restore_content(key)
    state = _state(key)
    if not state["content"].get("legacy") or not state["content"].get(
        "settings_match_backup"
    ):
        raise RuntimeError("legacy Worker content/settings restore did not converge")
    if _schedule_payload(list(state["schedules"] or [])) != schedules:
        raise RuntimeError("legacy schedule drift prevents quota-safe restore")
    if not state["matching_consumers"]:
        # Mark the request as sent even when the HTTP response is lost. A retry
        # could otherwise create a second consumer after an ambiguous timeout.
        try:
            _cf(
                "POST",
                f"/accounts/{ACCOUNT_ID}/queues/{state['queue_id']}/consumers",
                key,
                _consumer_payload(consumers[0]),
            )
        except Exception:
            pass
        # Do not re-publish the legacy endpoint until the non-idempotent
        # consumer creation is observed. A lost response is polled, never
        # replayed, so rollback cannot create duplicate consumers.
        consumer_deadline = time.monotonic() + 30
        state = _state(key)
        while not state["matching_consumers"]:
            if state["consumers"]:
                raise RuntimeError(
                    "unexpected legacy queue consumer appeared during restore"
                )
            if time.monotonic() >= consumer_deadline:
                raise RuntimeError(
                    "legacy consumer restore response remained ambiguous"
                )
            time.sleep(2)
            state = _state(key)
        if len(state["consumers"]) != 1 or (
            _consumer_payload(state["matching_consumers"][0]) != expected_consumer
        ):
            raise RuntimeError("legacy queue consumer restore did not converge safely")
    saved_subdomain = dict(backup.get("subdomain") or {})
    current = _state(key)
    if saved_subdomain.get("enabled") and not current["subdomain"].get("enabled"):
        _cf(
            "POST",
            f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/subdomain",
            key,
            saved_subdomain,
        )
    elif not saved_subdomain.get("enabled") and current["subdomain"].get("enabled"):
        _cf(
            "DELETE",
            f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/subdomain",
            key,
        )
    expected_crons = sorted(item["cron"] for item in schedules)
    expected_domains = sorted(
        list(backup.get("domains") or []),
        key=lambda item: json.dumps(item, sort_keys=True),
    )
    deadline = time.monotonic() + 90
    after = _state(key)
    while time.monotonic() < deadline:
        if (
            len(after["consumers"]) == 1
            and len(after["matching_consumers"]) == 1
            and _consumer_payload(after["matching_consumers"][0]) == expected_consumer
            and _summary(after)["crons"] == expected_crons
            and bool(after["subdomain"].get("enabled"))
            == bool(saved_subdomain.get("enabled"))
            and sorted(after["domains"], key=lambda item: json.dumps(item, sort_keys=True))
            == expected_domains
            and all(
                after["subdomain"].get(name) == value
                for name, value in saved_subdomain.items()
            )
            and bool(after["content"].get("legacy"))
            and not bool(after["content"].get("quarantined"))
            and bool(after["content"].get("settings_match_backup"))
        ):
            print(json.dumps({"action": "restored", **_summary(after)}, sort_keys=True))
            _clear_recovery_marker()
            return
        if len(after["consumers"]) > 1:
            raise RuntimeError("legacy trigger restore created multiple consumers")
        # Content/subdomain PUT/POST/DELETE are idempotent and may be retried;
        # consumer creation is never repeated after an ambiguous response.
        if _schedule_payload(list(after["schedules"] or [])) != schedules:
            raise RuntimeError("legacy schedule drift prevents quota-safe restore")
        if not after["content"].get("legacy") or not after["content"].get(
            "settings_match_backup"
        ):
            raise RuntimeError("legacy Worker content/settings drifted during restore")
        if saved_subdomain.get("enabled") and not after["subdomain"].get("enabled"):
            _cf(
                "POST",
                f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/subdomain",
                key,
                saved_subdomain,
            )
        elif not saved_subdomain.get("enabled") and after["subdomain"].get("enabled"):
            _cf(
                "DELETE",
                f"/accounts/{ACCOUNT_ID}/workers/scripts/{urllib.parse.quote(WORKER)}/subdomain",
                key,
            )
        time.sleep(2)
        after = _state(key)
    raise RuntimeError(
        "legacy trigger restore did not converge after bounded verification retries"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("status", "backup", "disable", "restore"))
    args = parser.parse_args()
    _load_identity()
    key = _cloudflare_token()
    _validate_identity(key)
    state = _state(key)
    if args.action == "status":
        print(
            json.dumps(
                {
                    **_summary(state),
                    "backup_restoreable": _backup_restoreable(state["queue_id"]),
                    "content_backup_restoreable": _content_backup_restoreable(),
                },
                sort_keys=True,
            )
        )
    elif args.action == "backup":
        _save_backup(state)
        _save_content_backup(key)
        print(json.dumps({"action": "backed_up", **_summary(state)}, sort_keys=True))
    elif args.action == "disable":
        disable(key)
    else:
        restore(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
