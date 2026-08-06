"""Bounded Cloudflare Queue producer used by the FORGE command plane."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping


API_ROOT = "https://api.cloudflare.com/client/v4"


class ProviderQueueError(RuntimeError):
    """A provider dispatch did not return an unambiguous success receipt."""


def _provider_id(value: str, label: str) -> str:
    cleaned = str(value or "").strip()
    if not re.fullmatch(r"[0-9a-f]{32}", cleaned):
        raise ValueError(f"{label} must be a 32-character hexadecimal identifier")
    return cleaned


@dataclass(frozen=True, slots=True)
class QueueTarget:
    name: str
    queue_id: str

    def __post_init__(self) -> None:
        if self.name not in {"publicsearch", "texasfile", "tyler"}:
            raise ValueError("unsupported queue target")
        object.__setattr__(self, "queue_id", _provider_id(self.queue_id, "queue_id"))


class CloudflareQueueProducer:
    """Minimal push client which never exposes provider credentials in errors."""

    def __init__(
        self,
        *,
        account_id: str,
        token: str,
        targets: Mapping[str, str],
        timeout_seconds: float = 30.0,
    ) -> None:
        self.account_id = _provider_id(account_id, "account_id")
        self._token = str(token or "").strip()
        if not self._token:
            raise ValueError("queue token is required")
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds is outside safe bounds")
        self.timeout_seconds = float(timeout_seconds)
        self.targets = {name: QueueTarget(name, queue_id) for name, queue_id in targets.items()}
        if set(self.targets) != {"publicsearch", "texasfile", "tyler"}:
            raise ValueError("all three recovered queue targets are required")

    def send(self, target: str, payload: Mapping[str, Any]) -> None:
        destination = self.targets.get(target)
        if destination is None:
            raise ValueError("unsupported queue target")
        encoded = json.dumps(
            {"body": dict(payload), "content_type": "json"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > 128_000:
            raise ValueError("queue payload exceeds the service safety bound")
        request = urllib.request.Request(
            f"{API_ROOT}/accounts/{self.account_id}/queues/{destination.queue_id}/messages",
            data=encoded,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "shadowglass-v7-command-forge/1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                document = json.loads(response.read().decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.HTTPError) as exc:
            raise ProviderQueueError(
                f"provider dispatch failed ({type(exc).__name__})"
            ) from exc
        if not isinstance(document, Mapping) or document.get("success") is not True:
            raise ProviderQueueError("provider dispatch was not acknowledged")

