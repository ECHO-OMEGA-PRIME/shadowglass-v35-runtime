from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from provider_queue import CloudflareQueueProducer, ProviderQueueError


class Response:
    def __init__(self, document: dict[str, object]) -> None:
        self.document = document

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.document).encode()


def producer() -> CloudflareQueueProducer:
    return CloudflareQueueProducer(
        account_id="a" * 32,
        token="secret",
        targets={"publicsearch": "1" * 32, "texasfile": "2" * 32, "tyler": "3" * 32},
    )


def test_send_uses_exact_target_without_secret_in_body() -> None:
    with patch("urllib.request.urlopen", return_value=Response({"success": True})) as opened:
        producer().send("texasfile", {"type": "scrape", "county": "Midland"})
    request = opened.call_args.args[0]
    assert "/" + "2" * 32 + "/messages" in request.full_url
    assert b"secret" not in request.data
    assert json.loads(request.data)["content_type"] == "json"


def test_invalid_provider_response_fails_closed() -> None:
    with patch("urllib.request.urlopen", return_value=Response({"success": False})):
        with pytest.raises(ProviderQueueError):
            producer().send("tyler", {"type": "scrape"})


def test_unknown_target_is_rejected_before_network() -> None:
    with pytest.raises(ValueError):
        producer().send("unknown", {"type": "scrape"})


def test_provider_identifiers_are_validated() -> None:
    with pytest.raises(ValueError):
        CloudflareQueueProducer(account_id="bad", token="secret", targets={})


def test_payload_size_is_bounded() -> None:
    with pytest.raises(ValueError):
        producer().send("tyler", {"value": "x" * 130_000})

