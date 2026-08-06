from __future__ import annotations

import io
import json
import uuid
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from object_store import ObjectStoreError, PageObjectStore
import storage


class Response(io.BytesIO):
    def release_conn(self) -> None:
        return None


class FakeMinio:
    def __init__(self, exists: bool = True) -> None:
        self.exists = exists
        self.objects: dict[str, bytes] = {}
        self.metadata: dict[str, Mapping[str, str]] = {}
        self.puts = 0

    def bucket_exists(self, _: str) -> bool:
        return self.exists

    def make_bucket(self, _: str) -> None:
        self.exists = True

    def put_object(
        self,
        _: str,
        key: str,
        data: Any,
        length: int,
        content_type: str = "",
        metadata: Mapping[str, str] | None = None,
    ) -> Any:
        body = data.read()
        assert len(body) == length and content_type == "application/json"
        self.puts += 1
        self.objects[key] = body
        self.metadata[key] = metadata or {}
        return SimpleNamespace(etag="etag-1")

    def stat_object(self, _: str, key: str) -> Any:
        return SimpleNamespace(size=len(self.objects[key]), etag="etag-1")

    def get_object(self, _: str, key: str) -> Response:
        return Response(self.objects[key])

    def remove_object(self, _: str, key: str) -> None:
        self.objects.pop(key, None)


def fence(key: str) -> storage.LeaseWriteFence:
    return storage.LeaseWriteFence(1, uuid.uuid4(), key)


def test_page_write_uses_recovered_deterministic_key_and_verifies_bytes() -> None:
    client = FakeMinio()
    store = PageObjectStore(client, "shadowglass-v35")
    document = {"records": [{"id": "1"}], "page": 0}
    key = store.page_key(
        county="Midland", instrument_type="Deed of Trust", page=0, platform="publicsearch"
    )
    result = store.put_page(
        county="Midland",
        instrument_type="Deed of Trust",
        instrument_type_id=2,
        page=0,
        platform="publicsearch",
        document=document,
        fence=fence(key),
    )
    assert result.key == "SHADOWGLASS_V35/Midland/Deed_of_Trust/page_000000.json"
    assert json.loads(client.objects[result.key]) == document
    assert client.metadata[result.key]["sha256"] == result.sha256


def test_tyler_key_and_path_traversal_guard() -> None:
    store = PageObjectStore(FakeMinio(), "shadowglass-v35")
    key = store.page_key(
        county="Reeves", instrument_type="Deed", page=1001, platform="TYLER_TECH"
    )
    result = store.put_page(
        county="Reeves",
        instrument_type="Deed",
        instrument_type_id=2,
        page=1001,
        platform="TYLER_TECH",
        document={"records": []},
        fence=fence(key),
    )
    assert result.key == "SHADOWGLASS_V35/TYLER/Reeves/Deed/page_001001.json"
    with pytest.raises(ObjectStoreError, match="path separator"):
        store.put_page(
            county="../Reeves",
            instrument_type="Deed",
            instrument_type_id=2,
            page=0,
            platform="tyler",
            document={"records": []},
            fence=fence("invalid"),
        )


def test_provision_and_roundtrip_clean_up_probe_object() -> None:
    client = FakeMinio(exists=False)
    store = PageObjectStore(client, "shadowglass-v35")
    store.provision()
    store.roundtrip()
    assert client.exists and client.objects == {}


def test_same_content_is_noop_but_divergent_content_is_rejected() -> None:
    client = FakeMinio()
    store = PageObjectStore(client, "shadowglass-v35")
    key = store.page_key(county="Ward", instrument_type="Deed", page=3, platform="tyler")
    arguments = {
        "county": "Ward",
        "instrument_type": "Deed",
        "instrument_type_id": 2,
        "page": 3,
        "platform": "tyler",
    }
    store.put_page(**arguments, document={"records": [{"id": "one"}]}, fence=fence(key))
    store.put_page(**arguments, document={"records": [{"id": "one"}]}, fence=fence(key))
    assert client.puts == 1
    with pytest.raises(ObjectStoreError, match="divergent"):
        store.put_page(
            **arguments,
            document={"records": [{"id": "different"}]},
            fence=fence(key),
        )
    assert client.puts == 1


def test_inactive_or_wrong_key_fence_is_rejected() -> None:
    client = FakeMinio()
    store = PageObjectStore(client, "shadowglass-v35")
    key = store.page_key(county="Ward", instrument_type="Deed", page=0, platform="")
    proof = fence(key)
    proof._close()
    with pytest.raises(ObjectStoreError, match="lease fence"):
        store.put_page(
            county="Ward",
            instrument_type="Deed",
            instrument_type_id=2,
            page=0,
            platform="",
            document={"records": []},
            fence=proof,
        )
    assert client.puts == 0
