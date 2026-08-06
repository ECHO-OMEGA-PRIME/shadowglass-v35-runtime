#!/usr/bin/env python3
"""Deterministic, credential-file-backed page persistence in isolated MinIO."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from service import credential_text
import storage


class ObjectStoreError(RuntimeError):
    """Object persistence is unavailable or failed verification."""


class MinioLike(Protocol):
    def bucket_exists(self, bucket_name: str) -> bool: ...

    def make_bucket(self, bucket_name: str) -> None: ...

    def put_object(
        self,
        bucket_name: str,
        object_name: str,
        data: Any,
        length: int,
        content_type: str = "application/octet-stream",
        metadata: Mapping[str, str] | None = None,
    ) -> Any: ...

    def stat_object(self, bucket_name: str, object_name: str) -> Any: ...

    def get_object(self, bucket_name: str, object_name: str) -> Any: ...

    def remove_object(self, bucket_name: str, object_name: str) -> None: ...


@dataclass(frozen=True, slots=True)
class StoredPage:
    key: str
    sha256: str
    etag: str
    size: int


def _slug(value: str, *, maximum: int = 80) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")[:maximum]
    if not result:
        raise ObjectStoreError("object identity cannot be normalized")
    return result


def configured_client() -> tuple[MinioLike, str]:
    endpoint = credential_text("minio_endpoint")
    access = credential_text("minio_access_key")
    secret = credential_text("minio_secret_key")
    bucket = credential_text("minio_bucket")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise ObjectStoreError("object-store endpoint is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not access
        or not secret
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
    ):
        raise ObjectStoreError("object-store credentials are unavailable")
    from minio import Minio

    authority = parsed.hostname
    if port is not None:
        authority = f"{authority}:{port}"
    client = Minio(
        authority,
        access_key=access,
        secret_key=secret,
        secure=parsed.scheme == "https",
    )
    return client, bucket


class PageObjectStore:
    """Writes canonical page documents under deterministic isolated keys."""

    def __init__(self, client: MinioLike | None = None, bucket: str = "") -> None:
        if client is None:
            client, bucket = configured_client()
        if not bucket:
            raise ObjectStoreError("object-store bucket is unavailable")
        self.client = client
        self.bucket = bucket

    def provision(self) -> None:
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)
        if not self.client.bucket_exists(self.bucket):
            raise ObjectStoreError("object-store bucket provisioning did not converge")

    def probe(self) -> None:
        if not self.client.bucket_exists(self.bucket):
            raise ObjectStoreError("object-store bucket is missing")

    @staticmethod
    def page_key(
        *, county: str, instrument_type: str, page: int, platform: str
    ) -> str:
        if page < 0 or any(
            character in county + instrument_type for character in ("/", "\\", "..")
        ):
            raise ObjectStoreError("object identity contains a path separator")
        county_segment = county.strip()
        instrument_segment = re.sub(r"\s+", "_", instrument_type.strip())
        if not county_segment or not instrument_segment:
            raise ObjectStoreError("object identity is empty")
        platform_prefix = "TYLER/" if "tyler" in platform.casefold() else ""
        return (
            f"SHADOWGLASS_V35/{platform_prefix}{county_segment}/{instrument_segment}/"
            f"page_{page:06d}.json"
        )

    @staticmethod
    def canary_key(canary_id: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{32}", canary_id):
            raise ObjectStoreError("canary identity is invalid")
        return f"_acceptance_canary/v1/{canary_id}.json"

    @staticmethod
    def _canary_body(canary_id: str) -> bytes:
        return json.dumps(
            {
                "canary_id": canary_id,
                "schema_version": 1,
                "service": "shadowglass-v35",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _require_fence(fence: storage.LeaseWriteFence, key: str) -> None:
        if not fence.active or fence.object_key != key:
            raise ObjectStoreError("object write is not protected by its live lease fence")

    def _read_existing(self, key: str) -> tuple[bytes, Any] | None:
        try:
            stat = self.client.stat_object(self.bucket, key)
        except Exception as exc:
            code = str(getattr(exc, "code", ""))
            if isinstance(exc, (FileNotFoundError, KeyError)) or code in {
                "NoSuchKey",
                "NoSuchObject",
            }:
                return None
            raise ObjectStoreError("object-store existence check failed") from exc
        size = int(getattr(stat, "size", -1))
        if size < 0 or size > 64 * 1024 * 1024:
            raise ObjectStoreError("existing object is outside verification bounds")
        response = self.client.get_object(self.bucket, key)
        try:
            body = response.read(size + 1)
        finally:
            close = getattr(response, "close", None)
            release = getattr(response, "release_conn", None)
            if callable(close):
                close()
            if callable(release):
                release()
        if len(body) != size:
            raise ObjectStoreError("existing object read verification failed")
        return body, stat

    def _put_immutable(
        self,
        *,
        key: str,
        body: bytes,
        metadata: Mapping[str, str],
        fence: storage.LeaseWriteFence,
    ) -> StoredPage:
        self._require_fence(fence, key)
        digest = hashlib.sha256(body).hexdigest()
        existing = self._read_existing(key)
        if existing is not None:
            existing_body, stat = existing
            if hashlib.sha256(existing_body).hexdigest() != digest:
                raise ObjectStoreError("immutable object contains divergent content")
            return StoredPage(
                key=key,
                sha256=digest,
                etag=str(getattr(stat, "etag", ""))[:128],
                size=len(existing_body),
            )
        result = self.client.put_object(
            self.bucket,
            key,
            io.BytesIO(body),
            len(body),
            content_type="application/json",
            metadata=metadata,
        )
        verified = self._read_existing(key)
        if verified is None:
            raise ObjectStoreError("object-store write was not visible after persistence")
        persisted_body, stat = verified
        size = len(persisted_body)
        if size != len(body) or hashlib.sha256(persisted_body).hexdigest() != digest:
            raise ObjectStoreError("object-store write verification failed")
        etag = str(getattr(result, "etag", "") or getattr(stat, "etag", ""))[:128]
        return StoredPage(key=key, sha256=digest, etag=etag, size=size)

    def put_page(
        self,
        *,
        county: str,
        instrument_type: str,
        instrument_type_id: int,
        page: int,
        platform: str,
        document: Mapping[str, Any],
        fence: storage.LeaseWriteFence,
    ) -> StoredPage:
        if instrument_type_id < 1 or page < 0:
            raise ObjectStoreError("object identity is invalid")
        body = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        key = self.page_key(
            county=county,
            instrument_type=instrument_type,
            page=page,
            platform=platform,
        )
        digest = hashlib.sha256(body).hexdigest()
        metadata = {
            "county": _slug(county),
            "instrument-type": _slug(instrument_type),
            "page": str(page),
            "record-count": str(len(document.get("records") or [])),
            "sha256": digest,
        }
        return self._put_immutable(
            key=key, body=body, metadata=metadata, fence=fence
        )

    def put_canary(
        self, *, canary_id: str, fence: storage.LeaseWriteFence
    ) -> StoredPage:
        key = self.canary_key(canary_id)
        return self._put_immutable(
            key=key,
            body=self._canary_body(canary_id),
            metadata={"purpose": "acceptance-canary", "schema-version": "1"},
            fence=fence,
        )

    def verify_canary(self, canary_id: str) -> StoredPage:
        key = self.canary_key(canary_id)
        expected = self._canary_body(canary_id)
        existing = self._read_existing(key)
        if existing is None or existing[0] != expected:
            raise ObjectStoreError("acceptance canary object verification failed")
        body, stat = existing
        return StoredPage(
            key=key,
            sha256=hashlib.sha256(body).hexdigest(),
            etag=str(getattr(stat, "etag", ""))[:128],
            size=len(body),
        )

    def remove_canary(self, canary_id: str) -> None:
        self.client.remove_object(self.bucket, self.canary_key(canary_id))

    def roundtrip(self) -> None:
        """Backward-compatible read-only alias; writes require queue fencing."""

        self.probe()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("provision", "probe", "roundtrip"))
    args = parser.parse_args()
    store = PageObjectStore()
    getattr(store, args.action)()
    print(json.dumps({"ok": True, "action": args.action}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
