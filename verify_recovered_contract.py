#!/usr/bin/env python3
"""Verify recovered Worker evidence without emitting source, values, or records."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CONTRACT = ROOT / "migration_contract.json"
ROUTES = ROOT / "evidence" / "route_contract.json"
STRICT_SOURCE = Path("/mnt/cf_kv_r2/workers/shadowglass-v35/source/index.js")
STRICT_BINDINGS = Path("/mnt/cf_kv_r2/workers/shadowglass-v35/bindings.json")
STRICT_SETTINGS = Path("/mnt/cf_kv_r2/workers/shadowglass-v35/settings.json")
STRICT_MANIFEST = Path("/mnt/cf_kv_r2/workers/shadowglass-v35/manifest.json")
STRICT_ROOT = STRICT_SOURCE.parent.parent


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def tree_digest(root: Path) -> tuple[int, str]:
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    hasher = hashlib.sha256()
    for path in files:
        name = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        hasher.update(len(name).to_bytes(4, "big"))
        hasher.update(name)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return len(files), hasher.hexdigest()


def main() -> int:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    route_contract = json.loads(ROUTES.read_text(encoding="utf-8"))
    expected = contract["provenance"]
    tree_count, recovered_tree_digest = tree_digest(STRICT_ROOT)
    checks = {
        "strict_source": digest(STRICT_SOURCE)
        == expected["strict_recovered_bundle"]["sha256"],
        "bindings": digest(STRICT_BINDINGS) == expected["bindings_metadata_sha256"],
        "settings": digest(STRICT_SETTINGS) == expected["settings_metadata_sha256"],
        "manifest": digest(STRICT_MANIFEST) == expected["manifest_metadata_sha256"],
        "recovered_tree": (
            tree_count == expected["recovered_tree_file_count"]
            and recovered_tree_digest == expected["recovered_tree_sha256"]
            and expected["recovered_tree_hash_algorithm"]
            == "sha256(length-prefixed-relative-path-and-bytes-v1)"
        ),
    }
    source = STRICT_SOURCE.read_text(encoding="utf-8", errors="strict")
    checks["fetch_handler"] = bool(re.search(r"\bfetch\s*\(", source))
    checks["queue_handler"] = bool(re.search(r"\bqueue\s*\(", source))
    checks["scheduled_handler"] = bool(re.search(r"\bscheduled\s*\(", source))
    route_presence: list[bool] = []
    for route in route_contract["routes"]:
        static = str(route["path"]).split("/{", 1)[0]
        route_presence.append(static in source)
    checks["all_route_literals_present"] = all(route_presence)
    checks["route_count"] = len(route_contract["routes"]) == 17
    if not all(checks.values()):
        raise SystemExit("recovered contract verification failed")
    print(
        json.dumps(
            {
                "ok": True,
                "checks": len(checks),
                "route_literals": sum(route_presence),
                "route_contract_sha256": digest(ROUTES),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
