from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "ae46a39a494e01049ce0bc6ca0fb25cec07e7f5f7e853edd645bba1da0cd410e"
CATALOG_SHA = "f152b35554706e35f989524d52910077ca746e6f67a19a65039dd9686e382ab7"


def test_v1_auditor_sidecars_are_internally_exact() -> None:
    route = json.loads((ROOT / "evidence" / "route_contract.json").read_text())
    migration = json.loads((ROOT / "migration_contract.json").read_text())
    assert route["contract_source_sha256"] == SOURCE_SHA
    assert route["source_route_extractor"] == "dispatch_conditions_v1"
    assert route["source_count"] == route["target_count"] == route["tested_count"] == len(route["routes"]) == 17
    assert migration["provenance"]["canonical_catalog_source"]["sha256"] == CATALOG_SHA
    assert migration["provenance"]["strict_recovered_bundle"]["sha256"] == SOURCE_SHA
    assert migration["runtime"]["service_dir"] == "/home/forge/shadowglass-v7-command"
    assert migration["runtime"]["api_unit"] == "shadowglass-v7-command.service"
    assert migration["routes"] == {
        "contract_path": "evidence/route_contract.json",
        "source_count": 17,
        "target_count": 17,
        "tested_count": 17,
        "coverage": 1.0,
        "omissions": [],
    }
