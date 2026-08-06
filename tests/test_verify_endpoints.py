from __future__ import annotations

from typing import Any

import verify_endpoints


class FakeRelay:
    def browse(self, url: str, wait_for: str) -> dict[str, str]:
        assert url.startswith("https://")
        assert wait_for == "table tbody tr"
        return {
            "html": (
                "<html><body data-provider='PublicSearch'>"
                "<form>department recordedDateRange searchType results</form>"
                "<table></table>" + (" " * 1_000) + "</body></html>"
            )
        }


def test_all_active_endpoint_families_are_verified(monkeypatch: Any) -> None:
    initialized: list[str] = []

    class FakeTyler:
        def __init__(self, context: Any) -> None:
            self.context = context

        def verify_live(self) -> bytes:
            initialized.append(self.context.county)
            return f"Tyler search results {self.context.county}".encode()

    monkeypatch.setattr(verify_endpoints, "TylerAdapter", FakeTyler)
    result = verify_endpoints.verify(relay=FakeRelay())
    assert result["active_count"] == 7
    assert result["ok"] is True
    assert result["publicsearch_count"] == 2
    assert result["tyler_count"] == 5
    assert len(result["counties"]) == 7
    assert all(len(item["evidence_sha256"]) == 64 for item in result["counties"])
    assert len(initialized) == 5


def test_publicsearch_empty_generic_table_is_rejected() -> None:
    try:
        verify_endpoints._verify_publicsearch(
            {"html": "<html><body><table></table></body></html>"}
        )
    except RuntimeError as exc:
        assert "provider" in str(exc)
    else:
        raise AssertionError("generic empty HTML must not activate an endpoint")
