from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import scraper
import storage


CONTEXT = storage.JobContext(
    1,
    "Midland",
    "https://county.example/publicsearch",
    "PublicSearch",
    2,
    "Deed of Trust",
)


def test_public_search_url_is_zero_based_and_internal() -> None:
    url = scraper.public_search_url(CONTEXT, 2)
    assert url.startswith("https://county.example/publicsearch/results?")
    assert "offset=100" in url and "limit=50" in url
    assert "searchType=Deed+of+Trust" in url


def test_public_search_extracted_and_html_fallback_normalization() -> None:
    extracted = {
        "html": "<p>1-1 of 75 results</p>",
        "extracted": [
            {
                "text": (
                    "Grantor\tGrantee\tDeed\t2026-01-02\tDOC-1\t12/34\tLot 1"
                )
            }
        ],
    }
    records, total = scraper.parse_public_search(extracted)
    assert total == 75 and records[0]["id"] == "DOC-1"
    html = """
    <p>Showing 1-1 of 1 results</p><table><tbody>
      <tr data-document-id="DOC-2"><td>x</td><td>x</td><td>x</td>
      <td>A</td><td>B</td><td>Deed</td><td>2025-01-01</td>
      <td>DOC-2</td><td>1/2</td><td>Section 3</td></tr>
    </tbody></table>
    """
    records, total = scraper.parse_public_search({"content": html})
    assert total == 1 and records[0]["legalDescription"] == "Section 3"


class FakeRelay:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def browse(self, url: str, wait_for: str) -> dict[str, Any]:
        self.urls.append(url)
        assert wait_for == "table tbody tr"
        return {
            "html": "<p>1-1 of 1 results</p>",
            "extracted": [{"text": "A\tB\tDeed\t2026-01-01\t1\t1/1\tLot"}],
        }


def test_public_discovery_and_scrape_use_browser_relay() -> None:
    relay = FakeRelay()
    worker = scraper.Scraper(relay)  # type: ignore[arg-type]
    assert worker.discover(CONTEXT) == scraper.Discovery(1, 1)
    pages = worker.scrape(CONTEXT, 0, 0)
    assert pages[0].page == 0 and pages[0].records[0]["id"] == "1"
    assert len(relay.urls) == 2


def test_tyler_chunks_are_newest_first_nonoverlapping_and_bounded() -> None:
    chunks = scraper._tyler_chunks(date(2000, 4, 1))
    assert chunks[0][1] == date(2000, 4, 1)
    assert chunks[-1][0] == date(2000, 1, 1)
    for older, newer in zip(chunks[1:], chunks[:-1], strict=True):
        assert older[1] == newer[0] - timedelta(days=1)


def test_page_document_contains_recovered_envelope() -> None:
    page = scraper.ScrapedPage(0, [{"id": "1"}], 1, 1)
    document = scraper.page_document(CONTEXT, page)
    assert set(document) == {
        "county",
        "instrumentType",
        "page",
        "records",
        "totalFound",
        "domTotal",
        "timestamp",
    }
