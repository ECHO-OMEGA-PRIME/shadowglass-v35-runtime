"""Recovered PublicSearch and Tyler adapters with bounded, pinned networking."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import math
import random
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from datetime import date, timedelta, timezone, datetime
from email.message import Message
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any, Callable, Iterable, Mapping

import storage
from relay import RelayClient


MAX_RESPONSE_BYTES = 8_000_000
USER_AGENT = "ShadowGlass-v8-Forge/9"


class ScrapeError(RuntimeError):
    """A remote response cannot be safely normalized or persisted."""


@dataclass(frozen=True, slots=True)
class Discovery:
    total_records: int
    page_count: int


@dataclass(frozen=True, slots=True)
class ScrapedPage:
    page: int
    records: list[dict[str, str]]
    total_found: int
    dom_total: int


def _clean(value: str) -> str:
    return " ".join(value.replace("\xa0", " ").split())


def _fallback_id(values: Iterable[str]) -> str:
    joined = "\x1f".join(values).encode("utf-8", "ignore")
    return "generated-" + hashlib.sha256(joined).hexdigest()[:24]


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[tuple[dict[str, str], list[str]]] = []
        self.text: list[str] = []
        self._row: list[str] | None = None
        self._attrs: dict[str, str] = {}
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "tr":
            self._row = []
            self._attrs = {key.casefold(): value or "" for key, value in attrs}
        elif tag.casefold() == "td" and self._row is not None:
            self._cell = []

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "td" and self._cell is not None and self._row is not None:
            self._row.append(_clean(" ".join(self._cell)))
            self._cell = None
        elif tag.casefold() == "tr" and self._row is not None:
            self.rows.append((self._attrs, self._row))
            self._row = None


def _public_record(cells: list[str], attrs: Mapping[str, str]) -> dict[str, str] | None:
    if len(cells) >= 10:
        values = cells[3:10]
    elif len(cells) >= 7:
        values = cells[:7]
    else:
        return None
    grantor, grantee, kind, recorded, document, book_page, legal = values
    if not (grantor or grantee or kind):
        return None
    external_id = next(
        (
            attrs.get(name, "")
            for name in ("data-id", "data-doc-id", "data-document-id")
            if attrs.get(name)
        ),
        document,
    ) or _fallback_id(values)
    return {
        "id": external_id,
        "grantor": grantor,
        "grantee": grantee,
        "instrumentType": kind,
        "recordedDate": recorded,
        "filingDate": recorded,
        "bookPage": book_page,
        "legalDescription": legal,
        "consideration": "",
    }


def parse_public_search(payload: Mapping[str, Any]) -> tuple[list[dict[str, str]], int]:
    """Normalize relay extraction or HTML and derive the result total."""

    if payload.get("error"):
        raise ScrapeError("relay reported a browser error")
    records: list[dict[str, str]] = []
    extracted = payload.get("extracted")
    if isinstance(extracted, list):
        for item in extracted:
            text = item.get("text") if isinstance(item, Mapping) else None
            if isinstance(text, str):
                record = _public_record([_clean(value) for value in text.split("\t")], {})
                if record is not None:
                    records.append(record)
    html = payload.get("html") or payload.get("content")
    if not isinstance(html, str) or not html.strip():
        if records:
            return records, len(records)
        raise ScrapeError("relay response contains no usable HTML")
    parser = _TableParser()
    parser.feed(html)
    if not records:
        records = [
            record
            for attrs, cells in parser.rows
            if (record := _public_record(cells, attrs)) is not None
        ]
    text = _clean(" ".join(parser.text))
    total = 0
    patterns = (
        r"\b\d+\s*-\s*\d+\s+of\s+([\d,]+)\s+results\b",
        r"\b(?:total|found|showing)\D{0,20}([\d,]+)\s+(?:results|records|documents)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            total = int(match.group(1).replace(",", ""))
            break
    return records, max(total, len(records))


def public_search_url(context: storage.JobContext, page: int) -> str:
    if page < 0:
        raise ScrapeError("PublicSearch page index is invalid")
    parsed = urllib.parse.urlsplit(context.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScrapeError("county base URL is invalid")
    path = parsed.path.rstrip("/") + "/results"
    query = urllib.parse.urlencode(
        {
            "department": "RP",
            "limit": "50",
            "offset": str(page * 50),
            "recordedDateRange": ",",
            "searchOcrText": "false",
            "searchType": context.instrument_type,
        }
    )
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "a":
            values = dict(attrs)
            if values.get("href"):
                self.links.append(str(values["href"]))


class _TylerRows(HTMLParser):
    def __init__(self, origin: str) -> None:
        super().__init__(convert_charrefs=True)
        self.origin = origin
        self.rows: list[dict[str, str]] = []
        self._depth = 0
        self._row: dict[str, str] | None = None
        self._heading: list[str] | None = None
        self._li: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        classes = set(values.get("class", "").split())
        if tag.casefold() == "li" and "ss-search-row" in classes:
            self._row = {"_documentid": values.get("data-documentid", "")}
            self._depth = 1
            return
        if self._row is None:
            return
        self._depth += 1
        if tag.casefold() == "h1":
            self._heading = []
        elif tag.casefold() == "li":
            self._li = []
        elif tag.casefold() == "a" and "/document/" in values.get("href", ""):
            self._row["pdfUrl"] = urllib.parse.urljoin(self.origin, values["href"])

    def handle_data(self, data: str) -> None:
        if self._heading is not None:
            self._heading.append(data)
        if self._li is not None:
            self._li.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._row is None:
            return
        if tag.casefold() == "h1" and self._heading is not None:
            heading = _clean(" ".join(self._heading))
            pieces = [piece.strip() for piece in re.split(r"[•·]", heading, maxsplit=1)]
            self._row["id"] = pieces[0] if pieces else ""
            if len(pieces) > 1:
                self._row["instrumentType"] = pieces[1]
            self._heading = None
        elif tag.casefold() == "li" and self._li is not None:
            text = _clean(" ".join(self._li))
            label, separator, value = text.partition(":")
            if separator:
                key = label.casefold().strip()
                if "recording date" in key:
                    self._row["recordedDate"] = value.strip()
                    self._row["filingDate"] = value.strip()
                elif key == "grantor":
                    self._row["grantor"] = value.strip()
                elif key == "grantee":
                    self._row["grantee"] = value.strip()
                elif "legal" in key:
                    self._row["legalDescription"] = value.strip()
                elif "book" in key and "page" in key:
                    self._row["bookPage"] = value.strip()
            self._li = None
        self._depth -= 1
        if self._depth == 0:
            record = self._row
            record["id"] = record.get("id") or record.pop("_documentid", "")
            record["instrumentType"] = record.get("instrumentType", "")
            record["consideration"] = ""
            if record.get("id") and record.get("grantor") and record.get("recordedDate"):
                record.pop("_documentid", None)
                self.rows.append(record)
            self._row = None


def _addresses(host: str, port: int) -> frozenset[str]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScrapeError("county origin DNS resolution failed") from exc
    result = frozenset(answer[4][0] for answer in answers)
    if not result or any(not ipaddress.ip_address(value).is_global for value in result):
        raise ScrapeError("county origin did not resolve exclusively to public addresses")
    return result


class PinnedSession:
    """Cookie-bearing direct HTTP session connected only to pinned public IPs."""

    def __init__(self, base_url: str, timeout: float = 30) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScrapeError("county origin is invalid")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.origin = urllib.parse.urlunsplit(
            (self.scheme, parsed.netloc, "", "", "")
        )
        self.addresses = _addresses(self.host, self.port)
        self.timeout = max(1.0, min(timeout, 60.0))
        self.cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        redirects: int = 5,
    ) -> tuple[int, Message, bytes]:
        if _addresses(self.host, self.port) != self.addresses:
            raise ScrapeError("county origin DNS changed during session")
        target = urllib.parse.urlsplit(urllib.parse.urljoin(self.origin, path))
        if target.hostname != self.host or target.scheme != self.scheme:
            raise ScrapeError("county request escaped its validated origin")
        request_headers = {"User-Agent": USER_AGENT, "Host": self.host}
        request_headers.update(headers or {})
        if self.cookies:
            request_headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(self.cookies.items())
            )
        last_error: Exception | None = None
        for address in sorted(self.addresses):
            connection: http.client.HTTPConnection | None = None
            try:
                transport = socket.create_connection(
                    (address, self.port), timeout=self.timeout
                )
                if self.scheme == "https":
                    transport = ssl.create_default_context().wrap_socket(
                        transport, server_hostname=self.host
                    )
                connection = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout
                )
                connection.sock = transport
                relative = urllib.parse.urlunsplit(("", "", target.path or "/", target.query, ""))
                connection.request(method, relative, body=body, headers=request_headers)
                response = connection.getresponse()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ScrapeError("county response exceeded the byte limit")
                cookie = SimpleCookie()
                for value in response.headers.get_all("Set-Cookie") or []:
                    cookie.load(value)
                for name, morsel in cookie.items():
                    self.cookies[name] = morsel.value
                if 300 <= response.status < 400:
                    if redirects <= 0:
                        raise ScrapeError("county redirect limit exceeded")
                    location = response.headers.get("Location", "")
                    return self.request(
                        "GET",
                        urllib.parse.urljoin(self.origin, location),
                        headers=headers,
                        redirects=redirects - 1,
                    )
                return int(response.status), response.headers, raw
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
            finally:
                if connection is not None:
                    connection.close()
        raise ScrapeError("county request failed") from last_error


def _tyler_chunks(today: date | None = None) -> list[tuple[date, date]]:
    end = today or date.today()
    floor = date(2000, 1, 1)
    chunks = []
    while end >= floor:
        start = max(floor, end - timedelta(days=89))
        chunks.append((start, end))
        end = start - timedelta(days=1)
    return chunks


class TylerAdapter:
    def __init__(self, context: storage.JobContext) -> None:
        self.context = context
        self.session = PinnedSession(context.base_url)
        base_path = "/recorder/web" if "/recorder/" in urllib.parse.urlsplit(context.base_url).path else "/web"
        self.base_path = base_path
        self.search_path = ""

    def _require(self, status: int, raw: bytes, label: str) -> str:
        if not 200 <= status < 300:
            raise ScrapeError(f"Tyler {label} returned non-success")
        return raw.decode("utf-8", "replace")

    def initialize(self) -> None:
        ajax = {"ajaxRequest": "true", "X-Requested-With": "XMLHttpRequest"}
        status, _, raw = self.session.request("GET", f"{self.base_path}/user/disclaimer")
        self._require(status, raw, "disclaimer")
        status, _, raw = self.session.request(
            "POST", f"{self.base_path}/user/disclaimer", headers=ajax, body=b""
        )
        self._require(status, raw, "disclaimer acceptance")
        status, _, raw = self.session.request("GET", f"{self.base_path}/")
        self._require(status, raw, "home")
        status, _, raw = self.session.request(
            "POST", f"{self.base_path}/homeActions", headers=ajax, body=b""
        )
        parser = _LinkParser()
        parser.feed(self._require(status, raw, "home actions"))
        action = next(
            (href for href in parser.links if "/action/" in href and "ACTIONGROUP" in href.upper()),
            "",
        )
        if not action:
            raise ScrapeError("Tyler action group is unavailable")
        status, _, raw = self.session.request("GET", action)
        parser = _LinkParser()
        parser.feed(self._require(status, raw, "action group"))
        search = next(
            (href for href in parser.links if "/search/" in href and "DOCSEARCH" in href.upper()),
            "",
        )
        if not search:
            raise ScrapeError("Tyler document search module is unavailable")
        self.search_path = search
        status, _, raw = self.session.request("GET", search)
        self._require(status, raw, "search form")

    def _submit_search(self, start: date, end: date) -> tuple[str, int, dict[str, str]]:
        """Submit one bounded search and validate Tyler's JSON envelope."""

        if not self.search_path:
            raise ScrapeError("Tyler search session is not initialized")
        action_id = urllib.parse.urlsplit(self.search_path).path.rstrip("/").split("/")[-1]
        fields = {
            "field_BothNamesID": "",
            "field_GrantorID": "",
            "field_GranteeID": "",
            "field_RecordingDateID_DOT_StartDate": start.strftime("%m/%d/%Y"),
            "field_RecordingDateID_DOT_EndDate": end.strftime("%m/%d/%Y"),
            "field_DocumentNumberID": "",
            "field_BookPageID_DOT_Book": "",
            "field_BookPageID_DOT_Volume": "",
            "field_BookPageID_DOT_Page": "",
            "field_PlattedLegalID_DOT_Subdivision": "",
            "field_PlattedLegalID_DOT_Lot": "",
            "field_PlattedLegalID_DOT_Block": "",
            "field_PlattedLegalID_DOT_Tract": "",
            "field_PlattedLegalID_DOT_Unit": "",
            "field_selfservice_documentTypes": self.context.instrument_type,
        }
        headers = {
            "ajaxRequest": "true",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": self.session.origin,
            "Referer": urllib.parse.urljoin(self.session.origin, self.search_path),
        }
        status, _, raw = self.session.request(
            "POST",
            f"{self.base_path}/searchPost/{urllib.parse.quote(action_id)}",
            headers=headers,
            body=urllib.parse.urlencode(fields).encode("ascii"),
        )
        if not 200 <= status < 300:
            raise ScrapeError("Tyler search submission returned non-success")
        try:
            search_result = json.loads(raw)
            total_pages = int(search_result["totalPages"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ScrapeError("Tyler search response is invalid") from exc
        if total_pages < 0:
            raise ScrapeError("Tyler search page count is invalid")
        return action_id, total_pages, headers

    def verify_live(self) -> bytes:
        """Exercise a benign future-date search plus result HTML request."""

        self.initialize()
        future = date.today() + timedelta(days=1)
        action_id, _, headers = self._submit_search(future, future)
        status, _, raw = self.session.request(
            "GET",
            f"{self.base_path}/searchResults/{urllib.parse.quote(action_id)}?page=1",
            headers={"Accept": "text/html", "Referer": headers["Referer"]},
        )
        html = self._require(status, raw, "verification result page")
        lowered = html.casefold()
        if "search" not in lowered or not any(
            marker in lowered for marker in ("result", "document", "no records", "no results")
        ):
            raise ScrapeError("Tyler verification page lacks provider semantics")
        parser = _TylerRows(self.session.origin)
        parser.feed(html)
        return raw

    def search(
        self, chunk_index: int, heartbeat: Callable[[], None] | None = None
    ) -> list[ScrapedPage]:
        chunks = _tyler_chunks()
        if not 0 <= chunk_index < len(chunks):
            raise ScrapeError("Tyler date chunk is outside the supported range")
        start, end = chunks[chunk_index]
        action_id, total_pages, headers = self._submit_search(start, end)
        pages: list[ScrapedPage] = []
        empty = 0
        for result_page in range(1, min(total_pages, 100) + 1):
            if heartbeat is not None:
                heartbeat()
            path = (
                f"{self.base_path}/searchResults/{urllib.parse.quote(action_id)}"
                f"?page={result_page}"
            )
            for attempt in range(3):
                status, _, raw = self.session.request(
                    "GET", path, headers={"Accept": "text/html", "Referer": headers["Referer"]}
                )
                if status != 500:
                    break
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
            if not 200 <= status < 300:
                raise ScrapeError("Tyler result page returned non-success")
            parser = _TylerRows(self.session.origin)
            parser.feed(raw.decode("utf-8", "replace"))
            empty = empty + 1 if not parser.rows else 0
            global_page = chunk_index * 1000 + result_page
            pages.append(
                ScrapedPage(global_page, parser.rows, total_pages * 50, total_pages * 50)
            )
            if empty >= 3:
                break
            time.sleep(random.uniform(0.5, 1.0))
        return pages


class Scraper:
    def __init__(self, relay: RelayClient | None = None) -> None:
        self.relay = relay or RelayClient(timeout_seconds=60)

    @staticmethod
    def is_tyler(context: storage.JobContext) -> bool:
        return "tyler" in context.platform.casefold()

    def discover(
        self,
        context: storage.JobContext,
        heartbeat: Callable[[], None] | None = None,
    ) -> Discovery:
        if heartbeat is not None:
            heartbeat()
        if self.is_tyler(context):
            adapter = TylerAdapter(context)
            adapter.initialize()
            if heartbeat is not None:
                heartbeat()
            pages = adapter.search(0, heartbeat)
            chunks = len(_tyler_chunks()) if any(page.records for page in pages) else 0
            return Discovery(chunks * 100, chunks)
        result = self.relay.browse(public_search_url(context, 0), "table tbody tr")
        if heartbeat is not None:
            heartbeat()
        records, total = parse_public_search(result)
        if total == 0 and not records:
            return Discovery(0, 0)
        return Discovery(total, math.ceil(total / 50))

    def scrape(
        self,
        context: storage.JobContext,
        start_page: int,
        end_page: int,
        heartbeat: Callable[[], None] | None = None,
    ) -> list[ScrapedPage]:
        if self.is_tyler(context):
            pages: list[ScrapedPage] = []
            for chunk in range(start_page, end_page + 1):
                adapter = TylerAdapter(context)
                adapter.initialize()
                pages.extend(adapter.search(chunk, heartbeat))
            return pages
        pages = []
        empty = 0
        for page in range(start_page, end_page + 1):
            if heartbeat is not None:
                heartbeat()
            result = self.relay.browse(public_search_url(context, page), "table tbody tr")
            records, total = parse_public_search(result)
            empty = empty + 1 if not records else 0
            pages.append(ScrapedPage(page, records, total, total))
            if page * 50 >= total or empty >= 3:
                break
            time.sleep(random.uniform(0.2, 0.5))
        return pages


def page_document(
    context: storage.JobContext, page: ScrapedPage
) -> dict[str, Any]:
    return {
        "county": context.county,
        "instrumentType": context.instrument_type,
        "page": page.page,
        "records": page.records,
        "totalFound": page.total_found,
        "domTotal": page.dom_total,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
