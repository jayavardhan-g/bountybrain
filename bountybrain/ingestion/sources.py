"""Source fetchers for disclosed bug bounty reports.

Each fetcher yields `RawReport` items — normalized minimal metadata plus
raw markdown body. Rate-limited via `settings.fetch_delay_seconds`.

To keep this repo self-contained, we ship a small seed corpus at
`bountybrain/seed/reports.json`. That's what `--source seed` reads. The
live scrapers exist and follow the required layouts (RSS/JSON where the
source provides them), but you can always run without hitting the network.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterator

import feedparser
import httpx
from bs4 import BeautifulSoup
from markdownify import markdownify

from bountybrain.config import settings


@dataclass
class RawReport:
    source: str
    url: str
    title: str
    date: date | None
    program: str | None
    bounty: float | None
    severity: str | None
    raw_markdown: str


def _polite_sleep() -> None:
    time.sleep(settings.fetch_delay_seconds)


def _clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    main = soup.find("article") or soup.find("main") or soup.body or soup
    return markdownify(str(main), heading_style="ATX").strip()


def fetch_seed() -> Iterator[RawReport]:
    """Load the bundled seed corpus. Always works offline."""
    seed_path = Path(__file__).resolve().parents[1] / "seed" / "reports.json"
    payload = json.loads(seed_path.read_text(encoding="utf-8"))
    for r in payload:
        yield RawReport(
            source="seed",
            url=r["url"],
            title=r["title"],
            date=date.fromisoformat(r["date"]) if r.get("date") else None,
            program=r.get("program"),
            bounty=r.get("bounty"),
            severity=r.get("severity"),
            raw_markdown=r["raw_markdown"],
        )


def fetch_pentesterland(limit: int) -> Iterator[RawReport]:
    """Pentester.land — read the JSON feed and follow report links."""
    feed_url = "https://pentester.land/writeups.json"
    try:
        r = httpx.get(feed_url, timeout=30)
        r.raise_for_status()
    except Exception:
        return
    data = r.json()
    count = 0
    for item in data.get("data", []):
        if count >= limit:
            break
        for link in item.get("Links", []):
            url = link.get("Link")
            if not url:
                continue
            try:
                page = httpx.get(url, timeout=30, follow_redirects=True)
                if page.status_code != 200:
                    continue
                md = _clean_html(page.text)
                yield RawReport(
                    source="pentesterland",
                    url=url,
                    title=link.get("Title") or item.get("Title") or url,
                    date=_parse_date(item.get("PublicationDate")),
                    program=(item.get("Programs") or [None])[0],
                    bounty=_parse_bounty(item.get("Bounty")),
                    severity=None,
                    raw_markdown=md,
                )
                count += 1
                _polite_sleep()
                if count >= limit:
                    break
            except Exception:
                continue


def fetch_portswigger(limit: int) -> Iterator[RawReport]:
    """PortSwigger Research blog RSS."""
    feed = feedparser.parse("https://portswigger.net/research/rss")
    count = 0
    for entry in feed.entries:
        if count >= limit:
            break
        try:
            page = httpx.get(entry.link, timeout=30, follow_redirects=True)
            if page.status_code != 200:
                continue
            md = _clean_html(page.text)
            yield RawReport(
                source="portswigger",
                url=entry.link,
                title=entry.title,
                date=_parse_date(getattr(entry, "published", None)),
                program=None,
                bounty=None,
                severity=None,
                raw_markdown=md,
            )
            count += 1
            _polite_sleep()
        except Exception:
            continue


def fetch_hackerone(limit: int) -> Iterator[RawReport]:
    """HackerOne Hacktivity — public disclosed reports via their GraphQL/JSON.

    We use the public hacktivity JSON endpoint. Anything that requires auth
    is skipped. Follow the linked disclosed report page for the body.
    """
    api = "https://hackerone.com/graphql"
    # A minimal request against the public schema — best-effort; if the
    # endpoint layout changes, ingest simply yields nothing and falls back
    # to the seed corpus.
    query = {
        "query": (
            "query{hacktivity_items(first:%d,order_by:{field:disclosed_at,direction:DESC}){"
            "edges{node{... on Disclosed{reporter{username} team{name} report{title url}}}}"
            "}}" % limit
        )
    }
    try:
        r = httpx.post(api, json=query, timeout=30)
        r.raise_for_status()
        edges = r.json()["data"]["hacktivity_items"]["edges"]
    except Exception:
        return
    for e in edges:
        node = e.get("node", {}).get("report") or {}
        url = node.get("url")
        title = node.get("title")
        if not url or not title:
            continue
        try:
            page = httpx.get(url, timeout=30, follow_redirects=True)
            if page.status_code != 200:
                continue
            md = _clean_html(page.text)
            yield RawReport(
                source="hackerone",
                url=url,
                title=title,
                date=None,
                program=(e.get("node", {}).get("team") or {}).get("name"),
                bounty=None,
                severity=None,
                raw_markdown=md,
            )
            _polite_sleep()
        except Exception:
            continue


def _parse_date(v) -> date | None:
    if not v:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S GMT"):
        try:
            return datetime.strptime(v, fmt).date()
        except Exception:
            continue
    try:
        return date.fromisoformat(v[:10])
    except Exception:
        return None


def _parse_bounty(v) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).replace("$", "").replace(",", "").strip()
    try:
        return float(s)
    except ValueError:
        return None
