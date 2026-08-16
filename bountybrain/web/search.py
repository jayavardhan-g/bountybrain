"""Live web search restricted to bounty-relevant domains (Brave API).

Optionally persists each fetched result into the local corpus so future
runs treat it like an ingested report.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Iterable

import httpx
from bs4 import BeautifulSoup
from markdownify import markdownify

from bountybrain.clients.llm import chat, load_prompt
from bountybrain.config import settings
from bountybrain.ingestion.extractor import extract
from bountybrain.ingestion.pipeline import _cache_report, _embed_and_store, _persist
from bountybrain.ingestion.sources import RawReport

DEFAULT_DOMAINS = [
    "hackerone.com",
    "bugcrowd.com",
    "pentester.land",
    "portswigger.net",
    "github.com",
]

BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"


@dataclass
class WebHit:
    url: str
    title: str
    snippet: str
    summary_md: str | None = None


def _brave(query: str, count: int) -> list[WebHit]:
    if not settings.brave_api_key:
        return []
    site_filter = " OR ".join(f"site:{d}" for d in DEFAULT_DOMAINS)
    full = f"({site_filter}) {query}"
    headers = {"X-Subscription-Token": settings.brave_api_key, "Accept": "application/json"}
    resp = httpx.get(
        BRAVE_ENDPOINT, params={"q": full, "count": count}, headers=headers, timeout=20
    )
    resp.raise_for_status()
    data = resp.json()
    hits = []
    for r in data.get("web", {}).get("results", []):
        hits.append(WebHit(url=r["url"], title=r.get("title", ""), snippet=r.get("description", "")))
    return hits


def _fetch_markdown(url: str) -> str:
    r = httpx.get(url, timeout=20, follow_redirects=True)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    main = soup.find("article") or soup.find("main") or soup.body or soup
    return markdownify(str(main), heading_style="ATX").strip()


def live_search(query: str, count: int = 5, persist: bool = False) -> list[WebHit]:
    hits = _brave(query, count=count)
    for h in hits:
        try:
            body = _fetch_markdown(h.url)
            summary = chat(
                system="You summarize security write-ups.",
                user=load_prompt("web_summary", url=h.url, title=h.title, content=body[:6000]),
            )
            h.summary_md = summary
            if persist:
                raw = RawReport(
                    source="web",
                    url=h.url,
                    title=h.title,
                    date=date.today(),
                    program=None,
                    bounty=None,
                    severity=None,
                    raw_markdown=body,
                )
                ext = extract(h.title, h.url, body)
                _cache_report(raw, ext)
                rid = _persist(raw, ext)
                _embed_and_store(rid, raw, ext)
        except Exception:
            continue
    return hits
