"""Ingest orchestrator: fetch -> extract -> KG -> vectors.

Called by `ingest.py` CLI (at repo root).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable, Iterator

from qdrant_client.http import models as qm
from rich.console import Console

from bountybrain.clients import embeddings
from bountybrain.clients import qdrant as qc
from bountybrain.config import settings
from bountybrain.ingestion.chunker import chunk_text
from bountybrain.ingestion.extractor import ReportExtraction, extract
from bountybrain.ingestion.sources import (
    RawReport,
    fetch_hackerone,
    fetch_pentesterland,
    fetch_portswigger,
    fetch_seed,
)
from bountybrain.kg.db import Session, init_db
from bountybrain.kg.models import (
    CVE,
    Report,
    ReportBypassesReport,
    ReportExploitsVuln,
    ReportReferencesCVE,
    ReportTargetsTech,
    ReportUsesTechnique,
    ReportUsesTool,
    Target,
    Technique,
    Tool,
    Vulnerability,
)
from bountybrain.kg.queries import link, upsert

console = Console()

SOURCE_FETCHERS: dict[str, Callable[[int], Iterator[RawReport]]] = {
    "seed": lambda _n: fetch_seed(),
    "pentesterland": fetch_pentesterland,
    "portswigger": fetch_portswigger,
    "hackerone": fetch_hackerone,
}


def _point_id(url: str, chunk_idx: int) -> str:
    h = hashlib.sha1(f"{url}::{chunk_idx}".encode()).hexdigest()
    return h[:32]


def _cache_report(raw: RawReport, ext: ReportExtraction) -> None:
    Path(settings.corpus_cache_dir).mkdir(parents=True, exist_ok=True)
    fname = hashlib.sha1(raw.url.encode()).hexdigest()[:16] + ".json"
    payload = {
        "source": raw.source,
        "url": raw.url,
        "title": raw.title,
        "date": raw.date.isoformat() if raw.date else None,
        "program": raw.program,
        "bounty": raw.bounty,
        "severity": raw.severity,
        "raw_markdown": raw.raw_markdown,
        "extraction": ext.model_dump(),
    }
    (settings.corpus_cache_dir / fname).write_text(json.dumps(payload, indent=2))


def _persist(raw: RawReport, ext: ReportExtraction) -> int:
    """Insert (or return existing id for) the report + KG edges."""
    with Session() as s:
        existing = s.query(Report).filter(Report.url == raw.url).one_or_none()
        if existing:
            return existing.id
        r = Report(
            source=raw.source,
            url=raw.url,
            title=raw.title,
            date=raw.date,
            program=raw.program,
            bounty=raw.bounty,
            severity=raw.severity,
            raw_markdown=raw.raw_markdown,
            difficulty=ext.difficulty,
            key_takeaway=ext.key_takeaway,
            root_cause=ext.root_cause,
            payloads_json=json.dumps(ext.payloads),
        )
        s.add(r)
        s.flush()

        v = upsert(s, Vulnerability, "name", ext.vuln_type)
        link(s, ReportExploitsVuln, report_id=r.id, vuln_id=v.id)
        for t in ext.techniques:
            te = upsert(s, Technique, "name", t)
            link(s, ReportUsesTechnique, report_id=r.id, technique_id=te.id)
        for t in ext.tools_used:
            to = upsert(s, Tool, "name", t)
            link(s, ReportUsesTool, report_id=r.id, tool_id=to.id)
        for tt in ext.target_tech:
            tg = upsert(s, Target, "name", tt)
            link(s, ReportTargetsTech, report_id=r.id, target_id=tg.id)
        for c in ext.cve_ids:
            cv = upsert(
                s,
                CVE,
                "cve_id",
                c,
                year=int(c.split("-")[1]) if c.startswith("CVE-") else None,
            )
            link(s, ReportReferencesCVE, report_id=r.id, cve_id=cv.id)
        # Bypass links deferred: prior report may not be ingested yet.
        # We resolve them in a second pass after all reports are in.
        return r.id


def _resolve_bypass_links() -> None:
    with Session() as s:
        reports = s.query(Report).all()
        by_url = {r.url: r.id for r in reports}
        for r in reports:
            try:
                data = json.loads(r.payloads_json or "[]")
            except Exception:
                data = []
            # bypass urls live in cache, not on the row; re-read from cache
            fname = hashlib.sha1(r.url.encode()).hexdigest()[:16] + ".json"
            fp = settings.corpus_cache_dir / fname
            if not fp.exists():
                continue
            ext = json.loads(fp.read_text()).get("extraction", {})
            for burl in ext.get("bypasses_report_urls", []):
                if burl in by_url and by_url[burl] != r.id:
                    link(
                        s,
                        ReportBypassesReport,
                        report_id=r.id,
                        bypassed_report_id=by_url[burl],
                    )


def _embed_and_store(report_id: int, raw: RawReport, ext: ReportExtraction) -> None:
    chunks = chunk_text(raw.raw_markdown)
    if not chunks:
        return
    vectors = embeddings.embed(chunks)
    points = []
    for i, (chunk, vec) in enumerate(zip(chunks, vectors)):
        points.append(
            qm.PointStruct(
                id=_point_id(raw.url, i),
                vector=vec,
                payload={
                    "report_id": report_id,
                    "chunk_idx": i,
                    "text": chunk,
                    "vuln_type": ext.vuln_type,
                    "difficulty": ext.difficulty,
                    "source": raw.source,
                    "url": raw.url,
                    "title": raw.title,
                    "date": raw.date.isoformat() if raw.date else None,
                },
            )
        )
    qc.upsert_points(points)


def run(
    sources: list[str],
    limit_per_source: int,
    use_llm: bool = True,
    embed: bool = True,
) -> dict:
    init_db()
    seen = 0
    for src in sources:
        fetcher = SOURCE_FETCHERS.get(src)
        if not fetcher:
            console.print(f"[yellow]Unknown source: {src}[/yellow]")
            continue
        console.print(f"[cyan]Fetching from {src} (limit {limit_per_source})[/cyan]")
        for raw in fetcher(limit_per_source):
            try:
                ext = extract(raw.title, raw.url, raw.raw_markdown, use_llm=use_llm)
                _cache_report(raw, ext)
                rid = _persist(raw, ext)
                if embed:
                    _embed_and_store(rid, raw, ext)
                seen += 1
                console.print(f"  ✓ {raw.title[:80]}")
            except Exception as e:
                console.print(f"  [red]! {raw.title[:60]}: {e}[/red]")
    _resolve_bypass_links()
    console.print(f"[green]Ingested {seen} reports total[/green]")
    return {"ingested": seen}
