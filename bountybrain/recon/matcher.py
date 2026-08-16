"""Match recon findings against the KG + RAG.

Strategy:
- `tech` findings -> KG lookup for reports whose `target_tech` matches.
- `cve` findings  -> KG lookup for reports referencing that CVE.
- `url`, `endpoint`, `subdomain`, `other` -> RAG query using the value as
  the query string.

Rank by RAG score, then by bounty of the matched report (higher first).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from bountybrain.kg.db import Session
from bountybrain.kg.models import Report
from bountybrain.kg.queries import kg_query
from bountybrain.rag.hybrid import search as rag_search

from .models import ReconFinding


def _report_meta(report_id: int) -> dict[str, Any]:
    with Session() as s:
        r = s.get(Report, report_id)
        if not r:
            return {}
        return {
            "id": r.id,
            "title": r.title,
            "url": r.url,
            "date": r.date.isoformat() if r.date else None,
            "bounty": r.bounty or 0,
            "severity": r.severity,
        }


def _match_one(f: ReconFinding, top_k: int) -> list[dict]:
    if f.type == "tech":
        return [
            {**r, "reason": f"target uses {f.value}"}
            for r in kg_query("target", f.value, "reports")[:top_k]
        ]
    if f.type == "cve":
        # small KG lookup: find any report row that references this cve
        from bountybrain.kg.models import CVE, ReportReferencesCVE
        from sqlalchemy import select

        with Session() as s:
            cve = s.execute(select(CVE).where(CVE.cve_id.ilike(f.value))).scalar_one_or_none()
            if not cve:
                return []
            rows = s.execute(
                select(Report)
                .join(ReportReferencesCVE, ReportReferencesCVE.report_id == Report.id)
                .where(ReportReferencesCVE.cve_id == cve.id)
            ).scalars()
            return [
                {**_report_meta(r.id), "reason": f"references {f.value}"} for r in rows
            ][:top_k]
    # RAG fallback
    q = f.value if f.type != "subdomain" else f"vulnerabilities in {f.value}"
    hits = rag_search(q, top_k=top_k).hits
    results = []
    for h in hits:
        meta = _report_meta(h.report_id) if h.report_id else {}
        if not meta:
            continue
        meta["reason"] = f"semantic match on {f.type}: {f.value[:80]}"
        meta["_score"] = h.score
        results.append(meta)
    return results


def _rank(matches: list[dict]) -> list[dict]:
    return sorted(
        matches,
        key=lambda m: (-(m.get("_score") or 0.0), -(m.get("bounty") or 0.0)),
    )


def match_findings(findings: list[ReconFinding], top_k: int = 5) -> dict:
    """Return matches grouped by (target, finding type)."""
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        matches = _match_one(f, top_k=top_k)
        matches = _rank(matches)
        if matches:
            grouped[(f.target, f.type)].append(
                {"finding": f.model_dump(), "matches": matches}
            )
    # convert tuple keys to strings for JSON friendliness
    return {
        f"{target}::{ftype}": entries
        for (target, ftype), entries in grouped.items()
    }
