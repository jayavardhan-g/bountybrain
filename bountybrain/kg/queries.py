"""KG query helpers used by the agent and UI.

Kept small — the agent calls these by name and treats them like tools.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import select

from bountybrain.kg.db import Session
from bountybrain.kg.models import (
    Report,
    ReportBypassesReport,
    ReportExploitsVuln,
    ReportTargetsTech,
    ReportUsesTechnique,
    ReportUsesTool,
    Target,
    Technique,
    Tool,
    Vulnerability,
)


def upsert(session, model, unique_field: str, value: str, **extra) -> Any:
    obj = session.execute(
        select(model).where(getattr(model, unique_field) == value)
    ).scalar_one_or_none()
    if obj:
        return obj
    obj = model(**{unique_field: value, **extra})
    session.add(obj)
    session.flush()
    return obj


def link(session, model, **cols) -> None:
    obj = session.execute(
        select(model).filter_by(**cols)
    ).scalar_one_or_none()
    if not obj:
        session.add(model(**cols))


def get_bypass_chain(vuln_type: str, target_tech: str | None = None) -> list[dict]:
    """Return the timeline of bypass chains for a vuln class.

    A "chain" is a report that bypasses an earlier report — we walk backwards
    from each such link and return them ordered by report date ascending so
    the timeline reads left-to-right.
    """
    with Session() as s:
        q = (
            select(Report)
            .join(ReportExploitsVuln, ReportExploitsVuln.report_id == Report.id)
            .join(Vulnerability, Vulnerability.id == ReportExploitsVuln.vuln_id)
            .where(Vulnerability.name.ilike(vuln_type))
        )
        if target_tech:
            q = (
                q.join(ReportTargetsTech, ReportTargetsTech.report_id == Report.id)
                .join(Target, Target.id == ReportTargetsTech.target_id)
                .where(Target.name.ilike(target_tech))
            )
        reports = s.execute(q).scalars().all()

        chains = []
        for r in reports:
            bypassed = (
                s.execute(
                    select(Report)
                    .join(
                        ReportBypassesReport,
                        ReportBypassesReport.bypassed_report_id == Report.id,
                    )
                    .where(ReportBypassesReport.report_id == r.id)
                )
                .scalars()
                .all()
            )
            if bypassed:
                chains.append(
                    {
                        "report": {
                            "id": r.id,
                            "title": r.title,
                            "url": r.url,
                            "date": r.date.isoformat() if r.date else None,
                        },
                        "bypassed": [
                            {
                                "id": b.id,
                                "title": b.title,
                                "url": b.url,
                                "date": b.date.isoformat() if b.date else None,
                            }
                            for b in bypassed
                        ],
                    }
                )
        chains.sort(key=lambda c: c["report"]["date"] or "")
        return chains


def kg_query(entity_type: str, entity_name: str, relationship: str) -> list[dict]:
    """Generic KG lookup.

    entity_type: vulnerability | technique | tool | target
    relationship: reports | techniques | tools | targets
    """
    entity_map = {
        "vulnerability": (Vulnerability, ReportExploitsVuln, "vuln_id"),
        "technique": (Technique, ReportUsesTechnique, "technique_id"),
        "tool": (Tool, ReportUsesTool, "tool_id"),
        "target": (Target, ReportTargetsTech, "target_id"),
    }
    if entity_type not in entity_map:
        return []
    Entity, RelTable, col = entity_map[entity_type]
    with Session() as s:
        e = s.execute(
            select(Entity).where(Entity.name.ilike(entity_name))
        ).scalar_one_or_none()
        if not e:
            return []
        reports = (
            s.execute(
                select(Report)
                .join(RelTable, RelTable.report_id == Report.id)
                .where(getattr(RelTable, col) == e.id)
            )
            .scalars()
            .all()
        )
        return [
            {
                "id": r.id,
                "title": r.title,
                "url": r.url,
                "date": r.date.isoformat() if r.date else None,
                "bounty": r.bounty,
                "severity": r.severity,
            }
            for r in reports
        ]


def compare_reports(report_ids: list[int]) -> dict:
    """Structured diff of techniques/tools/targets across the given reports."""
    with Session() as s:
        rows = defaultdict(lambda: {"techniques": [], "tools": [], "targets": []})
        for rid in report_ids:
            r = s.get(Report, rid)
            if not r:
                continue
            rows[rid]["title"] = r.title
            rows[rid]["url"] = r.url
            rows[rid]["techniques"] = [
                t.name
                for t in s.execute(
                    select(Technique)
                    .join(
                        ReportUsesTechnique,
                        ReportUsesTechnique.technique_id == Technique.id,
                    )
                    .where(ReportUsesTechnique.report_id == rid)
                ).scalars()
            ]
            rows[rid]["tools"] = [
                t.name
                for t in s.execute(
                    select(Tool)
                    .join(ReportUsesTool, ReportUsesTool.tool_id == Tool.id)
                    .where(ReportUsesTool.report_id == rid)
                ).scalars()
            ]
            rows[rid]["targets"] = [
                t.name
                for t in s.execute(
                    select(Target)
                    .join(ReportTargetsTech, ReportTargetsTech.target_id == Target.id)
                    .where(ReportTargetsTech.report_id == rid)
                ).scalars()
            ]
        return dict(rows)


def corpus_stats() -> dict:
    with Session() as s:
        reports = s.execute(select(Report)).scalars().all()
        by_vuln: dict[str, int] = defaultdict(int)
        by_year: dict[str, int] = defaultdict(int)
        for r in reports:
            if r.date:
                by_year[str(r.date.year)] += 1
            vulns = s.execute(
                select(Vulnerability)
                .join(
                    ReportExploitsVuln,
                    ReportExploitsVuln.vuln_id == Vulnerability.id,
                )
                .where(ReportExploitsVuln.report_id == r.id)
            ).scalars()
            for v in vulns:
                by_vuln[v.name] += 1
        return {
            "total_reports": len(reports),
            "by_vuln": dict(by_vuln),
            "by_year": dict(by_year),
        }
