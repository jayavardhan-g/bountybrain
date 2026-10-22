"""KG query helpers used by the agent, the planner and the UI.

Kept deliberately small and side-effect free — the agent calls these by name
and treats them as tools, so each one returns plain JSON-able dicts.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, or_, select

from bountybrain.kg.db import Session
from bountybrain.kg.models import (
    CVE,
    Document,
    DocumentCoversWeakness,
    Exploit,
    Product,
    Signature,
    SignatureDetectsWeakness,
    SignatureTargetsProduct,
    Technique,
    TechniqueRelation,
    TechniqueTargetsWeakness,
    Vulnerability,
    WeaknessRelation,
)


def _loads(value: str | None) -> Any:
    if not value:
        return []
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return []


def _weakness_dict(v: Vulnerability) -> dict:
    return {
        "cwe_id": v.cwe_id,
        "key": f"CWE-{v.cwe_id}",
        "name": v.name,
        "abstraction": v.abstraction,
        "likelihood": v.likelihood,
        "vrt_priority": v.vrt_priority,
        "description": v.description,
        "aliases": _loads(v.aliases_json),
        "url": f"https://cwe.mitre.org/data/definitions/{v.cwe_id}.html",
    }


def _technique_dict(t: Technique) -> dict:
    return {
        "capec_id": t.capec_id,
        "key": f"CAPEC-{t.capec_id}",
        "name": t.name,
        "abstraction": t.abstraction,
        "likelihood": t.likelihood,
        "typical_severity": t.typical_severity,
        "min_skill": t.min_skill,
        "description": t.description,
        "prerequisites": _loads(t.prerequisites_json),
        "execution_flow": _loads(t.execution_flow_json),
        "mitigations": _loads(t.mitigations_json),
        "url": f"https://capec.mitre.org/data/definitions/{t.capec_id}.html",
    }


# --------------------------------------------------------------------------
# lookup
# --------------------------------------------------------------------------


def find_weakness(term: str | int) -> dict | None:
    """Resolve a CWE by number, 'CWE-89', exact name, or alias substring."""
    with Session() as s:
        if isinstance(term, int) or str(term).isdigit():
            v = s.execute(
                select(Vulnerability).where(Vulnerability.cwe_id == int(term))
            ).scalar_one_or_none()
            return _weakness_dict(v) if v else None

        text = str(term).strip()
        if text.upper().startswith("CWE-") and text[4:].isdigit():
            v = s.execute(
                select(Vulnerability).where(Vulnerability.cwe_id == int(text[4:]))
            ).scalar_one_or_none()
            return _weakness_dict(v) if v else None

        v = s.execute(
            select(Vulnerability).where(func.lower(Vulnerability.name) == text.lower())
        ).scalar_one_or_none()
        if v:
            return _weakness_dict(v)

        # An exact alias beats any substring hit. Without this, "SQL injection"
        # substring-matched "SQL Injection: Hibernate" (a Variant) ahead of
        # CWE-89, whose alias it is, and "path traversal" landed on CWE-24.
        exact = s.execute(
            select(Vulnerability).where(Vulnerability.aliases_json.ilike(f'%"{text}"%'))
        ).scalars().all()
        if exact:
            rank = {"Base": 0, "Variant": 1, "Class": 2, "Compound": 3, "Pillar": 4}
            exact.sort(key=lambda v: rank.get(v.abstraction or "", 9))
            return _weakness_dict(exact[0])

        # fall back to a name substring match, preferring the most
        # specific abstraction so "injection" does not return the Pillar
        rank = {"Variant": 0, "Base": 1, "Compound": 2, "Class": 3, "Pillar": 4}
        rows = s.execute(
            select(Vulnerability).where(Vulnerability.name.ilike(f"%{text}%"))
        ).scalars().all()
        if not rows:
            return None
        rows.sort(key=lambda v: rank.get(v.abstraction or "", 9))
        return _weakness_dict(rows[0])


def search_weaknesses(term: str, limit: int = 20) -> list[dict]:
    with Session() as s:
        rows = s.execute(
            select(Vulnerability)
            .where(
                or_(
                    Vulnerability.name.ilike(f"%{term}%"),
                    Vulnerability.description.ilike(f"%{term}%"),
                    Vulnerability.aliases_json.ilike(f"%{term}%"),
                )
            )
            .limit(limit)
        ).scalars().all()
        return [_weakness_dict(v) for v in rows]


def weakness_hierarchy(cwe_id: int) -> dict:
    """Parents, children and siblings of a weakness in the CWE taxonomy."""
    with Session() as s:
        v = s.execute(
            select(Vulnerability).where(Vulnerability.cwe_id == cwe_id)
        ).scalar_one_or_none()
        if not v:
            return {}

        def related(nature: str, outgoing: bool) -> list[dict]:
            if outgoing:
                stmt = (
                    select(Vulnerability)
                    .join(WeaknessRelation, WeaknessRelation.dst_id == Vulnerability.id)
                    .where(WeaknessRelation.src_id == v.id, WeaknessRelation.nature == nature)
                )
            else:
                stmt = (
                    select(Vulnerability)
                    .join(WeaknessRelation, WeaknessRelation.src_id == Vulnerability.id)
                    .where(WeaknessRelation.dst_id == v.id, WeaknessRelation.nature == nature)
                )
            return [_weakness_dict(x) for x in s.execute(stmt).scalars().all()]

        return {
            "weakness": _weakness_dict(v),
            "parents": related("ChildOf", outgoing=True),
            "children": related("ChildOf", outgoing=False),
            "peers": related("PeerOf", outgoing=True),
            "can_precede": related("CanPrecede", outgoing=True),
            "can_follow": related("CanPrecede", outgoing=False),
        }


def techniques_for_weakness(cwe_id: int) -> list[dict]:
    """CAPEC attack patterns that exploit a given CWE (official mapping)."""
    with Session() as s:
        rows = s.execute(
            select(Technique)
            .join(TechniqueTargetsWeakness, TechniqueTargetsWeakness.technique_id == Technique.id)
            .join(Vulnerability, Vulnerability.id == TechniqueTargetsWeakness.vuln_id)
            .where(Vulnerability.cwe_id == cwe_id)
        ).scalars().all()
        return [_technique_dict(t) for t in rows]


def attack_chain(capec_id: int, depth: int = 3) -> list[list[dict]]:
    """Walk `CanPrecede` edges to surface multi-step attack chains.

    This is the closest thing the corpus has to "what does this bug let me do
    next" — CAPEC records which patterns can chain into which.
    """
    with Session() as s:
        start = s.execute(
            select(Technique).where(Technique.capec_id == capec_id)
        ).scalar_one_or_none()
        if not start:
            return []

        chains: list[list[dict]] = []

        def successors(node: Technique) -> list[Technique]:
            """Patterns that can come after `node`.

            CAPEC states each link from whichever side the pattern author was
            writing: "A CanPrecede B" and "B CanFollow A" carry identical
            information. Walking only the CanPrecede direction therefore drops
            every chain the catalogue happened to record from the follower's
            side — which is most of them, and why this returned nothing.
            """
            forward = s.execute(
                select(Technique)
                .join(TechniqueRelation, TechniqueRelation.dst_id == Technique.id)
                .where(
                    TechniqueRelation.src_id == node.id,
                    TechniqueRelation.nature == "CanPrecede",
                )
            ).scalars().all()
            backward = s.execute(
                select(Technique)
                .join(TechniqueRelation, TechniqueRelation.src_id == Technique.id)
                .where(
                    TechniqueRelation.dst_id == node.id,
                    TechniqueRelation.nature == "CanFollow",
                )
            ).scalars().all()
            merged: dict[int, Technique] = {t.id: t for t in [*forward, *backward]}
            return list(merged.values())

        def walk(node: Technique, path: list[Technique], seen: set[int]) -> None:
            if len(path) > depth:
                chains.append([_technique_dict(p) for p in path])
                return
            nxt = [t for t in successors(node) if t.id not in seen]
            if not nxt:
                if len(path) > 1:
                    chains.append([_technique_dict(p) for p in path])
                return
            for t in nxt:
                walk(t, [*path, t], seen | {t.id})

        walk(start, [start], {start.id})
        return chains


def documents_for_weakness(cwe_id: int, limit: int = 10, doc_type: str | None = None) -> list[dict]:
    with Session() as s:
        stmt = (
            select(Document)
            .join(DocumentCoversWeakness, DocumentCoversWeakness.document_id == Document.id)
            .join(Vulnerability, Vulnerability.id == DocumentCoversWeakness.vuln_id)
            .where(Vulnerability.cwe_id == cwe_id)
        )
        if doc_type:
            stmt = stmt.where(Document.doc_type == doc_type)
        stmt = stmt.order_by(Document.bounty.desc().nullslast()).limit(limit)
        return [
            {
                "id": d.id,
                "title": d.title,
                "url": d.url,
                "doc_type": d.doc_type,
                "source": d.source,
                "bounty": d.bounty,
                "published": d.published.isoformat() if d.published else None,
                "program": d.program,
            }
            for d in s.execute(stmt).scalars().all()
        ]


def _writeup_dict(row) -> dict:
    return {
        "id": row.id,
        "title": row.title,
        "url": row.url,
        "bounty": row.bounty,
        "program": row.program,
        "published": row.published.isoformat() if row.published else None,
    }


def _product_matcher(products: list[str]) -> re.Pattern | None:
    """Match fingerprinted product names inside free text.

    Longest alternative first so "wordpress-plugin" wins over "wordpress", and
    non-alphanumeric boundaries so "jira" does not fire inside "jirafe".
    """
    if not products:
        return None
    # The group is required, not cosmetic: `|` binds looser than the
    # look-arounds, so without it the boundaries would apply to the first and
    # last alternative only.
    parts = "|".join(re.escape(p) for p in sorted(products, key=len, reverse=True))
    return re.compile(rf"(?<![a-z0-9])(?:{parts})(?![a-z0-9])")


def writeups_for_recon(
    cwe_ids: Iterable[int],
    product_names: Iterable[str] = (),
    limit: int = 15,
) -> list[dict]:
    """Disclosed reports that match what a recon run actually found.

    Two independent signals, both traceable to a row in the graph:

    - the report is labelled with one of the weakness classes the planner
      ranked for this asset, and
    - its title or program names one of the technologies recon fingerprinted.

    Reports carrying both rank first, because those are the ones describing
    this bug class *on this stack* — the difference between "here is some SSRF
    reading" and "here is SSRF found in the GitLab you are looking at".
    """
    cwes = [int(c) for c in cwe_ids]
    if not cwes:
        return []
    products = sorted(
        {p.strip().lower() for p in product_names if p and len(p.strip()) >= 3}
    )
    matcher = _product_matcher(products)

    with Session() as s:
        rows = s.execute(
            select(
                Document.id,
                Document.title,
                Document.url,
                Document.bounty,
                Document.program,
                Document.published,
                Vulnerability.cwe_id,
                Vulnerability.name.label("weakness_name"),
            )
            .join(DocumentCoversWeakness, DocumentCoversWeakness.document_id == Document.id)
            .join(Vulnerability, Vulnerability.id == DocumentCoversWeakness.vuln_id)
            .where(Vulnerability.cwe_id.in_(cwes), Document.doc_type == "writeup")
        ).all()

    # One row per (document, weakness); fold back to one entry per report.
    merged: dict[int, dict] = {}
    for r in rows:
        entry = merged.get(r.id)
        if entry is None:
            entry = _writeup_dict(r)
            entry["weaknesses"] = []
            haystack = " ".join(filter(None, [r.title or "", r.program or ""])).lower()
            entry["matched_products"] = (
                sorted(set(matcher.findall(haystack))) if matcher else []
            )
            merged[r.id] = entry
        entry["weaknesses"].append({"cwe_id": r.cwe_id, "name": r.weakness_name})

    out = sorted(
        merged.values(),
        key=lambda d: (
            -len(d["matched_products"]),
            -(d["bounty"] or 0.0),
            d["title"] or "",
        ),
    )
    return out[:limit]


def related_writeups(document_id: int, limit: int = 8) -> list[dict]:
    """Other disclosed reports connected to this one.

    Two kinds of edge make two reports related, and they answer different
    questions: a **shared weakness class** is the same bug found somewhere
    else, and a **shared program** is the same target yielding a different bug.
    Shared-weakness matches rank first, then bounty.
    """
    with Session() as s:
        doc = s.execute(select(Document).where(Document.id == document_id)).scalar_one_or_none()
        if doc is None:
            return []
        # Read what we need while the row is attached, rather than relying on
        # the session's expiry policy after the block closes.
        doc_program = doc.program

        own_cwes = [
            r[0]
            for r in s.execute(
                select(Vulnerability.cwe_id)
                .join(
                    DocumentCoversWeakness,
                    DocumentCoversWeakness.vuln_id == Vulnerability.id,
                )
                .where(DocumentCoversWeakness.document_id == document_id)
            ).all()
        ]

        clauses = []
        if own_cwes:
            clauses.append(Vulnerability.cwe_id.in_(own_cwes))
        if doc_program:
            clauses.append(Document.program == doc_program)
        if not clauses:
            return []

        rows = s.execute(
            select(
                Document.id,
                Document.title,
                Document.url,
                Document.bounty,
                Document.program,
                Document.published,
                Vulnerability.cwe_id,
            )
            .join(
                DocumentCoversWeakness,
                DocumentCoversWeakness.document_id == Document.id,
                isouter=True,
            )
            .join(
                Vulnerability,
                Vulnerability.id == DocumentCoversWeakness.vuln_id,
                isouter=True,
            )
            .where(
                Document.doc_type == "writeup",
                Document.id != document_id,
                or_(*clauses),
            )
        ).all()

    merged: dict[int, dict] = {}
    for r in rows:
        entry = merged.get(r.id)
        if entry is None:
            entry = _writeup_dict(r)
            entry["shared_weaknesses"] = []
            entry["shared_program"] = bool(doc_program and r.program == doc_program)
            merged[r.id] = entry
        if r.cwe_id is not None and r.cwe_id in own_cwes:
            if r.cwe_id not in entry["shared_weaknesses"]:
                entry["shared_weaknesses"].append(r.cwe_id)

    out = sorted(
        merged.values(),
        key=lambda d: (
            -len(d["shared_weaknesses"]),
            -int(d["shared_program"]),
            -(d["bounty"] or 0.0),
        ),
    )
    return out[:limit]


def signatures_for_product(name: str, limit: int = 25) -> list[dict]:
    """Detection templates that target a fingerprinted technology.

    Ordered by EPSS (probability of real-world exploitation) then CVSS, so the
    head of the list is what is actually worth trying first.
    """
    with Session() as s:
        rows = s.execute(
            select(Signature)
            .join(SignatureTargetsProduct, SignatureTargetsProduct.signature_id == Signature.id)
            .join(Product, Product.id == SignatureTargetsProduct.product_id)
            .where(func.lower(Product.name) == name.lower())
            .order_by(
                Signature.epss_score.desc().nullslast(),
                Signature.cvss_score.desc().nullslast(),
            )
            .limit(limit)
        ).scalars().all()
        return [
            {
                "template_id": r.template_id,
                "name": r.name,
                "severity": r.severity,
                "cvss_score": r.cvss_score,
                "epss_score": r.epss_score,
                "path": r.path,
                "tags": _loads(r.tags_json),
                "url": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{r.path}",
            }
            for r in rows
        ]


def weaknesses_for_product(name: str, limit: int = 15) -> list[dict]:
    """Which weakness classes historically show up in a given technology."""
    with Session() as s:
        rows = s.execute(
            select(
                Vulnerability.cwe_id,
                Vulnerability.name,
                Vulnerability.vrt_priority,
                func.count(Signature.id).label("n"),
                func.max(Signature.epss_score).label("max_epss"),
            )
            .join(SignatureDetectsWeakness, SignatureDetectsWeakness.vuln_id == Vulnerability.id)
            .join(Signature, Signature.id == SignatureDetectsWeakness.signature_id)
            .join(SignatureTargetsProduct, SignatureTargetsProduct.signature_id == Signature.id)
            .join(Product, Product.id == SignatureTargetsProduct.product_id)
            .where(func.lower(Product.name) == name.lower())
            .group_by(Vulnerability.cwe_id, Vulnerability.name, Vulnerability.vrt_priority)
            .order_by(func.count(Signature.id).desc())
            .limit(limit)
        ).all()
        return [
            {
                "cwe_id": r.cwe_id,
                "name": r.name,
                "vrt_priority": r.vrt_priority,
                "signature_count": r.n,
                "max_epss": r.max_epss,
            }
            for r in rows
        ]


def known_products(prefix: str = "", limit: int = 50) -> list[str]:
    with Session() as s:
        stmt = select(Product.name)
        if prefix:
            stmt = stmt.where(Product.name.ilike(f"{prefix}%"))
        return [r[0] for r in s.execute(stmt.limit(limit)).all()]


def corpus_summary() -> dict:
    """Headline counts, for the UI landing page."""
    with Session() as s:
        def count(model) -> int:
            return s.execute(select(func.count()).select_from(model)).scalar_one()

        return {
            "weaknesses": count(Vulnerability),
            "techniques": count(Technique),
            "documents": count(Document),
            "signatures": count(Signature),
            "exploits": count(Exploit),
            "cves": count(CVE),
            "products": count(Product),
            "by_doc_type": dict(
                s.execute(
                    select(Document.doc_type, func.count()).group_by(Document.doc_type)
                ).all()
            ),
        }
