"""A learning path for one weakness class, read off the graph.

    understand the weakness → see how it is attacked → read real disclosures
    → practise in a lab → where to go next

Every item comes from a typed edge in the graph, not from the model:

    weakness      the resolved CWE node, plus its ChildOf parent for context
    patterns      technique_targets_weakness (CAPEC → CWE), easiest first
    writeups      document_covers_weakness, highest bounty first
    labs          the curated lab table, resolved through the CWE hierarchy
    next          CanPrecede successors and ChildOf children

When a stage is empty for the exact class, it borrows from its neighbours in
the CWE tree — patterns from a parent, disclosures from a child, since a bug
in a more specific class is still an instance of this one — and says so via
`inherited_from`, so the UI never presents borrowed material as direct.
"""
from __future__ import annotations

from bountybrain.kg import queries

from .labs import LABS_BY_CWE

# CAPEC's Skills_Required level. Unrated patterns go last, not first: "no
# rating" is not evidence that a pattern is easy.
SKILL_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def _stage(key: str, title: str, why: str, items: list, inherited_from: str | None = None) -> dict:
    return {
        "key": key,
        "title": title,
        "why": why,
        "items": items,
        "inherited_from": inherited_from,
    }


def _pattern_item(t: dict) -> dict:
    flow = t.get("execution_flow") or []
    return {
        "key": t["key"],
        "name": t["name"],
        "url": t["url"],
        "min_skill": t.get("min_skill"),
        "typical_severity": t.get("typical_severity"),
        "explore_steps": [s.get("description", "") for s in flow if s.get("phase") == "Explore"][:3],
    }


def _first_nonempty(candidates: list[tuple[str | None, list]]) -> tuple[str | None, list]:
    for origin, items in candidates:
        if items:
            return origin, items
    return None, []


def learning_path(topic: str | int, max_patterns: int = 5, max_writeups: int = 5) -> dict | None:
    """Ordered study plan for a topic, or None if it resolves to no CWE."""
    weakness = queries.find_weakness(topic)
    if not weakness:
        return None
    cwe_id = weakness["cwe_id"]
    hierarchy = queries.weakness_hierarchy(cwe_id)
    parents = hierarchy.get("parents", [])
    children = hierarchy.get("children", [])

    # -- 1. understand the weakness
    understand = _stage(
        "weakness",
        f"Understand {weakness['key']}: {weakness['name']}",
        "The root flaw, in MITRE's words, and the broader class it belongs to.",
        [
            {
                "key": weakness["key"],
                "name": weakness["name"],
                "url": weakness["url"],
                "abstraction": weakness.get("abstraction"),
                "description": weakness.get("description") or "",
                "aliases": weakness.get("aliases", [])[:8],
                "parents": [{"key": p["key"], "name": p["name"]} for p in parents],
            }
        ],
    )

    # -- 2. how it is attacked: own patterns, else the parents'
    origin, techniques = _first_nonempty(
        [(None, queries.techniques_for_weakness(cwe_id))]
        + [(p["key"], queries.techniques_for_weakness(p["cwe_id"])) for p in parents]
    )
    techniques.sort(key=lambda t: (SKILL_ORDER.get(t.get("min_skill") or "", 3), t["capec_id"]))
    patterns = _stage(
        "patterns",
        "See how it is attacked",
        "CAPEC attack patterns that exploit this weakness, lowest required skill first.",
        [_pattern_item(t) for t in techniques[:max_patterns]],
        origin,
    )

    # -- 3. real disclosures: own, else a child's (an instance of this class),
    #       else a parent's
    origin, docs = _first_nonempty(
        [(None, queries.documents_for_weakness(cwe_id, limit=max_writeups, doc_type="writeup"))]
        + [
            (c["key"], queries.documents_for_weakness(c["cwe_id"], limit=max_writeups, doc_type="writeup"))
            for c in children
        ]
        + [
            (p["key"], queries.documents_for_weakness(p["cwe_id"], limit=max_writeups, doc_type="writeup"))
            for p in parents
        ]
    )
    writeups = _stage(
        "writeups",
        "Read real disclosures",
        "Disclosed bug bounty reports labelled with this class, highest bounty first.",
        docs,
        origin,
    )

    # -- 4. practise: own labs, else a parent's — the same walk find_practice_labs does
    origin, labs = _first_nonempty(
        [(None, LABS_BY_CWE.get(cwe_id, []))]
        + [(p["key"], LABS_BY_CWE.get(p["cwe_id"], [])) for p in parents]
    )
    practise = _stage(
        "labs",
        "Practise it hands-on",
        "Free or widely used training labs that cover this class. Never a live target.",
        labs,
        origin,
    )

    # -- 5. where to go next
    following = [
        {"key": w["key"], "name": w["name"], "relation": "can lead to"}
        for w in hierarchy.get("can_precede", [])
    ] + [
        {"key": c["key"], "name": c["name"], "relation": "more specific variant"}
        for c in children[:8]
    ]
    nxt = _stage(
        "next",
        "Where to go next",
        "Weaknesses this one can lead to (CanPrecede), then its more specific variants.",
        following,
    )

    stages = [understand, patterns, writeups, practise, nxt]
    return {
        "topic": str(topic),
        "weakness": {"cwe_id": cwe_id, "key": weakness["key"], "name": weakness["name"]},
        "stages": stages,
        "complete": all(s["items"] for s in stages[:4]),
    }

