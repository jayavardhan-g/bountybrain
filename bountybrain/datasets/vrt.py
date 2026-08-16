"""Parse Bugcrowd's Vulnerability Rating Taxonomy.

VRT is the triage taxonomy real bug bounty programs pay against. Each leaf
carries a priority from P1 (critical) to P5 (informational), and Bugcrowd
publishes an official VRT -> CWE mapping alongside it.

That mapping is what lets the planner answer the question a learner actually
has — "is this worth my afternoon?" — because it connects a weakness class to
the payout tier programs assign it, independently of CVSS.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


@dataclass
class VRTEntry:
    vrt_id: str
    name: str
    node_type: str  # category | subcategory | variant
    priority: int | None = None  # 1..5, lower is more severe
    path: list[str] = field(default_factory=list)  # ancestor names
    cwe_ids: list[int] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return " > ".join([*self.path, self.name])


def _walk(nodes: list[dict], path: list[str]) -> list[VRTEntry]:
    out: list[VRTEntry] = []
    for n in nodes or []:
        entry = VRTEntry(
            vrt_id=n.get("id", ""),
            name=n.get("name", ""),
            node_type=n.get("type", ""),
            priority=n.get("priority") if isinstance(n.get("priority"), int) else None,
            path=list(path),
        )
        out.append(entry)
        children = n.get("children")
        if children:
            out.extend(_walk(children, [*path, entry.name]))
    return out


def _walk_cwe(nodes: list[dict], acc: dict[str, list[int]]) -> None:
    """Flatten the parallel CWE-mapping tree, which is keyed by the same ids."""
    for n in nodes or []:
        raw = n.get("cwe")
        if raw:
            ids: list[int] = []
            for item in raw if isinstance(raw, list) else [raw]:
                for m in _CWE_RE.findall(str(item)):
                    if int(m) not in ids:
                        ids.append(int(m))
            if ids:
                acc[n.get("id", "")] = ids
        if n.get("children"):
            _walk_cwe(n["children"], acc)


def load(vrt_dir: str | Path) -> list[VRTEntry]:
    root = Path(vrt_dir)
    taxonomy = json.loads(
        (root / "vulnerability-rating-taxonomy.json").read_text(encoding="utf-8")
    )
    entries = _walk(taxonomy.get("content", []), [])

    mapping_file = root / "mappings" / "cwe" / "cwe.json"
    if mapping_file.exists():
        acc: dict[str, list[int]] = {}
        _walk_cwe(json.loads(mapping_file.read_text(encoding="utf-8")).get("content", []), acc)
        for e in entries:
            if e.vrt_id in acc:
                e.cwe_ids = acc[e.vrt_id]
    return entries


def priority_by_cwe(entries: list[VRTEntry]) -> dict[int, int]:
    """CWE id -> best (lowest-numbered, most severe) VRT priority.

    A weakness can appear under several VRT leaves at different priorities;
    we keep the most severe, since that is the ceiling a program might pay.
    """
    out: dict[int, int] = {}
    for e in entries:
        if e.priority is None:
            continue
        for cwe in e.cwe_ids:
            if cwe not in out or e.priority < out[cwe]:
                out[cwe] = e.priority
    return out
