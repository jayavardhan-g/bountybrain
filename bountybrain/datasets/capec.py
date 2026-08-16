"""Parse the MITRE CAPEC catalog into attack-pattern (technique) nodes.

CAPEC is the piece that turns this from "a search engine over writeups"
into something that can propose a next move. Every pattern carries:

- an **execution flow** broken into Explore / Experiment / Exploit phases,
  with concrete techniques per step — an Explore step is literally "what to
  try next" once recon has told you a surface exists;
- **prerequisites**, which are the conditions a target must satisfy for the
  pattern to apply, so they can be tested against recon output;
- **skills required**, so guidance can be pitched at the user's level;
- the official **CAPEC -> CWE mapping**, which links every technique to the
  weakness backbone parsed in `cwe.py`.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

NS = "{http://capec.mitre.org/capec-3}"

KEPT_NATURES = {"ChildOf", "ParentOf", "CanFollow", "CanPrecede", "PeerOf", "CanAlsoBe"}

# Execution-flow phases, in the order an engagement actually runs.
PHASE_ORDER = {"Explore": 0, "Experiment": 1, "Exploit": 2}


@dataclass
class AttackStep:
    step: int
    phase: str
    description: str
    techniques: list[str] = field(default_factory=list)


@dataclass
class AttackPattern:
    capec_id: int
    name: str
    abstraction: str  # Meta | Standard | Detailed
    status: str
    description: str
    extended_description: str = ""
    likelihood: str | None = None
    typical_severity: str | None = None
    prerequisites: list[str] = field(default_factory=list)
    skills: list[dict] = field(default_factory=list)  # {level, description}
    resources: list[str] = field(default_factory=list)
    consequences: list[dict] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    execution_flow: list[AttackStep] = field(default_factory=list)
    related_cwes: list[int] = field(default_factory=list)
    # (nature, target_capec_id)
    relations: list[tuple[str, int]] = field(default_factory=list)
    taxonomy: list[dict] = field(default_factory=list)  # e.g. ATT&CK mappings

    @property
    def key(self) -> str:
        return f"CAPEC-{self.capec_id}"

    @property
    def min_skill(self) -> str | None:
        """Lowest skill level the pattern can be attempted at."""
        order = {"Low": 0, "Medium": 1, "High": 2}
        levels = [s["level"] for s in self.skills if s.get("level") in order]
        return min(levels, key=lambda lvl: order[lvl]) if levels else None

    def steps_for_phase(self, phase: str) -> list[AttackStep]:
        return [s for s in self.execution_flow if s.phase == phase]

    def to_document(self) -> str:
        """Flatten into retrievable prose for the RAG index."""
        parts = [f"# {self.key}: {self.name}", "", self.description]
        if self.extended_description:
            parts += ["", self.extended_description]
        meta = []
        if self.likelihood:
            meta.append(f"likelihood of attack: {self.likelihood}")
        if self.typical_severity:
            meta.append(f"typical severity: {self.typical_severity}")
        if self.min_skill:
            meta.append(f"minimum skill: {self.min_skill}")
        if meta:
            parts += ["", "**" + " | ".join(meta) + "**"]
        if self.prerequisites:
            parts += ["", "## Prerequisites"]
            parts += [f"- {p}" for p in self.prerequisites]
        if self.execution_flow:
            parts += ["", "## Execution flow"]
            for s in sorted(
                self.execution_flow, key=lambda x: (PHASE_ORDER.get(x.phase, 9), x.step)
            ):
                parts.append(f"**Step {s.step} ({s.phase}):** {s.description}")
                parts += [f"  - {t}" for t in s.techniques]
        if self.skills:
            parts += ["", "## Skills required"]
            for s in self.skills:
                parts.append(f"- [{s.get('level', '?')}] {s.get('description', '')}")
        if self.mitigations:
            parts += ["", "## Mitigations"]
            parts += [f"- {m}" for m in self.mitigations]
        if self.related_cwes:
            refs = ", ".join(f"CWE-{c}" for c in self.related_cwes)
            parts += ["", f"**Related weaknesses:** {refs}"]
        return "\n".join(parts)


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return " ".join("".join(el.itertext()).split())


def _texts(parent: ET.Element, path: str) -> list[str]:
    return [t for t in (_text(e) for e in parent.findall(path)) if t]


def _parse_pattern(a: ET.Element) -> AttackPattern:
    ap = AttackPattern(
        capec_id=int(a.attrib["ID"]),
        name=a.attrib.get("Name", ""),
        abstraction=a.attrib.get("Abstraction", ""),
        status=a.attrib.get("Status", ""),
        description=_text(a.find(NS + "Description")),
        extended_description=_text(a.find(NS + "Extended_Description")),
        likelihood=_text(a.find(NS + "Likelihood_Of_Attack")) or None,
        typical_severity=_text(a.find(NS + "Typical_Severity")) or None,
    )

    ap.prerequisites = _texts(a, f"{NS}Prerequisites/{NS}Prerequisite")
    ap.resources = _texts(a, f"{NS}Resources_Required/{NS}Resource")
    ap.mitigations = _texts(a, f"{NS}Mitigations/{NS}Mitigation")
    ap.examples = _texts(a, f"{NS}Example_Instances/{NS}Example")

    for s in a.findall(f"{NS}Skills_Required/{NS}Skill"):
        ap.skills.append(
            {"level": s.attrib.get("Level", ""), "description": _text(s)}
        )

    for c in a.findall(f"{NS}Consequences/{NS}Consequence"):
        ap.consequences.append(
            {
                "scopes": _texts(c, NS + "Scope"),
                "impacts": _texts(c, NS + "Impact"),
                "note": _text(c.find(NS + "Note")),
            }
        )

    for st in a.findall(f"{NS}Execution_Flow/{NS}Attack_Step"):
        raw_step = _text(st.find(NS + "Step"))
        ap.execution_flow.append(
            AttackStep(
                step=int(raw_step) if raw_step.isdigit() else 0,
                phase=_text(st.find(NS + "Phase")),
                description=_text(st.find(NS + "Description")),
                techniques=_texts(st, NS + "Technique"),
            )
        )

    for rw in a.findall(f"{NS}Related_Weaknesses/{NS}Related_Weakness"):
        cid = rw.attrib.get("CWE_ID")
        if cid and cid.isdigit() and int(cid) not in ap.related_cwes:
            ap.related_cwes.append(int(cid))

    for rp in a.findall(f"{NS}Related_Attack_Patterns/{NS}Related_Attack_Pattern"):
        nature = rp.attrib.get("Nature", "")
        target = rp.attrib.get("CAPEC_ID")
        if nature in KEPT_NATURES and target and target.isdigit():
            pair = (nature, int(target))
            if pair not in ap.relations:
                ap.relations.append(pair)

    for tm in a.findall(f"{NS}Taxonomy_Mappings/{NS}Taxonomy_Mapping"):
        ap.taxonomy.append(
            {
                "taxonomy": tm.attrib.get("Taxonomy_Name", ""),
                "entry_id": _text(tm.find(NS + "Entry_ID")),
                "entry_name": _text(tm.find(NS + "Entry_Name")),
            }
        )

    return ap


def load(xml_path: str | Path) -> list[AttackPattern]:
    root = ET.parse(str(xml_path)).getroot()
    container = root.find(NS + "Attack_Patterns")
    if container is None:
        return []
    return [_parse_pattern(a) for a in container]


def index_by_cwe(patterns: list[AttackPattern]) -> dict[int, list[AttackPattern]]:
    """CWE id -> attack patterns that exploit it.

    This is the lookup the recon planner runs: recon says a surface looks
    like CWE-918, and this returns the concrete techniques to try.
    """
    out: dict[int, list[AttackPattern]] = {}
    for p in patterns:
        for cwe_id in p.related_cwes:
            out.setdefault(cwe_id, []).append(p)
    return out
