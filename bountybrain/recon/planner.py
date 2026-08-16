"""Turn recon output into a ranked, cited plan of what to try next.

This is the part that does something a search box cannot. Given the
technologies a recon run fingerprinted on an asset, it asks the graph four
separate questions about every candidate weakness class:

    applicability  do detection signatures for this stack actually exist,
                   and how many?
    exploitability how likely is real-world exploitation? EPSS where a CVE is
                   involved, otherwise CWE's own likelihood-of-exploit rating
    weaponisation  is there public working exploit code (Exploit-DB)?
    economics      what have bug bounty programs historically paid for this
                   class (disclosed writeup bounties), and how does Bugcrowd's
                   VRT price it?

...then combines them into one score, and for the top classes pulls the
matching CAPEC execution flow so the output is concrete steps rather than a
list of nouns. Every component of every score traces back to a citable row in
the graph — see `Recommendation.evidence`.

The weights are heuristics, not learned parameters, and they are stated
explicitly in `ScoringWeights` so they can be argued with and tuned. The
`--evaluate` path in `eval_planner.py` measures whether they actually rank
the right weakness first.

Nothing here touches a network. It reads files you produced with your own
tools and queries the local graph.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from sqlalchemy import func, select

from bountybrain.kg.db import Session
from bountybrain.kg.models import (
    CVE,
    Document,
    DocumentCoversWeakness,
    Product,
    Signature,
    SignatureDetectsWeakness,
    SignatureReferencesCVE,
    SignatureTargetsProduct,
    Technique,
    TechniqueTargetsWeakness,
    Vulnerability,
)

from .models import ReconFinding

# CWE's own qualitative rating, when no CVE-specific EPSS score applies.
LIKELIHOOD_PRIOR = {"High": 0.60, "Medium": 0.35, "Low": 0.15, "Unknown": 0.25}

# Saturation points for the log-scaled counts. Past these, more evidence stops
# meaningfully changing the ranking.
EXPLOIT_SATURATION = 25
WRITEUP_SATURATION = 60


# Smoothing strength for the conditional estimate. Interpretable as "pretend
# we saw ALPHA extra templates on this product, distributed by the global
# class prior" — so a product with two templates falls back to the prior,
# while one with hundreds is dominated by its own evidence.
SMOOTHING_ALPHA = 25.0


@dataclass(frozen=True)
class ScoringWeights:
    """Explicit, tunable weights. They sum to 1.0 for interpretability.

    `applicability` carries most of the weight because it is the only term
    conditioned on the actual technology stack; the others describe a weakness
    class in general and would otherwise just re-derive a global popularity
    ranking.
    """

    applicability: float = 0.55
    exploitability: float = 0.15
    weaponisation: float = 0.05
    economics: float = 0.25

    def normalised(self) -> "ScoringWeights":
        total = self.applicability + self.exploitability + self.weaponisation + self.economics
        if total <= 0:
            return ScoringWeights()
        return ScoringWeights(
            applicability=self.applicability / total,
            exploitability=self.exploitability / total,
            weaponisation=self.weaponisation / total,
            economics=self.economics / total,
        )


# Ranking objective. "likelihood" answers *what will this stack actually turn
# up*; "value" additionally weights by what the finding would be worth. They
# are different questions and the evaluation reports both, because value
# weighting deliberately trades ranking accuracy for usefulness.
LIKELIHOOD_ONLY = ScoringWeights(
    applicability=1.0, exploitability=0.0, weaponisation=0.0, economics=0.0
)


@dataclass
class Evidence:
    """Why a recommendation was made, with links."""

    signatures: list[dict] = field(default_factory=list)
    writeups: list[dict] = field(default_factory=list)
    cves: list[dict] = field(default_factory=list)
    matched_products: list[str] = field(default_factory=list)


@dataclass
class NextStep:
    phase: str  # Explore | Experiment | Exploit
    description: str
    techniques: list[str] = field(default_factory=list)
    capec: str | None = None
    capec_url: str | None = None


@dataclass
class Recommendation:
    cwe_id: int
    name: str
    score: float
    components: dict[str, float]
    vrt_priority: int | None
    likelihood: str | None
    mean_bounty: float | None
    median_bounty: float | None
    max_epss: float | None
    exploit_count: int
    signature_count: int
    writeup_count: int
    url: str
    next_steps: list[NextStep] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["next_steps"] = [asdict(s) for s in self.next_steps]
        d["evidence"] = asdict(self.evidence)
        return d


@dataclass
class AssetPlan:
    asset: str
    technologies: list[str]
    cves: list[str]
    endpoints: list[str]
    recommendations: list[Recommendation]
    unmatched_technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "technologies": self.technologies,
            "cves": self.cves,
            "endpoints": self.endpoints[:25],
            "unmatched_technologies": self.unmatched_technologies,
            "recommendations": [r.to_dict() for r in self.recommendations],
        }


# --------------------------------------------------------------------------
# normalisation helpers
# --------------------------------------------------------------------------


def _log_scale(value: float, saturation: float) -> float:
    """Map a count onto [0,1], with diminishing returns."""
    if value <= 0:
        return 0.0
    return min(1.0, math.log1p(value) / math.log1p(saturation))


def _money_scale(amount: float | None) -> float:
    """Map a bounty onto [0,1]. $100 -> ~0, $10k -> ~1, log-spaced."""
    if not amount or amount <= 0:
        return 0.0
    return max(0.0, min(1.0, (math.log10(amount) - 2.0) / 2.0))


_TECH_SPLIT = re.compile(r"[\s,;/|]+")


def normalise_tech_token(raw: str) -> list[str]:
    """Turn a recon fingerprint into candidate product keys.

    httpx reports things like "Apache HTTP Server:2.4.41" or "WordPress".
    We lowercase, strip versions, and emit both the whole string and its
    parts so either can match a product node.
    """
    if not raw:
        return []
    text = raw.strip().lower()
    text = re.sub(r":+[\d.]+$", "", text)  # trailing :2.4.41
    text = re.sub(r"\s+v?[\d.]+$", "", text)  # trailing " 2.4.41"
    out: list[str] = []
    if text:
        out.append(text)
        out.append(text.replace(" ", "_"))
        out.append(text.replace(" ", "-"))
        for part in _TECH_SPLIT.split(text):
            if len(part) >= 3:
                out.append(part)
    seen, uniq = set(), []
    for t in out:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


# --------------------------------------------------------------------------
# core scoring
# --------------------------------------------------------------------------


def rank_weaknesses(
    tech_tokens: Iterable[str],
    cve_ids: Iterable[str] = (),
    top_k: int = 10,
    weights: ScoringWeights | None = None,
    session=None,
    exclude_signature_paths: set[str] | None = None,
) -> tuple[list[Recommendation], list[str]]:
    """Rank weakness classes for a technology stack.

    Returns (recommendations, unmatched_tokens). Separated from the file
    parsing so it can be evaluated directly on synthetic inputs.

    `exclude_signature_paths` hides specific detection templates from the
    evidence pool. The planner's evaluation needs this: the gold label for a
    held-out template is precisely the signature->CWE edge that would
    otherwise be scored, so without excluding it the evaluation would be
    circular and would report near-perfect accuracy for free.
    """
    w = (weights or ScoringWeights()).normalised()
    tokens = {t for raw in tech_tokens for t in normalise_tech_token(raw)}
    cves = {c.upper() for c in cve_ids}

    own_session = session is None
    ctx = Session() if own_session else _NullCtx(session)
    with ctx as s:
        matched_products = _match_products(s, tokens)
        if not matched_products and not cves:
            return [], sorted(tokens)

        sig_rows = _signatures_for_products(s, list(matched_products.values()))
        if exclude_signature_paths:
            sig_rows = [r for r in sig_rows if r.path not in exclude_signature_paths]
        cve_rows = _cve_facts(s, cves)

        # candidate CWEs from signatures on the matched stack...
        per_cwe: dict[int, dict] = defaultdict(
            lambda: {"signatures": [], "max_epss": None, "products": set()}
        )
        for row in sig_rows:
            entry = per_cwe[row.cwe_id]
            entry["signatures"].append(row)
            entry["products"].add(row.product_name)
            if row.epss_score is not None:
                entry["max_epss"] = max(entry["max_epss"] or 0.0, row.epss_score)

        # ...plus any CWE implicated by a CVE the recon run already found
        for cwe_id, facts in _cwes_for_cves(s, cves).items():
            entry = per_cwe[cwe_id]
            if facts["max_epss"] is not None:
                entry["max_epss"] = max(entry["max_epss"] or 0.0, facts["max_epss"])

        if not per_cwe:
            return [], sorted(tokens - set(matched_products))

        meta = _weakness_meta(s, list(per_cwe))
        econ = _economics(s, list(per_cwe))
        weaponisation = _weaponisation(s, list(per_cwe))

        # Applicability is a *conditional* estimate: given this technology
        # stack, how much of its known weakness surface is this class? A raw
        # count saturates — every popular product has "lots" of templates for
        # several classes — and then the ranking is decided entirely by the
        # stack-independent terms, which is how an earlier version of this
        # scorer ended up losing to a plain global-frequency baseline.
        # Smoothing toward the global prior keeps sparse products sane.
        prior = _global_class_prior(s)
        observed = {c: len(e["signatures"]) for c, e in per_cwe.items()}
        total_observed = sum(observed.values())
        conditional = {
            c: (n + SMOOTHING_ALPHA * prior.get(c, 0.0))
            / (total_observed + SMOOTHING_ALPHA)
            for c, n in observed.items()
        }
        max_conditional = max(conditional.values(), default=0.0) or 1.0

        recs: list[Recommendation] = []
        for cwe_id, entry in per_cwe.items():
            m = meta.get(cwe_id)
            if not m:
                continue
            e = econ.get(cwe_id, {})
            n_exploits = weaponisation.get(cwe_id, 0)

            # scale so the strongest candidate is 1.0 and the term is
            # comparable with the other [0,1] components
            applicability = conditional.get(cwe_id, 0.0) / max_conditional
            if entry["max_epss"] is not None:
                exploitability = float(entry["max_epss"])
            else:
                exploitability = LIKELIHOOD_PRIOR.get(m["likelihood"] or "Unknown", 0.25)
            weaponised = _log_scale(n_exploits, EXPLOIT_SATURATION)

            # Economics blends what the market paid with how VRT prices the
            # class, so a weakness with few disclosed bounties still scores if
            # Bugcrowd rates it P1.
            money = _money_scale(e.get("median_bounty"))
            vrt = (6 - m["vrt_priority"]) / 5 if m["vrt_priority"] else 0.5
            volume = _log_scale(e.get("writeups", 0), WRITEUP_SATURATION)
            economics = 0.5 * money + 0.3 * vrt + 0.2 * volume

            score = (
                w.applicability * applicability
                + w.exploitability * exploitability
                + w.weaponisation * weaponised
                + w.economics * economics
            )

            top_sigs = sorted(
                entry["signatures"],
                key=lambda r: (-(r.epss_score or 0.0), -(r.cvss_score or 0.0)),
            )[:5]

            recs.append(
                Recommendation(
                    cwe_id=cwe_id,
                    name=m["name"],
                    score=round(score, 4),
                    components={
                        "applicability": round(applicability, 4),
                        "exploitability": round(exploitability, 4),
                        "weaponisation": round(weaponised, 4),
                        "economics": round(economics, 4),
                    },
                    vrt_priority=m["vrt_priority"],
                    likelihood=m["likelihood"],
                    mean_bounty=e.get("mean_bounty"),
                    median_bounty=e.get("median_bounty"),
                    max_epss=entry["max_epss"],
                    exploit_count=n_exploits,
                    signature_count=len(entry["signatures"]),
                    writeup_count=e.get("writeups", 0),
                    url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                    evidence=Evidence(
                        signatures=[
                            {
                                "name": r.name,
                                "severity": r.severity,
                                "epss": r.epss_score,
                                "cvss": r.cvss_score,
                                "url": (
                                    "https://github.com/projectdiscovery/"
                                    f"nuclei-templates/blob/main/{r.path}"
                                ),
                            }
                            for r in top_sigs
                        ],
                        matched_products=sorted(entry["products"]),
                        cves=[cve_rows[c] for c in sorted(cves) if c in cve_rows],
                    ),
                )
            )

        recs.sort(key=lambda r: -r.score)
        recs = recs[:top_k]
        _attach_next_steps(s, recs)
        _attach_writeups(s, recs)

    unmatched = sorted(tokens - set(matched_products))
    return recs, unmatched


class _NullCtx:
    """Lets `rank_weaknesses` accept a caller-managed session."""

    def __init__(self, session) -> None:
        self._s = session

    def __enter__(self):
        return self._s

    def __exit__(self, *exc) -> bool:
        return False


# --------------------------------------------------------------------------
# graph lookups
# --------------------------------------------------------------------------


_PRIOR_CACHE: dict[str, dict[int, float]] = {}


def _global_class_prior(s) -> dict[int, float]:
    """P(weakness class) across every detection template in the graph.

    Used as the smoothing target so that a product with only a handful of
    templates degrades gracefully to the population base rate instead of
    over-committing to whatever two classes happened to be observed.
    """
    if "prior" in _PRIOR_CACHE:
        return _PRIOR_CACHE["prior"]
    rows = s.execute(
        select(Vulnerability.cwe_id, func.count(SignatureDetectsWeakness.signature_id))
        .join(SignatureDetectsWeakness, SignatureDetectsWeakness.vuln_id == Vulnerability.id)
        .group_by(Vulnerability.cwe_id)
    ).all()
    total = sum(n for _, n in rows) or 1
    prior = {cwe_id: n / total for cwe_id, n in rows}
    _PRIOR_CACHE["prior"] = prior
    return prior


def _match_products(s, tokens: set[str]) -> dict[str, int]:
    if not tokens:
        return {}
    rows = s.execute(
        select(Product.name, Product.id).where(Product.name.in_(tokens))
    ).all()
    return {name: pid for name, pid in rows}


def _signatures_for_products(s, product_ids: list[int]):
    if not product_ids:
        return []
    return s.execute(
        select(
            Vulnerability.cwe_id.label("cwe_id"),
            Signature.name.label("name"),
            Signature.path.label("path"),
            Signature.severity.label("severity"),
            Signature.epss_score.label("epss_score"),
            Signature.cvss_score.label("cvss_score"),
            Product.name.label("product_name"),
        )
        .select_from(Signature)
        .join(SignatureTargetsProduct, SignatureTargetsProduct.signature_id == Signature.id)
        .join(Product, Product.id == SignatureTargetsProduct.product_id)
        .join(SignatureDetectsWeakness, SignatureDetectsWeakness.signature_id == Signature.id)
        .join(Vulnerability, Vulnerability.id == SignatureDetectsWeakness.vuln_id)
        .where(SignatureTargetsProduct.product_id.in_(product_ids))
    ).all()


def _cve_facts(s, cve_ids: set[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    rows = s.execute(
        select(CVE.cve_id, CVE.epss_score, CVE.cvss_score, CVE.exploit_count).where(
            CVE.cve_id.in_(cve_ids)
        )
    ).all()
    return {
        r.cve_id: {
            "cve_id": r.cve_id,
            "epss": r.epss_score,
            "cvss": r.cvss_score,
            "public_exploits": r.exploit_count,
            "url": f"https://nvd.nist.gov/vuln/detail/{r.cve_id}",
        }
        for r in rows
    }


def _cwes_for_cves(s, cve_ids: set[str]) -> dict[int, dict]:
    """A CVE already found by recon implicates its weakness class directly."""
    if not cve_ids:
        return {}
    rows = s.execute(
        select(Vulnerability.cwe_id, func.max(Signature.epss_score))
        .select_from(Signature)
        .join(SignatureReferencesCVE, SignatureReferencesCVE.signature_id == Signature.id)
        .join(CVE, CVE.id == SignatureReferencesCVE.cve_id)
        .join(SignatureDetectsWeakness, SignatureDetectsWeakness.signature_id == Signature.id)
        .join(Vulnerability, Vulnerability.id == SignatureDetectsWeakness.vuln_id)
        .where(CVE.cve_id.in_(cve_ids))
        .group_by(Vulnerability.cwe_id)
    ).all()
    return {r[0]: {"max_epss": r[1]} for r in rows}


def _weakness_meta(s, cwe_ids: list[int]) -> dict[int, dict]:
    rows = s.execute(
        select(
            Vulnerability.cwe_id,
            Vulnerability.name,
            Vulnerability.likelihood,
            Vulnerability.vrt_priority,
        ).where(Vulnerability.cwe_id.in_(cwe_ids))
    ).all()
    return {
        r.cwe_id: {
            "name": r.name,
            "likelihood": r.likelihood,
            "vrt_priority": r.vrt_priority,
        }
        for r in rows
    }


def _economics(s, cwe_ids: list[int]) -> dict[int, dict]:
    """Historical bounty statistics per weakness class."""
    rows = s.execute(
        select(Vulnerability.cwe_id, Document.bounty)
        .join(DocumentCoversWeakness, DocumentCoversWeakness.vuln_id == Vulnerability.id)
        .join(Document, Document.id == DocumentCoversWeakness.document_id)
        .where(
            Vulnerability.cwe_id.in_(cwe_ids),
            Document.doc_type == "writeup",
        )
    ).all()
    buckets: dict[int, list[float]] = defaultdict(list)
    counts: dict[int, int] = defaultdict(int)
    for cwe_id, bounty in rows:
        counts[cwe_id] += 1
        if bounty:
            buckets[cwe_id].append(bounty)
    out: dict[int, dict] = {}
    for cwe_id, n in counts.items():
        paid = sorted(buckets.get(cwe_id, []))
        out[cwe_id] = {
            "writeups": n,
            "paid": len(paid),
            "mean_bounty": round(sum(paid) / len(paid), 2) if paid else None,
            "median_bounty": paid[len(paid) // 2] if paid else None,
        }
    return out


def _weaponisation(s, cwe_ids: list[int]) -> dict[int, int]:
    """Public exploit count per weakness, via signature -> CVE -> Exploit-DB."""
    rows = s.execute(
        select(Vulnerability.cwe_id, func.sum(CVE.exploit_count))
        .select_from(Signature)
        .join(SignatureDetectsWeakness, SignatureDetectsWeakness.signature_id == Signature.id)
        .join(Vulnerability, Vulnerability.id == SignatureDetectsWeakness.vuln_id)
        .join(SignatureReferencesCVE, SignatureReferencesCVE.signature_id == Signature.id)
        .join(CVE, CVE.id == SignatureReferencesCVE.cve_id)
        .where(Vulnerability.cwe_id.in_(cwe_ids))
        .group_by(Vulnerability.cwe_id)
    ).all()
    return {r[0]: int(r[1] or 0) for r in rows}


def _attach_next_steps(s, recs: list[Recommendation], per_cwe: int = 2) -> None:
    """Pull CAPEC execution flows so output is actions, not nouns."""
    if not recs:
        return
    cwe_ids = [r.cwe_id for r in recs]
    rows = s.execute(
        select(
            Vulnerability.cwe_id,
            Technique.capec_id,
            Technique.name,
            Technique.execution_flow_json,
            Technique.typical_severity,
            Technique.min_skill,
        )
        .join(TechniqueTargetsWeakness, TechniqueTargetsWeakness.vuln_id == Vulnerability.id)
        .join(Technique, Technique.id == TechniqueTargetsWeakness.technique_id)
        .where(Vulnerability.cwe_id.in_(cwe_ids))
    ).all()

    by_cwe: dict[int, list] = defaultdict(list)
    for r in rows:
        by_cwe[r.cwe_id].append(r)

    for rec in recs:
        steps: list[NextStep] = []
        # Prefer patterns that actually document a flow, easiest skill first.
        candidates = sorted(
            by_cwe.get(rec.cwe_id, []),
            key=lambda r: (
                0 if r.execution_flow_json and r.execution_flow_json != "null" else 1,
                {"Low": 0, "Medium": 1, "High": 2}.get(r.min_skill or "", 3),
            ),
        )
        for cand in candidates[:per_cwe]:
            flow = json.loads(cand.execution_flow_json or "[]")
            for step in flow:
                if step.get("phase") not in ("Explore", "Experiment"):
                    continue
                steps.append(
                    NextStep(
                        phase=step.get("phase", ""),
                        description=step.get("description", ""),
                        techniques=step.get("techniques", [])[:4],
                        capec=f"CAPEC-{cand.capec_id}: {cand.name}",
                        capec_url=f"https://capec.mitre.org/data/definitions/{cand.capec_id}.html",
                    )
                )
        # Explore before Experiment, capped so the plan stays readable.
        steps.sort(key=lambda s: 0 if s.phase == "Explore" else 1)
        rec.next_steps = steps[:6]


def _attach_writeups(s, recs: list[Recommendation], per_cwe: int = 3) -> None:
    """Attach the best-paying real disclosures for each recommended class."""
    if not recs:
        return
    for rec in recs:
        rows = s.execute(
            select(Document.title, Document.url, Document.bounty, Document.published, Document.program)
            .join(DocumentCoversWeakness, DocumentCoversWeakness.document_id == Document.id)
            .join(Vulnerability, Vulnerability.id == DocumentCoversWeakness.vuln_id)
            .where(Vulnerability.cwe_id == rec.cwe_id, Document.doc_type == "writeup")
            .order_by(Document.bounty.desc().nullslast())
            .limit(per_cwe)
        ).all()
        rec.evidence.writeups = [
            {
                "title": r.title,
                "url": r.url,
                "bounty": r.bounty,
                "program": r.program,
                "published": r.published.isoformat() if r.published else None,
            }
            for r in rows
        ]


# --------------------------------------------------------------------------
# top-level: findings -> plan
# --------------------------------------------------------------------------


def plan_from_findings(
    findings: list[ReconFinding],
    top_k: int = 8,
    weights: ScoringWeights | None = None,
) -> list[AssetPlan]:
    """Group recon findings by asset and build a plan for each."""
    by_asset: dict[str, list[ReconFinding]] = defaultdict(list)
    for f in findings:
        by_asset[f.target].append(f)

    plans: list[AssetPlan] = []
    with Session() as s:
        for asset, items in sorted(by_asset.items()):
            techs = sorted({f.value for f in items if f.type == "tech"})
            cves = sorted({f.value.upper() for f in items if f.type == "cve"})
            endpoints = sorted(
                {f.value for f in items if f.type in ("url", "endpoint")}
            )
            if not techs and not cves:
                continue
            recs, unmatched = rank_weaknesses(
                techs, cves, top_k=top_k, weights=weights, session=s
            )
            plans.append(
                AssetPlan(
                    asset=asset,
                    technologies=techs,
                    cves=cves,
                    endpoints=endpoints,
                    recommendations=recs,
                    unmatched_technologies=unmatched,
                )
            )
    plans.sort(
        key=lambda p: -(p.recommendations[0].score if p.recommendations else 0.0)
    )
    return plans


def render_markdown(plans: list[AssetPlan]) -> str:
    """Human-readable engagement plan."""
    out: list[str] = ["# Recon-informed testing plan", ""]
    if not plans:
        out.append("_No assets with recognised technologies or CVEs._")
        return "\n".join(out)

    out.append(
        f"{len(plans)} asset(s) matched against the knowledge graph. "
        "Scores blend signature applicability, exploitation likelihood (EPSS), "
        "public exploit availability, and historical bounty economics."
    )
    out.append("")

    for p in plans:
        out.append(f"## {p.asset}")
        if p.technologies:
            out.append(f"**Fingerprinted:** {', '.join(p.technologies)}")
        if p.cves:
            out.append(f"**CVEs found by recon:** {', '.join(p.cves)}")
        if p.unmatched_technologies:
            out.append(
                f"_Not in graph: {', '.join(p.unmatched_technologies[:10])}_"
            )
        out.append("")
        if not p.recommendations:
            out.append("_No weakness classes matched this stack._")
            out.append("")
            continue

        out.append("| # | Weakness | Score | EPSS | Exploits | Median bounty | Signals |")
        out.append("|---|----------|-------|------|----------|---------------|---------|")
        for i, r in enumerate(p.recommendations, 1):
            epss = f"{r.max_epss:.3f}" if r.max_epss is not None else "—"
            money = f"${r.median_bounty:,.0f}" if r.median_bounty else "—"
            out.append(
                f"| {i} | [CWE-{r.cwe_id} {r.name[:44]}]({r.url}) | {r.score:.3f} | "
                f"{epss} | {r.exploit_count} | {money} | {r.signature_count} sigs, "
                f"{r.writeup_count} writeups |"
            )
        out.append("")

        for r in p.recommendations[:3]:
            out.append(f"### What to try: CWE-{r.cwe_id} {r.name}")
            if r.next_steps:
                for step in r.next_steps:
                    out.append(f"- **{step.phase}** — {step.description}")
                    for t in step.techniques:
                        out.append(f"    - {t}")
                    if step.capec_url:
                        out.append(f"    - _source: [{step.capec}]({step.capec_url})_")
            else:
                out.append("- _No CAPEC execution flow recorded for this class._")
            if r.evidence.signatures:
                out.append("")
                out.append("**Detection templates to run:**")
                for sig in r.evidence.signatures[:3]:
                    out.append(f"- [{sig['name']}]({sig['url']}) ({sig['severity']})")
            if r.evidence.writeups:
                out.append("")
                out.append("**Prior disclosures:**")
                for wu in r.evidence.writeups:
                    amt = f" — ${wu['bounty']:,.0f}" if wu["bounty"] else ""
                    out.append(f"- [{wu['title'][:80]}]({wu['url']}){amt}")
            out.append("")
    return "\n".join(out)
