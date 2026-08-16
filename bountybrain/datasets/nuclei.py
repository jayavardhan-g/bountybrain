"""Parse ProjectDiscovery nuclei templates into detection-signature records.

Nuclei is the highest-value dataset in the corpus and does triple duty:

1. **Gold labels.** ~7k templates carry a hand-assigned `cwe-id` alongside a
   severity rating and CVSS vector, which is what the extraction evaluation
   scores against — orders of magnitude more ground truth than hand
   annotation could produce.
2. **Recon bridge.** `vendor`, `product`, `framework` and `cpe` are exactly
   the fields an httpx/wappalyzer fingerprint yields, so a recon hit joins
   straight onto known weaknesses.
3. **Exploitation prior.** `epss-score` is FIRST's published probability
   that a CVE will be exploited in the wild within 30 days. That turns
   "here are some ideas" into a ranked worklist.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class Signature:
    template_id: str
    name: str
    path: str  # repo-relative, so it can be cited
    severity: str | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    authors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # classification
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[int] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cpe: str | None = None
    # metadata
    vendor: str | None = None
    product: str | None = None
    framework: str | None = None
    shodan_queries: list[str] = field(default_factory=list)
    verified: bool = False
    protocol: str | None = None  # http | dns | network | headless | ...

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get((self.severity or "info").lower(), 0)

    @property
    def tech_keys(self) -> set[str]:
        """Lowercased tokens a recon fingerprint could match against.

        Deliberately includes tags: a template tagged `wordpress` is relevant
        to a WordPress finding even when the vendor field is a plugin author.
        """
        keys = {
            v.lower()
            for v in (self.vendor, self.product, self.framework)
            if v and isinstance(v, str)
        }
        keys |= {t.lower() for t in self.tags}
        if self.cpe:
            # cpe:2.3:a:smartbear:swagger_ui:*:... -> smartbear, swagger_ui
            parts = self.cpe.split(":")
            keys |= {p.lower() for p in parts[3:5] if p and p != "*"}
        return {k for k in keys if len(k) > 1}

    def to_document(self) -> str:
        parts = [f"# {self.name}", ""]
        if self.description:
            parts += [self.description, ""]
        meta = []
        if self.severity:
            meta.append(f"severity: {self.severity}")
        if self.cvss_score is not None:
            meta.append(f"CVSS: {self.cvss_score}")
        if self.epss_score is not None:
            meta.append(f"EPSS: {self.epss_score:.4f}")
        if self.cve_ids:
            meta.append(", ".join(self.cve_ids))
        if meta:
            parts += ["**" + " | ".join(meta) + "**", ""]
        if self.impact:
            parts += ["## Impact", self.impact, ""]
        if self.remediation:
            parts += ["## Remediation", self.remediation, ""]
        stack = ", ".join(x for x in (self.vendor, self.product, self.framework) if x)
        if stack:
            parts += [f"**Affected:** {stack}", ""]
        if self.tags:
            parts += [f"**Tags:** {', '.join(self.tags)}"]
        return "\n".join(parts).strip()


def _as_list(value) -> list[str]:
    """Nuclei fields are inconsistently a scalar, a list, or a CSV string."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        if "," in value:
            return [v.strip() for v in value.split(",") if v.strip()]
        return [value.strip()] if value.strip() else []
    return [str(value)]


def _as_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_template(path: Path, repo_root: Path) -> Signature | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    if not isinstance(info, dict) or not info.get("name"):
        return None

    cls = info.get("classification") or {}
    if not isinstance(cls, dict):
        cls = {}
    md = info.get("metadata") or {}
    if not isinstance(md, dict):
        md = {}

    # Protocol is whichever top-level executor key the template uses.
    protocol = next(
        (
            k
            for k in ("http", "network", "dns", "file", "headless", "ssl", "code", "javascript")
            if k in data
        ),
        None,
    )

    cwe_ids: list[int] = []
    for raw in _as_list(cls.get("cwe-id")):
        for m in _CWE_RE.findall(raw):
            n = int(m)
            if n not in cwe_ids:
                cwe_ids.append(n)

    cve_ids: list[str] = []
    for raw in _as_list(cls.get("cve-id")):
        for m in _CVE_RE.findall(raw):
            u = m.upper()
            if u not in cve_ids:
                cve_ids.append(u)

    return Signature(
        template_id=str(data.get("id") or path.stem),
        name=str(info.get("name", "")).strip(),
        path=str(path.relative_to(repo_root)),
        severity=(str(info["severity"]).lower() if info.get("severity") else None),
        description=str(info.get("description") or "").strip(),
        impact=str(info.get("impact") or "").strip(),
        remediation=str(info.get("remediation") or "").strip(),
        authors=_as_list(info.get("author")),
        tags=_as_list(info.get("tags")),
        references=_as_list(info.get("reference")),
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        cvss_score=_as_float(cls.get("cvss-score")),
        cvss_vector=(str(cls["cvss-metrics"]) if cls.get("cvss-metrics") else None),
        epss_score=_as_float(cls.get("epss-score")),
        epss_percentile=_as_float(cls.get("epss-percentile")),
        cpe=(str(cls["cpe"]) if cls.get("cpe") else None),
        vendor=(str(md["vendor"]) if md.get("vendor") else None),
        product=(str(md["product"]) if md.get("product") else None),
        framework=(str(md["framework"]) if md.get("framework") else None),
        shodan_queries=_as_list(md.get("shodan-query")),
        verified=bool(md.get("verified", False)),
        protocol=protocol,
    )


def load(repo_dir: str | Path) -> list[Signature]:
    """Parse every template in a nuclei-templates checkout."""
    root = Path(repo_dir)
    out: list[Signature] = []
    for path in sorted(root.rglob("*.yaml")):
        # skip repo tooling / workflow definitions, keep detection templates
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        sig = parse_template(path, root)
        if sig:
            out.append(sig)
    return out


def index_by_tech(signatures: list[Signature]) -> dict[str, list[Signature]]:
    """Lowercased technology token -> signatures that target it."""
    out: dict[str, list[Signature]] = {}
    for s in signatures:
        for key in s.tech_keys:
            out.setdefault(key, []).append(s)
    return out
