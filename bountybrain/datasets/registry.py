"""Manifest of every external dataset BountyBrain ingests.

Each entry records where the data comes from, how to fetch it, and under
what licence it is redistributed. `fetch_data.py` walks this list.

Design rule: **bulk download only**. Every source below publishes either a
git repository or a single archive intended for bulk consumption, so
fetching the whole corpus costs a handful of requests rather than
thousands. Nothing here scrapes a site page-by-page.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from bountybrain.config import settings


@dataclass(frozen=True)
class Dataset:
    """One external corpus."""

    name: str
    kind: str  # "git" | "archive" | "file"
    url: str
    dest: str  # directory or filename under data/raw/
    license: str
    attribution: str
    description: str
    # For archives: the file we expect after unpacking (glob).
    unpacked_glob: str | None = None
    # Shallow clones only — we want the current state, not the history.
    git_depth: int = 1
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def path(self) -> Path:
        return Path(settings.raw_cache_dir) / self.dest

    def exists(self) -> bool:
        p = self.path
        if not p.exists():
            return False
        if self.kind == "git":
            return (p / ".git").exists()
        return p.stat().st_size > 0


DATASETS: list[Dataset] = [
    # ---------- ontology backbone ----------
    Dataset(
        name="cwe",
        kind="archive",
        url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        dest="cwec_latest.xml.zip",
        unpacked_glob="cwec_v*.xml",
        license="CWE is free to use with attribution (MITRE Terms of Use)",
        attribution="CWE™ is a trademark of The MITRE Corporation. https://cwe.mitre.org/",
        description=(
            "Common Weakness Enumeration catalog: ~940 weakness classes with a real "
            "ChildOf/PeerOf/CanPrecede hierarchy, consequences, detection methods, "
            "mitigations and observed CVE examples."
        ),
        tags=("ontology", "weakness"),
    ),
    Dataset(
        name="capec",
        kind="file",
        url="https://capec.mitre.org/data/xml/capec_latest.xml",
        dest="capec_latest.xml",
        license="CAPEC is free to use with attribution (MITRE Terms of Use)",
        attribution="CAPEC™ is a trademark of The MITRE Corporation. https://capec.mitre.org/",
        description=(
            "Common Attack Pattern Enumeration and Classification: ~600 attack patterns "
            "with step-by-step execution flows, prerequisites, required skill levels, "
            "mitigations, and the official CAPEC->CWE mapping."
        ),
        tags=("ontology", "technique"),
    ),
    Dataset(
        name="vrt",
        kind="git",
        url="https://github.com/bugcrowd/vulnerability-rating-taxonomy.git",
        dest="vrt",
        license="Apache-2.0",
        attribution="Bugcrowd Vulnerability Rating Taxonomy",
        description=(
            "Bugcrowd's VRT: the payout-priority taxonomy (P1-P5) bug bounty programs "
            "actually triage against, with CWE cross-references."
        ),
        tags=("ontology", "priority"),
    ),
    # ---------- instance data ----------
    Dataset(
        name="nuclei",
        kind="git",
        url="https://github.com/projectdiscovery/nuclei-templates.git",
        dest="nuclei",
        license="MIT",
        attribution="ProjectDiscovery nuclei-templates",
        description=(
            "~13.5k detection templates. Each carries severity, CVE id, CWE id, CVSS "
            "vector and score, EPSS exploitation probability, CPE, vendor/product and "
            "tags — the single richest gold-labelled source in the corpus, and the "
            "bridge between a recon fingerprint and a known weakness."
        ),
        tags=("instance", "detection", "gold"),
    ),
    Dataset(
        name="exploitdb",
        kind="file",
        url="https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        dest="files_exploits.csv",
        license="GPL-2.0 (Exploit Database)",
        attribution="OffSec Exploit Database",
        description=(
            "~46k catalogued public exploits with type, platform, verification status "
            "and CVE cross-references — evidence that a weakness class is weaponised."
        ),
        tags=("instance", "exploit"),
    ),
    Dataset(
        name="pentesterland",
        kind="file",
        url="https://pentester.land/writeups.json",
        dest="pentesterland_writeups.json",
        license="Index metadata, published as a public JSON feed",
        attribution="pentester.land List of Bug Bounty Writeups",
        description=(
            "Index of ~6.4k real disclosed bug bounty writeups (2013-2024) with "
            "curated vulnerability labels, program names, bounty amounts and authors. "
            "We ingest the metadata feed only — a single request, no page scraping."
        ),
        tags=("instance", "writeup", "gold"),
    ),
    # ---------- prose corpus ----------
    Dataset(
        name="payloadsallthethings",
        kind="git",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        dest="patt",
        license="MIT",
        attribution="swisskyrepo/PayloadsAllTheThings",
        description=(
            "Practitioner reference for web exploitation techniques, payloads and "
            "filter bypasses, organised by vulnerability class."
        ),
        tags=("prose", "technique"),
    ),
    Dataset(
        name="wstg",
        kind="git",
        url="https://github.com/OWASP/wstg.git",
        dest="wstg",
        license="CC-BY-SA-4.0",
        attribution="OWASP Web Security Testing Guide",
        description=(
            "OWASP's structured testing methodology: ~160 test procedures, each with "
            "objectives, how-to-test steps and remediation."
        ),
        tags=("prose", "methodology"),
    ),
]

BY_NAME: dict[str, Dataset] = {d.name: d for d in DATASETS}


def dataset_status() -> list[dict]:
    """Report which datasets are present on disk. Used by `fetch_data.py --status`."""
    rows = []
    for d in DATASETS:
        present = d.exists()
        size = 0
        if present:
            p = d.path
            if p.is_dir():
                size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
            else:
                size = p.stat().st_size
        rows.append(
            {
                "name": d.name,
                "present": present,
                "size_mb": round(size / 1e6, 1),
                "license": d.license,
                "path": str(d.path),
            }
        )
    return rows
