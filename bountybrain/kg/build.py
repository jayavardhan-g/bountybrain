"""Build the knowledge graph from the parsed datasets.

Order matters. The CWE catalogue is loaded first because every other source
resolves onto it: nuclei templates carry `cwe-id`, CAPEC carries an official
CWE mapping, pentester.land labels normalise through the CWE alias map, and
VRT priorities attach to CWE ids. Load anything else first and you get
orphan nodes.

The build is idempotent — re-running upserts rather than duplicating — so it
can be re-run after a dataset refresh without rebuilding from scratch.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.orm import Session as SASession

from bountybrain.config import settings
from bountybrain.datasets import capec as capec_ds
from bountybrain.datasets import cwe as cwe_ds
from bountybrain.datasets import docs as docs_ds
from bountybrain.datasets import exploitdb as edb_ds
from bountybrain.datasets import nuclei as nuclei_ds
from bountybrain.datasets import pentesterland as pl_ds
from bountybrain.datasets import vrt as vrt_ds
from bountybrain.datasets.fetch import resolve_unpacked
from bountybrain.datasets.registry import BY_NAME
from bountybrain.kg.db import Session, init_db
from bountybrain.kg.models import (
    CVE,
    Document,
    DocumentCoversWeakness,
    Exploit,
    ExploitReferencesCVE,
    Product,
    Signature,
    SignatureDetectsWeakness,
    SignatureReferencesCVE,
    SignatureTargetsProduct,
    Technique,
    TechniqueRelation,
    TechniqueTargetsWeakness,
    Vulnerability,
    WeaknessObservedCVE,
    WeaknessRelation,
)

console = Console()

# Tokens that are too generic to be useful as a product join key — they would
# match nearly every recon fingerprint and drown the planner in noise.
GENERIC_TECH_TOKENS = {
    "cve", "panel", "tech", "misc", "exposure", "detect", "login", "config",
    "file", "http", "network", "generic", "unauth", "auth", "default",
    "disclosure", "injection", "xss", "sqli", "rce", "lfi", "ssrf", "redirect",
    "traversal", "takeover", "wordpress-plugin", "wp-plugin", "top-200",
    "top-100", "oss", "cloud", "devops", "edb", "packetstorm", "kev",
    "intrusive", "fuzz", "dast", "vuln", "wpscan", "seclists", "osint",
    "token-spray", "honeypot", "iot", "cms", "framework", "javascript",
    "headless", "dns", "ssl", "tls", "ftp", "smtp", "ssh",
}
MIN_TECH_TOKEN_LEN = 3


def _json(value) -> str | None:
    return json.dumps(value, ensure_ascii=False) if value else None


def _cve_year(cve_id: str) -> int | None:
    parts = cve_id.split("-")
    return int(parts[1]) if len(parts) > 2 and parts[1].isdigit() else None


class GraphBuilder:
    """Accumulates entities in memory, then bulk-inserts.

    Bulk insert rather than per-row ORM writes: ~47k exploits and ~13.5k
    signatures through the ORM one at a time takes minutes, through
    `bulk_insert_mappings` it takes seconds.
    """

    def __init__(self, session: SASession) -> None:
        self.s = session
        self.cwe_pk: dict[int, int] = {}       # cwe number -> vulnerabilities.id
        self.capec_pk: dict[int, int] = {}     # capec number -> techniques.id
        self.cve_pk: dict[str, int] = {}       # "CVE-2021-1234" -> cves.id
        self.product_pk: dict[str, int] = {}   # name -> products.id
        self.stats: dict[str, int] = {}

    # -- helpers ---------------------------------------------------------

    def _bulk(self, model, rows: list[dict]) -> None:
        if rows:
            self.s.bulk_insert_mappings(model, rows)
            self.s.flush()

    def _record(self, key: str, n: int) -> None:
        self.stats[key] = n

    # -- entity loaders --------------------------------------------------

    def load_weaknesses(self, weaknesses: list[cwe_ds.Weakness], vrt_priority: dict[int, int]) -> None:
        rows = [
            {
                "cwe_id": w.cwe_id,
                "name": w.name,
                "abstraction": w.abstraction,
                "status": w.status,
                "description": w.description,
                "extended_description": w.extended_description or None,
                "likelihood": w.likelihood,
                "aliases_json": _json(w.aliases),
                "languages_json": _json(w.languages),
                "technologies_json": _json(w.technologies),
                "consequences_json": _json(w.consequences),
                "detection_json": _json(w.detection_methods),
                "mitigations_json": _json(w.mitigations),
                "vrt_priority": vrt_priority.get(w.cwe_id),
            }
            for w in weaknesses
        ]
        self._bulk(Vulnerability, rows)
        self.cwe_pk = {
            cwe_id: pk
            for cwe_id, pk in self.s.execute(
                select(Vulnerability.cwe_id, Vulnerability.id)
            ).all()
        }
        self._record("vulnerabilities", len(self.cwe_pk))

        # CWE -> CWE edges, dropping any pointing at an id absent from the
        # catalogue (deprecated entries are referenced but not defined).
        edges = {
            (self.cwe_pk[w.cwe_id], self.cwe_pk[target], nature)
            for w in weaknesses
            for nature, target in w.relations
            if w.cwe_id in self.cwe_pk and target in self.cwe_pk
        }
        self._bulk(
            WeaknessRelation,
            [{"src_id": a, "dst_id": b, "nature": n} for a, b, n in edges],
        )
        self._record("weakness_relations", len(edges))

    def load_techniques(self, patterns: list[capec_ds.AttackPattern]) -> None:
        rows = [
            {
                "capec_id": p.capec_id,
                "name": p.name,
                "abstraction": p.abstraction,
                "status": p.status,
                "description": p.description,
                "extended_description": p.extended_description or None,
                "likelihood": p.likelihood,
                "typical_severity": p.typical_severity,
                "min_skill": p.min_skill,
                "prerequisites_json": _json(p.prerequisites),
                "skills_json": _json(p.skills),
                "execution_flow_json": _json(
                    [
                        {
                            "step": s.step,
                            "phase": s.phase,
                            "description": s.description,
                            "techniques": s.techniques,
                        }
                        for s in p.execution_flow
                    ]
                ),
                "mitigations_json": _json(p.mitigations),
            }
            for p in patterns
        ]
        self._bulk(Technique, rows)
        self.capec_pk = {
            cid: pk
            for cid, pk in self.s.execute(select(Technique.capec_id, Technique.id)).all()
        }
        self._record("techniques", len(self.capec_pk))

        rel = {
            (self.capec_pk[p.capec_id], self.capec_pk[t], nature)
            for p in patterns
            for nature, t in p.relations
            if p.capec_id in self.capec_pk and t in self.capec_pk
        }
        self._bulk(
            TechniqueRelation,
            [{"src_id": a, "dst_id": b, "nature": n} for a, b, n in rel],
        )
        self._record("technique_relations", len(rel))

        maps = {
            (self.capec_pk[p.capec_id], self.cwe_pk[c])
            for p in patterns
            for c in p.related_cwes
            if p.capec_id in self.capec_pk and c in self.cwe_pk
        }
        self._bulk(
            TechniqueTargetsWeakness,
            [{"technique_id": a, "vuln_id": b} for a, b in maps],
        )
        self._record("technique_targets_weakness", len(maps))

    def ensure_cves(self, cve_ids: set[str]) -> None:
        """Create CVE rows for every id referenced anywhere in the corpus."""
        missing = sorted(cve_ids - set(self.cve_pk))
        self._bulk(
            CVE,
            [{"cve_id": c, "year": _cve_year(c)} for c in missing],
        )
        self.cve_pk = {
            c: pk for c, pk in self.s.execute(select(CVE.cve_id, CVE.id)).all()
        }
        self._record("cves", len(self.cve_pk))

    def ensure_products(self, names: set[str]) -> None:
        missing = sorted(names - set(self.product_pk))
        self._bulk(Product, [{"name": n} for n in missing])
        self.product_pk = {
            n: pk for n, pk in self.s.execute(select(Product.name, Product.id)).all()
        }
        self._record("products", len(self.product_pk))

    def load_signatures(self, sigs: list[nuclei_ds.Signature]) -> None:
        self._bulk(
            Signature,
            [
                {
                    "template_id": s.template_id,
                    "name": s.name,
                    "path": s.path,
                    "severity": s.severity,
                    "protocol": s.protocol,
                    "description": s.description or None,
                    "impact": s.impact or None,
                    "remediation": s.remediation or None,
                    "cvss_score": s.cvss_score,
                    "epss_score": s.epss_score,
                    "verified": s.verified,
                    "tags_json": _json(s.tags),
                    "references_json": _json(s.references),
                }
                for s in sigs
            ],
        )
        sig_pk = {p: pk for p, pk in self.s.execute(select(Signature.path, Signature.id)).all()}
        self._record("signatures", len(sig_pk))

        det, refs, prods = set(), set(), set()
        for s in sigs:
            pk = sig_pk.get(s.path)
            if pk is None:
                continue
            for c in s.cwe_ids:
                if c in self.cwe_pk:
                    det.add((pk, self.cwe_pk[c]))
            for c in s.cve_ids:
                if c in self.cve_pk:
                    refs.add((pk, self.cve_pk[c]))
            for key in _useful_tech_keys(s):
                if key in self.product_pk:
                    prods.add((pk, self.product_pk[key]))

        self._bulk(SignatureDetectsWeakness, [{"signature_id": a, "vuln_id": b} for a, b in det])
        self._bulk(SignatureReferencesCVE, [{"signature_id": a, "cve_id": b} for a, b in refs])
        self._bulk(SignatureTargetsProduct, [{"signature_id": a, "product_id": b} for a, b in prods])
        self._record("signature_detects_weakness", len(det))
        self._record("signature_references_cve", len(refs))
        self._record("signature_targets_product", len(prods))

    def load_exploits(self, exploits: list[edb_ds.Exploit]) -> None:
        self._bulk(
            Exploit,
            [
                {
                    "edb_id": e.edb_id,
                    "description": e.description,
                    "exploit_type": e.exploit_type,
                    "platform": e.platform,
                    "verified": e.verified,
                    "published": e.published,
                    "url": e.url,
                }
                for e in exploits
            ],
        )
        ex_pk = {i: pk for i, pk in self.s.execute(select(Exploit.edb_id, Exploit.id)).all()}
        self._record("exploits", len(ex_pk))

        edges = {
            (ex_pk[e.edb_id], self.cve_pk[c])
            for e in exploits
            for c in e.cve_ids
            if e.edb_id in ex_pk and c in self.cve_pk
        }
        self._bulk(ExploitReferencesCVE, [{"exploit_id": a, "cve_id": b} for a, b in edges])
        self._record("exploit_references_cve", len(edges))

        # denormalise weaponisation counts onto the CVE rows
        counts: dict[int, int] = defaultdict(int)
        for _, cve_pk in edges:
            counts[cve_pk] += 1
        if counts:
            self.s.bulk_update_mappings(
                CVE, [{"id": pk, "exploit_count": n} for pk, n in counts.items()]
            )
            self.s.flush()

    def load_weakness_observed_cves(self, weaknesses: list[cwe_ds.Weakness]) -> None:
        edges = {
            (self.cwe_pk[w.cwe_id], self.cve_pk[c])
            for w in weaknesses
            for c in w.observed_cves
            if w.cwe_id in self.cwe_pk and c in self.cve_pk
        }
        self._bulk(WeaknessObservedCVE, [{"vuln_id": a, "cve_id": b} for a, b in edges])
        self._record("weakness_observed_cve", len(edges))

    # -- documents -------------------------------------------------------

    def load_documents(
        self,
        articles: list[docs_ds.Article],
        writeups: list[pl_ds.Writeup],
        weaknesses: list[cwe_ds.Weakness],
        patterns: list[capec_ds.AttackPattern],
    ) -> None:
        rows: list[dict] = []
        # keyed by (url, section) so edges can be attached after insert
        edge_plan: list[tuple[tuple[str, str | None], list[int]]] = []

        for a in articles:
            rows.append(
                {
                    "doc_type": "article",
                    "source": a.source,
                    "url": a.url,
                    "title": a.title,
                    "section": a.section,
                    "body": a.to_document(),
                    "external_id": a.doc_id,
                    "path": a.path,
                }
            )

        for w in writeups:
            rows.append(
                {
                    "doc_type": "writeup",
                    "source": "pentesterland",
                    "url": w.url,
                    "title": w.title or w.url,
                    "section": None,
                    "body": w.to_document(),
                    "published": w.published,
                    "program": ", ".join(w.programs) or None,
                    "bounty": w.bounty,
                    "authors_json": _json(w.authors),
                }
            )
            edge_plan.append(((w.url, None), w.cwe_ids))

        for w in weaknesses:
            rows.append(
                {
                    "doc_type": "weakness",
                    "source": "cwe",
                    "url": f"https://cwe.mitre.org/data/definitions/{w.cwe_id}.html",
                    "title": f"{w.key}: {w.name}",
                    "section": None,
                    "body": w.to_document(),
                    "external_id": w.key,
                }
            )
            edge_plan.append(
                ((f"https://cwe.mitre.org/data/definitions/{w.cwe_id}.html", None), [w.cwe_id])
            )

        for p in patterns:
            rows.append(
                {
                    "doc_type": "technique",
                    "source": "capec",
                    "url": f"https://capec.mitre.org/data/definitions/{p.capec_id}.html",
                    "title": f"{p.key}: {p.name}",
                    "section": None,
                    "body": p.to_document(),
                    "external_id": p.key,
                }
            )
            edge_plan.append(
                (
                    (f"https://capec.mitre.org/data/definitions/{p.capec_id}.html", None),
                    p.related_cwes,
                )
            )

        # De-duplicate on (url, section): a few WSTG pages repeat headings.
        seen: set[tuple[str, str | None]] = set()
        deduped = []
        for r in rows:
            key = (r["url"], r.get("section"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)

        self._bulk(Document, deduped)
        doc_pk = {
            (u, sec): pk
            for u, sec, pk in self.s.execute(
                select(Document.url, Document.section, Document.id)
            ).all()
        }
        self._record("documents", len(doc_pk))

        cover = {
            (doc_pk[key], self.cwe_pk[c])
            for key, cwes in edge_plan
            for c in cwes
            if key in doc_pk and c in self.cwe_pk
        }
        self._bulk(
            DocumentCoversWeakness,
            [
                {"document_id": a, "vuln_id": b, "provenance": "labelled", "confidence": 1.0}
                for a, b in cover
            ],
        )
        self._record("document_covers_weakness(labelled)", len(cover))


def _useful_tech_keys(sig: nuclei_ds.Signature) -> set[str]:
    """Filter a signature's tech tokens down to ones worth joining on."""
    return {
        k
        for k in sig.tech_keys
        if len(k) >= MIN_TECH_TOKEN_LEN
        and k not in GENERIC_TECH_TOKENS
        and not k.startswith("cve")
        and not k.isdigit()
    }


def build(raw_dir: str | Path | None = None) -> dict:
    """Load every dataset and materialise the graph. Returns node/edge counts."""
    raw = Path(raw_dir or settings.raw_cache_dir)
    init_db()

    console.rule("[bold cyan]Parsing datasets")
    cwe_path = resolve_unpacked(BY_NAME["cwe"])
    if cwe_path is None:
        raise FileNotFoundError("CWE catalogue not found — run `python fetch_data.py` first")
    weaknesses = cwe_ds.load(cwe_path)
    alias_map = cwe_ds.alias_map(weaknesses)
    console.print(f"  CWE weaknesses      {len(weaknesses):>7,}")

    patterns = capec_ds.load(raw / "capec_latest.xml")
    console.print(f"  CAPEC patterns      {len(patterns):>7,}")

    vrt_entries = vrt_ds.load(raw / "vrt")
    vrt_priority = vrt_ds.priority_by_cwe(vrt_entries)
    console.print(f"  VRT entries         {len(vrt_entries):>7,}  ({len(vrt_priority)} CWEs priced)")

    sigs = nuclei_ds.load(raw / "nuclei")
    console.print(f"  nuclei signatures   {len(sigs):>7,}")

    exploits = edb_ds.load(raw / "files_exploits.csv")
    console.print(f"  Exploit-DB entries  {len(exploits):>7,}")

    writeups = pl_ds.load(raw / "pentesterland_writeups.json")
    label_stats = pl_ds.normalise_labels(
        writeups, alias_map, cwe_ds.NON_VULNERABILITY_LABELS
    )
    console.print(
        f"  writeup records     {len(writeups):>7,}  "
        f"({label_stats['coverage']:.1%} of vuln-labelled resolve to CWE)"
    )

    articles = docs_ds.load_all(raw / "patt", raw / "wstg")
    console.print(f"  prose articles      {len(articles):>7,}")

    console.rule("[bold cyan]Building graph")
    with Session() as s:
        b = GraphBuilder(s)
        b.load_weaknesses(weaknesses, vrt_priority)
        b.load_techniques(patterns)

        all_cves: set[str] = set()
        for sig in sigs:
            all_cves.update(sig.cve_ids)
        for e in exploits:
            all_cves.update(e.cve_ids)
        for w in weaknesses:
            all_cves.update(w.observed_cves)
        b.ensure_cves(all_cves)

        product_names: set[str] = set()
        for sig in sigs:
            product_names.update(_useful_tech_keys(sig))
        b.ensure_products(product_names)

        b.load_signatures(sigs)
        b.load_exploits(exploits)
        b.load_weakness_observed_cves(weaknesses)
        b.load_documents(articles, writeups, weaknesses, patterns)
        stats = dict(b.stats)

    stats["_label_coverage"] = label_stats["coverage"]

    table = Table(title="Knowledge graph", show_header=True)
    table.add_column("table")
    table.add_column("rows", justify="right")
    for k, v in stats.items():
        if not k.startswith("_"):
            table.add_row(k, f"{v:,}")
    console.print(table)
    return stats
