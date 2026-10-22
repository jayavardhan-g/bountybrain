"""Measure the knowledge graph.

Two kinds of number live here, and it is worth keeping them apart:

*Structural* metrics describe the graph as a graph — node and edge counts by
type, density, degree distribution, connected components, centrality. They
say how well-connected the thing is.

*Coverage* metrics describe how much of the ontology is actually backed by
evidence: what fraction of weakness classes have a known attack pattern, a
detection signature, a public exploit, a real disclosed writeup. A graph can
look impressively large while most of its nodes are isolated, so coverage is
the honest counterpart to size.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from typing import Any

import networkx as nx
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select

from bountybrain.config import settings
from bountybrain.kg.db import Session
from bountybrain.kg.models import (
    CVE,
    EDGE_MODELS,
    ENTITY_MODELS,
    Document,
    DocumentCoversWeakness,
    Exploit,
    ExploitReferencesCVE,
    Product,
    Signature,
    SignatureDetectsWeakness,
    SignatureTargetsProduct,
    Technique,
    TechniqueRelation,
    TechniqueTargetsWeakness,
    Vulnerability,
    WeaknessObservedCVE,
    WeaknessRelation,
)

console = Console()


# --------------------------------------------------------------------------
# graph assembly
# --------------------------------------------------------------------------


def build_networkx(session) -> nx.MultiDiGraph:
    """Materialise the whole KG as a typed NetworkX graph.

    Node ids are namespaced (`cwe:89`, `capec:66`, `sig:123`) so the several
    entity tables can share one graph without primary keys colliding.
    """
    g = nx.MultiDiGraph()

    for v in session.execute(
        select(Vulnerability.id, Vulnerability.cwe_id, Vulnerability.name, Vulnerability.abstraction)
    ).all():
        g.add_node(f"cwe:{v.id}", kind="weakness", label=f"CWE-{v.cwe_id}", name=v.name,
                   abstraction=v.abstraction)

    for t in session.execute(
        select(Technique.id, Technique.capec_id, Technique.name, Technique.abstraction)
    ).all():
        g.add_node(f"capec:{t.id}", kind="technique", label=f"CAPEC-{t.capec_id}", name=t.name,
                   abstraction=t.abstraction)

    for c in session.execute(select(CVE.id, CVE.cve_id)).all():
        g.add_node(f"cve:{c.id}", kind="cve", label=c.cve_id)

    for p in session.execute(select(Product.id, Product.name)).all():
        g.add_node(f"product:{p.id}", kind="product", label=p.name)

    for s in session.execute(select(Signature.id, Signature.name)).all():
        g.add_node(f"sig:{s.id}", kind="signature", label=s.name)

    for e in session.execute(select(Exploit.id, Exploit.edb_id)).all():
        g.add_node(f"exploit:{e.id}", kind="exploit", label=f"EDB-{e.edb_id}")

    for d in session.execute(select(Document.id, Document.title, Document.doc_type)).all():
        g.add_node(f"doc:{d.id}", kind="document", label=d.title[:80], doc_type=d.doc_type)

    def add_edges(rows, src_fmt: str, dst_fmt: str, kind: str, nature_attr=None) -> None:
        for r in rows:
            src, dst = src_fmt.format(r[0]), dst_fmt.format(r[1])
            if g.has_node(src) and g.has_node(dst):
                g.add_edge(src, dst, kind=kind, nature=(r[2] if nature_attr else kind))

    add_edges(
        session.execute(
            select(WeaknessRelation.src_id, WeaknessRelation.dst_id, WeaknessRelation.nature)
        ).all(),
        "cwe:{}", "cwe:{}", "weakness_relation", nature_attr=True,
    )
    add_edges(
        session.execute(
            select(TechniqueRelation.src_id, TechniqueRelation.dst_id, TechniqueRelation.nature)
        ).all(),
        "capec:{}", "capec:{}", "technique_relation", nature_attr=True,
    )
    add_edges(
        session.execute(
            select(TechniqueTargetsWeakness.technique_id, TechniqueTargetsWeakness.vuln_id)
        ).all(),
        "capec:{}", "cwe:{}", "technique_targets_weakness",
    )
    add_edges(
        session.execute(
            select(WeaknessObservedCVE.vuln_id, WeaknessObservedCVE.cve_id)
        ).all(),
        "cwe:{}", "cve:{}", "weakness_observed_cve",
    )
    add_edges(
        session.execute(
            select(SignatureDetectsWeakness.signature_id, SignatureDetectsWeakness.vuln_id)
        ).all(),
        "sig:{}", "cwe:{}", "signature_detects_weakness",
    )
    add_edges(
        session.execute(
            select(SignatureTargetsProduct.signature_id, SignatureTargetsProduct.product_id)
        ).all(),
        "sig:{}", "product:{}", "signature_targets_product",
    )
    add_edges(
        session.execute(
            select(ExploitReferencesCVE.exploit_id, ExploitReferencesCVE.cve_id)
        ).all(),
        "exploit:{}", "cve:{}", "exploit_references_cve",
    )
    add_edges(
        session.execute(
            select(DocumentCoversWeakness.document_id, DocumentCoversWeakness.vuln_id)
        ).all(),
        "doc:{}", "cwe:{}", "document_covers_weakness",
    )
    return g


# --------------------------------------------------------------------------
# metric blocks
# --------------------------------------------------------------------------


def table_counts(session) -> dict[str, int]:
    counts: dict[str, int] = {}
    for model in ENTITY_MODELS + EDGE_MODELS:
        counts[model.__tablename__] = session.execute(
            select(func.count()).select_from(model)
        ).scalar_one()
    return counts


# The ontology core: everything except the CVE and exploit records, most of
# which sit in two-node CVE↔exploit components that no template references.
CORE_KINDS = {"weakness", "technique", "signature", "product", "document"}


def core_subgraph(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    keep = [n for n, d in g.nodes(data=True) if d.get("kind") in CORE_KINDS]
    return g.subgraph(keep).copy()


def structural_metrics(g: nx.MultiDiGraph) -> dict[str, Any]:
    simple = nx.Graph(g)  # undirected, de-duplicated, for component/degree work
    degrees = [d for _, d in simple.degree()]
    components = list(nx.connected_components(simple))
    largest = max(components, key=len) if components else set()

    n, m = g.number_of_nodes(), g.number_of_edges()
    return {
        "nodes": n,
        "edges": m,
        "node_kinds": dict(Counter(nx.get_node_attributes(g, "kind").values())),
        "edge_kinds": dict(Counter(d["kind"] for _, _, d in g.edges(data=True))),
        "density": round(nx.density(simple), 8),
        "mean_degree": round(statistics.mean(degrees), 3) if degrees else 0.0,
        "median_degree": statistics.median(degrees) if degrees else 0,
        "max_degree": max(degrees) if degrees else 0,
        "isolated_nodes": sum(1 for d in degrees if d == 0),
        "connected_components": len(components),
        "largest_component_size": len(largest),
        "largest_component_share": round(len(largest) / n, 4) if n else 0.0,
    }


def hierarchy_metrics(session) -> dict[str, Any]:
    """Shape of the CWE taxonomy: how deep it goes and how it branches."""
    rows = session.execute(
        select(WeaknessRelation.src_id, WeaknessRelation.dst_id).where(
            WeaknessRelation.nature == "ChildOf"
        )
    ).all()
    child_of = nx.DiGraph()
    for src, dst in rows:
        child_of.add_edge(src, dst)  # child -> parent

    if child_of.number_of_nodes() == 0:
        return {}

    roots = [n for n in child_of if child_of.out_degree(n) == 0]
    leaves = [n for n in child_of if child_of.in_degree(n) == 0]

    depths: list[int] = []
    for leaf in leaves:
        d, cur, seen = 0, leaf, set()
        while cur in child_of and child_of.out_degree(cur) > 0 and cur not in seen:
            seen.add(cur)
            cur = next(iter(child_of.successors(cur)))
            d += 1
        depths.append(d)

    abstraction = session.execute(
        select(Vulnerability.abstraction, func.count()).group_by(Vulnerability.abstraction)
    ).all()

    return {
        "childof_edges": len(rows),
        "roots": len(roots),
        "leaves": len(leaves),
        "max_depth": max(depths) if depths else 0,
        "mean_depth": round(statistics.mean(depths), 2) if depths else 0.0,
        "abstraction_levels": {a or "unknown": c for a, c in abstraction},
    }


def centrality_metrics(g: nx.MultiDiGraph, session, top_n: int = 10) -> dict[str, Any]:
    """PageRank over the weakness and technique sub-graphs.

    Run per-subgraph rather than over everything: with ~47k exploit nodes
    hanging off CVEs, whole-graph PageRank mostly measures how many exploits
    a CVE has, which is not an interesting statement about weaknesses.
    """
    out: dict[str, Any] = {}

    for kind, prefix, model, id_attr in (
        ("weakness", "cwe:", Vulnerability, "cwe_id"),
        ("technique", "capec:", Technique, "capec_id"),
    ):
        nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == kind]
        sub = nx.DiGraph(g.subgraph(nodes))
        if sub.number_of_edges() == 0:
            continue
        pr = nx.pagerank(sub)
        top = sorted(pr.items(), key=lambda kv: -kv[1])[:top_n]
        labels = {f"{prefix}{r[0]}": (r[1], r[2]) for r in session.execute(
            select(model.id, getattr(model, id_attr), model.name)
        ).all()}
        out[f"{kind}_pagerank_top"] = [
            {
                "id": labels.get(node, ("?", "?"))[0],
                "name": labels.get(node, ("?", "?"))[1],
                "score": round(score, 6),
            }
            for node, score in top
        ]
    return out


def coverage_metrics(session) -> dict[str, Any]:
    """How much of the weakness ontology is backed by real evidence."""
    total_cwe = session.execute(select(func.count()).select_from(Vulnerability)).scalar_one()

    def distinct_cwes(model, col) -> int:
        return session.execute(
            select(func.count(func.distinct(col))).select_from(model)
        ).scalar_one()

    with_technique = distinct_cwes(TechniqueTargetsWeakness, TechniqueTargetsWeakness.vuln_id)
    with_signature = distinct_cwes(SignatureDetectsWeakness, SignatureDetectsWeakness.vuln_id)
    with_cve = distinct_cwes(WeaknessObservedCVE, WeaknessObservedCVE.vuln_id)

    # Every CWE trivially "has a document" — its own catalogue page is one.
    # Counting that would report 100% coverage and mean nothing, so external
    # evidence is counted separately by document type.
    def cwes_with_doc_type(*doc_types: str) -> int:
        return session.execute(
            select(func.count(func.distinct(DocumentCoversWeakness.vuln_id)))
            .select_from(DocumentCoversWeakness)
            .join(Document, Document.id == DocumentCoversWeakness.document_id)
            .where(Document.doc_type.in_(doc_types))
        ).scalar_one()

    with_document = distinct_cwes(DocumentCoversWeakness, DocumentCoversWeakness.vuln_id)
    with_writeup = cwes_with_doc_type("writeup")
    with_external_doc = cwes_with_doc_type("writeup", "article", "technique")
    priced = session.execute(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.vrt_priority.isnot(None))
    ).scalar_one()

    def pct(x: int) -> float:
        return round(x / total_cwe, 4) if total_cwe else 0.0

    return {
        "weaknesses_total": total_cwe,
        "with_attack_pattern": with_technique,
        "with_attack_pattern_pct": pct(with_technique),
        "with_detection_signature": with_signature,
        "with_detection_signature_pct": pct(with_signature),
        "with_any_document": with_document,
        "with_any_document_pct": pct(with_document),
        "with_any_document_note": (
            "trivially near-100%: each CWE's own catalogue page is a document"
        ),
        "with_disclosed_writeup": with_writeup,
        "with_disclosed_writeup_pct": pct(with_writeup),
        "with_external_document": with_external_doc,
        "with_external_document_pct": pct(with_external_doc),
        "with_observed_cve": with_cve,
        "with_observed_cve_pct": pct(with_cve),
        "with_vrt_priority": priced,
        "with_vrt_priority_pct": pct(priced),
    }


def corpus_metrics(session) -> dict[str, Any]:
    by_type = dict(
        session.execute(
            select(Document.doc_type, func.count()).group_by(Document.doc_type)
        ).all()
    )
    by_source = dict(
        session.execute(
            select(Document.source, func.count()).group_by(Document.source)
        ).all()
    )
    lengths = [
        r[0]
        for r in session.execute(select(func.length(Document.body))).all()
        if r[0] is not None
    ]
    # Grouped in Python rather than SQL: `strftime` is SQLite-only and
    # `date_part` is Postgres-only, so doing it here keeps the metrics
    # identical whichever backend DATABASE_URL points at.
    year_counts: Counter = Counter()
    for (published,) in session.execute(
        select(Document.published).where(Document.published.isnot(None))
    ).all():
        if published is not None:
            year_counts[str(published.year)] += 1
    by_year = dict(sorted(year_counts.items()))
    return {
        "documents_total": sum(by_type.values()),
        "by_type": by_type,
        "by_source": by_source,
        "body_chars_mean": round(statistics.mean(lengths)) if lengths else 0,
        "body_chars_median": round(statistics.median(lengths)) if lengths else 0,
        "body_chars_total": sum(lengths),
        "writeups_by_year": by_year,
    }


def economic_metrics(session, min_paid: int = 10, top_n: int = 15) -> dict[str, Any]:
    """What each weakness class actually pays, from disclosed writeup bounties.

    This is the prior the recon planner ranks with: severity says how bad a
    bug is, bounty says what the market pays for finding it, and they differ.
    """
    rows = session.execute(
        select(Vulnerability.cwe_id, Vulnerability.name, Document.bounty)
        .join(DocumentCoversWeakness, DocumentCoversWeakness.vuln_id == Vulnerability.id)
        .join(Document, Document.id == DocumentCoversWeakness.document_id)
        .where(Document.doc_type == "writeup")
    ).all()

    buckets: dict[tuple[int, str], list[float]] = defaultdict(list)
    counts: Counter = Counter()
    for cwe_id, name, bounty in rows:
        counts[(cwe_id, name)] += 1
        if bounty:
            buckets[(cwe_id, name)].append(bounty)

    table = []
    for (cwe_id, name), paid in buckets.items():
        if len(paid) < min_paid:
            continue
        paid.sort()
        table.append(
            {
                "cwe_id": cwe_id,
                "name": name,
                "writeups": counts[(cwe_id, name)],
                "paid_writeups": len(paid),
                "mean_bounty": round(statistics.mean(paid), 2),
                "median_bounty": round(statistics.median(paid), 2),
                "max_bounty": paid[-1],
            }
        )
    table.sort(key=lambda r: -r["mean_bounty"])
    return {
        "min_paid_threshold": min_paid,
        "classes_ranked": len(table),
        "top_by_mean_bounty": table[:top_n],
        "most_reported": [
            {"cwe_id": c, "name": n, "writeups": v}
            for (c, n), v in counts.most_common(top_n)
        ],
    }


def compute_all() -> dict[str, Any]:
    with Session() as s:
        console.print("[dim]counting tables…[/dim]")
        counts = table_counts(s)
        console.print("[dim]assembling networkx graph…[/dim]")
        g = build_networkx(s)
        console.print("[dim]computing metrics…[/dim]")
        result = {
            "tables": counts,
            "structure": structural_metrics(g),
            "core_structure": structural_metrics(core_subgraph(g)),
            "hierarchy": hierarchy_metrics(s),
            "centrality": centrality_metrics(g, s),
            "coverage": coverage_metrics(s),
            "corpus": corpus_metrics(s),
            "economics": economic_metrics(s),
        }
    return result


def render(metrics: dict[str, Any]) -> None:
    st = metrics["structure"]
    console.rule("[bold cyan]Knowledge graph")
    console.print(
        f"[bold]{st['nodes']:,}[/bold] nodes  ·  [bold]{st['edges']:,}[/bold] edges  ·  "
        f"density {st['density']:.2e}  ·  mean degree {st['mean_degree']}"
    )
    console.print(
        f"largest component holds {st['largest_component_share']:.1%} of nodes "
        f"({st['connected_components']:,} components, {st['isolated_nodes']:,} isolated)"
    )

    t = Table(title="Nodes by type")
    t.add_column("type")
    t.add_column("count", justify="right")
    for k, v in sorted(st["node_kinds"].items(), key=lambda kv: -kv[1]):
        t.add_row(k, f"{v:,}")
    console.print(t)

    t = Table(title="Edges by type")
    t.add_column("type")
    t.add_column("count", justify="right")
    for k, v in sorted(st["edge_kinds"].items(), key=lambda kv: -kv[1]):
        t.add_row(k, f"{v:,}")
    console.print(t)

    cov = metrics["coverage"]
    t = Table(title=f"Weakness coverage (of {cov['weaknesses_total']:,} CWEs)")
    t.add_column("backed by")
    t.add_column("count", justify="right")
    t.add_column("%", justify="right")
    for label, key in [
        ("attack pattern (CAPEC)", "with_attack_pattern"),
        ("detection signature (nuclei)", "with_detection_signature"),
        ("disclosed writeup", "with_disclosed_writeup"),
        ("external document (writeup/article/CAPEC)", "with_external_document"),
        ("observed CVE", "with_observed_cve"),
        ("VRT payout priority", "with_vrt_priority"),
    ]:
        t.add_row(label, f"{cov[key]:,}", f"{cov[key + '_pct']:.1%}")
    console.print(t)

    econ = metrics["economics"]
    if econ["top_by_mean_bounty"]:
        t = Table(title=f"Best-paying weakness classes (≥{econ['min_paid_threshold']} paid writeups)")
        for c in ("CWE", "name", "paid", "mean", "median", "max"):
            t.add_column(c, justify="right" if c in ("paid", "mean", "median", "max") else "left")
        for r in econ["top_by_mean_bounty"][:10]:
            t.add_row(
                f"CWE-{r['cwe_id']}", r["name"][:44], str(r["paid_writeups"]),
                f"${r['mean_bounty']:,.0f}", f"${r['median_bounty']:,.0f}", f"${r['max_bounty']:,.0f}",
            )
        console.print(t)


def compute_and_save(path=None) -> dict[str, Any]:
    metrics = compute_all()
    out = path or (settings.artifact_dir / "graph_metrics.json")
    out.write_text(json.dumps(metrics, indent=2, default=str))
    render(metrics)
    console.print(f"[green]Wrote {out}[/green]")
    return metrics
