"""Export the knowledge graph for external tools.

    python export_graph.py --format graphml     # Gephi, yEd, Cytoscape
    python export_graph.py --format csv         # neo4j-admin import, pandas
    python export_graph.py --core-only          # ontology core, no CVE/exploit tail

GraphML of the full graph is ~112k nodes, which most desktop visualisers will
render but few will render *usefully*. `--core-only` drops the CVE and exploit
nodes — 77k of the total, and the part that contributes the long tail of
disconnected pairs — leaving the CWE/CAPEC/signature/product/document core that
is actually worth looking at.
"""
from __future__ import annotations

import csv
from pathlib import Path

import networkx as nx
import typer
from rich.console import Console

from bountybrain.config import settings
from bountybrain.kg.db import Session
from bountybrain.kg.metrics import build_networkx

app = typer.Typer(add_completion=False, help="Export the knowledge graph")
console = Console()

CORE_KINDS = {"weakness", "technique", "signature", "product", "document"}


def _filter_core(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    keep = [n for n, d in g.nodes(data=True) if d.get("kind") in CORE_KINDS]
    return g.subgraph(keep).copy()


def _write_graphml(g: nx.MultiDiGraph, path: Path) -> None:
    # GraphML has no null type; drop empty attributes rather than emit invalid XML.
    clean = nx.MultiDiGraph()
    for node, data in g.nodes(data=True):
        clean.add_node(node, **{k: v for k, v in data.items() if v is not None})
    for u, v, data in g.edges(data=True):
        clean.add_edge(u, v, **{k: val for k, val in data.items() if val is not None})
    nx.write_graphml(clean, path)


def _write_csv(g: nx.MultiDiGraph, out_dir: Path) -> tuple[Path, Path]:
    nodes_path = out_dir / "kg_nodes.csv"
    edges_path = out_dir / "kg_edges.csv"

    with nodes_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "kind", "label", "name", "abstraction", "doc_type"])
        for node, d in g.nodes(data=True):
            w.writerow(
                [
                    node,
                    d.get("kind", ""),
                    d.get("label", ""),
                    d.get("name", ""),
                    d.get("abstraction", ""),
                    d.get("doc_type", ""),
                ]
            )

    with edges_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source", "target", "kind", "nature"])
        for u, v, d in g.edges(data=True):
            w.writerow([u, v, d.get("kind", ""), d.get("nature", "")])

    return nodes_path, edges_path


@app.command()
def main(
    fmt: str = typer.Option("graphml", "--format", help="graphml | csv | both"),
    core_only: bool = typer.Option(
        False, "--core-only", help="Drop CVE and exploit nodes (77k of 112k)."
    ),
    out: Path = typer.Option(None, "--out", help="Output directory (default: artifacts/)."),
) -> None:
    out_dir = out or Path(settings.artifact_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print("[cyan]Assembling graph…[/cyan]")
    with Session() as s:
        g = build_networkx(s)

    if core_only:
        before = g.number_of_nodes()
        g = _filter_core(g)
        console.print(f"  core-only: {before:,} → {g.number_of_nodes():,} nodes")

    suffix = "_core" if core_only else ""
    console.print(f"  {g.number_of_nodes():,} nodes, {g.number_of_edges():,} edges")

    if fmt in ("graphml", "both"):
        path = out_dir / f"knowledge_graph{suffix}.graphml"
        _write_graphml(g, path)
        console.print(f"[green]Wrote {path} ({path.stat().st_size / 1e6:.1f} MB)[/green]")

    if fmt in ("csv", "both"):
        nodes_path, edges_path = _write_csv(g, out_dir)
        console.print(f"[green]Wrote {nodes_path} and {edges_path}[/green]")

    if fmt not in ("graphml", "csv", "both"):
        console.print(f"[red]Unknown format {fmt!r}; expected graphml, csv or both.[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
