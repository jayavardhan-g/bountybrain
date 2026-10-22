"""Render evaluation tables from `artifacts/` into the README.

    python report.py            # update README in place
    python report.py --print    # print the tables without writing

The README quotes a lot of numbers. Hand-copying them guarantees they drift
from what the code actually produced, and a stale metric in a README is worse
than no metric — so the tables are generated from the JSON the evaluation
suites wrote, between HTML comment markers.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import typer
from rich.console import Console

from bountybrain.config import settings

app = typer.Typer(add_completion=False, help="Render eval tables into the README")
console = Console()

README = Path("README.md")

MARKERS = {
    "retrieval": "RETRIEVAL_TABLE",
    "classification": "CLASSIFICATION_TABLE",
}


def _load(name: str) -> dict | None:
    path = Path(settings.artifact_dir) / name
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def retrieval_table() -> str:
    data = _load("eval_retrieval.json")
    if not data or not data.get("modes"):
        return "_Not yet run — `python eval.py --retrieval`._"

    rows = [
        f"**{data.get('queries', 0)} held-out queries.** "
        "Higher is better; latency is per query on one GPU.",
        "",
        "| mode | R@1 | R@5 | R@10 | MRR | nDCG@10 | median ms |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    label = {
        "bm25": "BM25 (lexical only)",
        "dense": "dense (embeddings only)",
        "hybrid": "hybrid (RRF fusion)",
        "hybrid_rerank": "hybrid + cross-encoder rerank",
    }
    best = max(
        (m.get("ndcg@10", 0) for m in data["modes"].values()), default=0
    )
    for mode, m in data["modes"].items():
        name = label.get(mode, mode)
        bold = m.get("ndcg@10", 0) == best and best > 0
        fmt = (lambda v: f"**{v:.3f}**") if bold else (lambda v: f"{v:.3f}")
        rows.append(
            f"| {'**' + name + '**' if bold else name} "
            f"| {fmt(m['recall@1'])} | {fmt(m['recall@5'])} | {fmt(m['recall@10'])} "
            f"| {fmt(m['mrr'])} | {fmt(m['ndcg@10'])} | {m['median_latency_ms']:.0f} |"
        )

    if data.get("by_doc_type"):
        rows += [
            "",
            f"Per document type ({data.get('breakdown_mode', '')}):",
            "",
            "| document type | n | R@5 | MRR |",
            "|---|---:|---:|---:|",
        ]
        for dt, m in data["by_doc_type"].items():
            rows.append(f"| {dt} | {m['n']} | {m['recall@5']:.3f} | {m['mrr']:.3f} |")

    if data.get("skipped_modes"):
        rows += ["", f"_Skipped: {', '.join(data['skipped_modes'])}._"]
    return "\n".join(rows)


def classification_table() -> str:
    data = _load("eval_classification.json")
    if not data or not data.get("sets"):
        return "_Not yet run — `python eval.py --classification`._"

    blocks: list[str] = []
    caption = {
        "nuclei": "nuclei templates (name + description + impact)",
        "pentesterland": "disclosed writeups (title only — a harder task)",
    }
    for set_name, per_method in data["sets"].items():
        blocks += [
            f"**Gold set: {caption.get(set_name, set_name)}**",
            "",
            "| strategy | n | accuracy | hierarchy ±2 | macro F1 | abstained |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        best = max((m.get("accuracy", 0) for m in per_method.values()), default=0)
        for method, m in per_method.items():
            bold = m.get("accuracy", 0) == best and best > 0
            name = f"**{method}**" if bold else method
            acc = f"**{m['accuracy']:.3f}**" if bold else f"{m['accuracy']:.3f}"
            blocks.append(
                f"| {name} | {m['n']:,} | {acc} | {m['hierarchy_match']:.3f} "
                f"| {m['macro_f1']:.3f} | {m['abstention_rate']:.3f} |"
            )
        blocks.append("")

    shortlist = data.get("shortlist") or {}
    if shortlist:
        ks = [k.split("@")[1] for k in next(iter(shortlist.values())) if k.startswith("recall@")]
        blocks += [
            "**Embedding shortlist recall** — is the gold class among the top-k "
            "candidates at all? The LLM chooses from the top 12, so recall@12 "
            "caps its accuracy.",
            "",
            "| gold set | " + " | ".join(f"R@{k}" for k in ks) + " | hierarchy ±2 R@12 |",
            "|---|" + "---:|" * (len(ks) + 1),
        ]
        for set_name, r in shortlist.items():
            blocks.append(
                f"| {set_name} | "
                + " | ".join(f"{r[f'recall@{k}']:.3f}" for k in ks)
                + f" | {r['hierarchy_recall@12']:.3f} |"
            )
        blocks.append("")

    split = data.get("llm_by_shortlist") or {}
    if split:
        blocks += [
            "**LLM accuracy, split by whether gold was on its shortlist**",
            "",
            "| gold set | gold on shortlist: n | accuracy | gold not on shortlist: n | accuracy |",
            "|---|---:|---:|---:|---:|",
        ]
        for set_name, s in split.items():
            a, b = s["gold_in_shortlist"], s["gold_not_in_shortlist"]
            blocks.append(
                f"| {set_name} | {a['n']} | {a['accuracy']:.3f} | {b['n']} | {b['accuracy']:.3f} |"
            )
        blocks.append("")
    return "\n".join(blocks).rstrip()


def _replace(text: str, marker: str, block: str) -> str:
    """Replace whatever sits between <!-- MARKER --> and <!-- /MARKER -->."""
    open_tag, close_tag = f"<!-- {marker} -->", f"<!-- /{marker} -->"
    payload = f"{open_tag}\n\n{block}\n\n{close_tag}"
    if open_tag in text and close_tag in text:
        return re.sub(
            re.escape(open_tag) + r".*?" + re.escape(close_tag),
            lambda _: payload,
            text,
            flags=re.DOTALL,
        )
    # first run: the README only has the opening marker as a placeholder
    if open_tag in text:
        return text.replace(open_tag, payload)
    return text


@app.command()
def main(
    print_only: bool = typer.Option(False, "--print", help="Print tables, do not write."),
) -> None:
    tables = {
        MARKERS["retrieval"]: retrieval_table(),
        MARKERS["classification"]: classification_table(),
    }

    if print_only:
        for marker, block in tables.items():
            console.rule(marker)
            print(block)
        raise typer.Exit()

    if not README.exists():
        console.print("[red]README.md not found[/red]")
        raise typer.Exit(code=1)

    text = README.read_text(encoding="utf-8")
    for marker, block in tables.items():
        text = _replace(text, marker, block)
    README.write_text(text, encoding="utf-8")
    console.print(f"[green]Updated {README} from {settings.artifact_dir}[/green]")


if __name__ == "__main__":
    app()
