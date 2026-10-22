"""Run the evaluation suites.

    python eval.py --all                    # everything available
    python eval.py --generate-queries       # (re)build the retrieval query set
    python eval.py --retrieval              # retrieval ablation only
    python eval.py --classification         # CWE classification only
    python eval.py --planner                # recon planner only
    python eval.py --faithfulness           # tutorial citation faithfulness (needs an LLM)
    python eval.py --learning-path          # learning-path completeness from the graph

Results land in `artifacts/` as JSON, one file per suite, plus a combined
`eval_summary.json`. Suites that need an LLM are skipped with a clear message
when no server is reachable, rather than silently reporting zeros.
"""
from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.rule import Rule

from bountybrain.clients.llm import is_available as llm_available
from bountybrain.config import settings

app = typer.Typer(add_completion=False, help="Run BountyBrain evaluations")
console = Console()


@app.command()
def main(
    all_suites: bool = typer.Option(False, "--all", help="Run every available suite."),
    retrieval: bool = typer.Option(False, "--retrieval", help="Retrieval ablation."),
    classification: bool = typer.Option(False, "--classification", help="CWE classification."),
    planner: bool = typer.Option(False, "--planner", help="Recon planner ranking."),
    faithfulness: bool = typer.Option(
        False, "--faithfulness", help="Citation faithfulness of generated tutorials (needs an LLM)."
    ),
    dev_topics: bool = typer.Option(
        False, "--dev-topics", help="Faithfulness on the dev topics (for prompt work), not the test set."
    ),
    learning_path: bool = typer.Option(
        False, "--learning-path", help="How often the graph fills a complete learning path."
    ),
    regenerate_tutorials: bool = typer.Option(
        False,
        "--regenerate-tutorials",
        help="Regenerate the faithfulness tutorials instead of re-judging the committed ones. "
        "Invalidates the hand labels.",
    ),
    generate_queries: bool = typer.Option(
        False, "--generate-queries", help="Regenerate the retrieval query fixture (needs an LLM)."
    ),
    n_queries: int = typer.Option(200, "--n-queries", help="Queries to generate."),
    n_per_source: int = typer.Option(
        500, "--n-per-source", help="Classification items per gold set."
    ),
    planner_cases: int = typer.Option(400, "--planner-cases", help="Held-out planner cases."),
) -> None:
    if not any([all_suites, retrieval, classification, planner, faithfulness, learning_path, generate_queries]):
        all_suites = True

    has_llm = llm_available()
    if has_llm:
        console.print(f"[green]LLM reachable[/green] ({settings.llm_provider}: {settings.llm_model})")
    else:
        console.print(
            "[yellow]No LLM reachable — LLM-dependent arms will be skipped. "
            "Start one with `python serve_llm.py`.[/yellow]"
        )

    summary: dict = {}

    if generate_queries:
        console.print(Rule("Generating retrieval queries"))
        if not has_llm:
            console.print("[red]Query generation needs an LLM. Skipped.[/red]")
        else:
            from bountybrain.eval import retrieval as retr

            queries = retr.generate_queries(n=n_queries)
            path = retr.save_queries(queries)
            console.print(f"[green]Saved {len(queries)} queries to {path}[/green]")
            summary["generated_queries"] = len(queries)

    if all_suites or retrieval:
        console.print(Rule("Retrieval ablation"))
        from bountybrain.eval import retrieval as retr

        if not retr.load_queries():
            console.print(
                "[yellow]No query fixture found. Run `python eval.py --generate-queries` "
                "first (needs an LLM). Skipping retrieval.[/yellow]"
            )
        else:
            summary["retrieval"] = retr.evaluate_and_save()

    if all_suites or classification:
        console.print(Rule("CWE classification"))
        from bountybrain.eval import classification as clf

        methods = ["keyword", "embedding"] + (["llm"] if has_llm else [])
        summary["classification"] = clf.evaluate_and_save(
            methods=methods, n_per_source=n_per_source
        )

    if all_suites or planner:
        console.print(Rule("Recon planner"))
        from bountybrain.eval import planner as pl

        summary["planner"] = pl.evaluate_and_save(max_cases=planner_cases)

    if all_suites or learning_path:
        console.print(Rule("Learning path completeness"))
        from bountybrain.eval import learning_path as lp

        summary["learning_path"] = lp.evaluate_and_save()

    if all_suites or faithfulness:
        console.print(Rule("Tutorial faithfulness"))
        if not has_llm:
            console.print("[yellow]Faithfulness needs an LLM (generator and judge). Skipped.[/yellow]")
        else:
            from bountybrain.eval import faithfulness as faith

            summary["faithfulness"] = faith.evaluate_and_save(
                regenerate=regenerate_tutorials or dev_topics, dev=dev_topics
            )

    # Merge rather than overwrite: running one suite should not erase the
    # others' last results from the summary.
    out = settings.artifact_dir / "eval_summary.json"
    previous = json.loads(out.read_text()) if out.exists() else {}
    out.write_text(json.dumps({**previous, **summary}, indent=2, default=str))
    console.print(f"\n[green]Wrote {out}[/green]")


if __name__ == "__main__":
    app()
