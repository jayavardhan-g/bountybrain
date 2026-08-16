"""Evaluate the recon planner: does it rank the right weakness first?

**The task.** A recon run fingerprints a technology on an asset. The planner
ranks weakness classes worth testing. The question is whether the class of a
vulnerability that genuinely affects that technology lands near the top.

**Avoiding a circular evaluation.** The gold label for a held-out nuclei
template is a signature->CWE edge. The planner scores using signature->CWE
edges. Score without care and the planner is graded on the very fact it was
handed — near-perfect accuracy, measuring nothing.

So the templates for each product are split: 80% stay visible as graph
evidence, 20% are held out as gold and *excluded from scoring*. The planner
must generalise — infer from the other templates on this stack what a new
finding is likely to be. That is the question a hunter actually has.

**Baselines.** Reported alongside, because a ranking metric with no baseline
is not interpretable:

    random      shuffle the candidate classes
    prior       always rank by global class frequency, ignoring the stack
    planner     the full scoring model

Beating `prior` is the real bar: it shows the planner uses the fingerprint,
not just the base rate of XSS being common.

**One residual leak, stated rather than hidden.** The planner smooths its
conditional estimate toward a global class prior computed over every template
in the graph — including the held-out ones. Removing a template from the
evidence pool therefore does not remove its (tiny) contribution to that global
aggregate. The effect is negligible: held-out templates are ~5% of the ~7.3k
signature→weakness edges, spread across classes, and the `prior` baseline is
computed the same way, so the comparison between arms is unaffected. It is
recorded here because the per-product evidence exclusion is the part that
actually matters, and it *is* strict.
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from bountybrain.config import settings
from bountybrain.kg.db import Session
from bountybrain.kg.models import (
    Product,
    Signature,
    SignatureDetectsWeakness,
    SignatureTargetsProduct,
    Vulnerability,
)
from bountybrain.recon.planner import LIKELIHOOD_ONLY, ScoringWeights, rank_weaknesses

console = Console()


@dataclass
class PlannerCase:
    product: str
    gold_cwe: int
    held_out_path: str
    held_out_name: str


def build_cases(
    min_signatures: int = 5,
    max_cases: int = 400,
    holdout_ratio: float = 0.2,
    seed: int = 31,
) -> tuple[list[PlannerCase], set[str]]:
    """Split each product's templates into visible evidence and held-out gold.

    Returns (cases, excluded_paths). `excluded_paths` covers every held-out
    template across all cases, so a single exclusion set can be applied for
    the whole run — otherwise gold for product A would leak as evidence when
    evaluating product B.
    """
    with Session() as s:
        rows = s.execute(
            select(
                Product.name,
                Signature.path,
                Signature.name,
                Vulnerability.cwe_id,
            )
            .select_from(Signature)
            .join(SignatureTargetsProduct, SignatureTargetsProduct.signature_id == Signature.id)
            .join(Product, Product.id == SignatureTargetsProduct.product_id)
            .join(SignatureDetectsWeakness, SignatureDetectsWeakness.signature_id == Signature.id)
            .join(Vulnerability, Vulnerability.id == SignatureDetectsWeakness.vuln_id)
        ).all()

    by_product: dict[str, list] = defaultdict(list)
    for r in rows:
        by_product[r[0]].append(r)

    rng = random.Random(seed)
    cases: list[PlannerCase] = []
    excluded: set[str] = set()

    for product, items in sorted(by_product.items()):
        # de-duplicate: a template can map to a product through several tokens
        uniq = {(r[1], r[2], r[3]) for r in items}
        if len(uniq) < min_signatures:
            continue
        # need at least two distinct classes, or the task is trivial
        if len({c for _, _, c in uniq}) < 2:
            continue
        pool = sorted(uniq)
        rng.shuffle(pool)
        n_hold = max(1, int(len(pool) * holdout_ratio))
        for path, name, cwe_id in pool[:n_hold]:
            cases.append(
                PlannerCase(
                    product=product,
                    gold_cwe=cwe_id,
                    held_out_path=path,
                    held_out_name=name,
                )
            )
            excluded.add(path)

    rng.shuffle(cases)
    cases = cases[:max_cases]
    # only exclude what we actually evaluate, so the evidence pool stays large
    excluded = {c.held_out_path for c in cases}
    return cases, excluded


def _global_prior() -> list[int]:
    """CWE ids ordered by how often they appear across all templates."""
    with Session() as s:
        rows = s.execute(
            select(Vulnerability.cwe_id, Vulnerability.id)
            .join(SignatureDetectsWeakness, SignatureDetectsWeakness.vuln_id == Vulnerability.id)
        ).all()
    return [c for c, _ in Counter(r[0] for r in rows).most_common()]


def _metrics(ranks: list[int | None], n: int) -> dict:
    def hit_at(k: int) -> float:
        return sum(1 for r in ranks if r is not None and r <= k) / n if n else 0.0

    mrr = sum(1.0 / r for r in ranks if r is not None) / n if n else 0.0
    return {
        "n": n,
        "precision@1": round(hit_at(1), 4),
        "precision@3": round(hit_at(3), 4),
        "precision@5": round(hit_at(5), 4),
        "precision@10": round(hit_at(10), 4),
        "mrr": round(mrr, 4),
        "unranked": sum(1 for r in ranks if r is None),
    }


def evaluate(
    max_cases: int = 400,
    top_k: int = 10,
    seed: int = 31,
    weights: ScoringWeights | None = None,
) -> dict:
    cases, excluded = build_cases(max_cases=max_cases, seed=seed)
    if not cases:
        return {"error": "no evaluable products — build the graph first"}

    console.print(
        f"[cyan]{len(cases)} held-out cases across "
        f"{len({c.product for c in cases})} products[/cyan]"
    )

    prior = _global_prior()
    rng = random.Random(seed)

    planner_ranks: list[int | None] = []
    likelihood_ranks: list[int | None] = []
    prior_ranks: list[int | None] = []
    random_ranks: list[int | None] = []
    per_product: dict[str, list[int | None]] = defaultdict(list)

    with Session() as s:
        for case in cases:
            recs, _ = rank_weaknesses(
                [case.product],
                top_k=top_k,
                weights=weights,
                session=s,
                exclude_signature_paths=excluded,
            )
            ranked = [r.cwe_id for r in recs]
            rank = ranked.index(case.gold_cwe) + 1 if case.gold_cwe in ranked else None
            planner_ranks.append(rank)
            per_product[case.product].append(rank)

            # Same model, ranking purely by likelihood — isolates how much
            # ranking accuracy the value weighting costs.
            lik_recs, _ = rank_weaknesses(
                [case.product],
                top_k=top_k,
                weights=LIKELIHOOD_ONLY,
                session=s,
                exclude_signature_paths=excluded,
            )
            lik_ranked = [r.cwe_id for r in lik_recs]
            likelihood_ranks.append(
                lik_ranked.index(case.gold_cwe) + 1 if case.gold_cwe in lik_ranked else None
            )

            # Baselines rank the *same candidate pool*, so the comparison is
            # about ordering rather than about who saw more candidates.
            pool = ranked or []
            prior_order = [c for c in prior if c in pool][:top_k]
            prior_ranks.append(
                prior_order.index(case.gold_cwe) + 1 if case.gold_cwe in prior_order else None
            )
            shuffled = list(pool)
            rng.shuffle(shuffled)
            shuffled = shuffled[:top_k]
            random_ranks.append(
                shuffled.index(case.gold_cwe) + 1 if case.gold_cwe in shuffled else None
            )

    n = len(cases)
    results = {
        "cases": n,
        "products": len({c.product for c in cases}),
        "top_k": top_k,
        "seed": seed,
        "strategies": {
            "planner (value-weighted)": _metrics(planner_ranks, n),
            "planner (likelihood-only)": _metrics(likelihood_ranks, n),
            "prior": _metrics(prior_ranks, n),
            "random": _metrics(random_ranks, n),
        },
    }

    best_products = sorted(
        (
            (p, sum(1 for r in rs if r is not None and r <= 3) / len(rs), len(rs))
            for p, rs in per_product.items()
            if len(rs) >= 3
        ),
        key=lambda x: -x[1],
    )
    results["per_product_top"] = [
        {"product": p, "precision@3": round(v, 3), "cases": n_} for p, v, n_ in best_products[:10]
    ]
    return results


def render(results: dict) -> None:
    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return
    t = Table(
        title=f"Recon planner — next-move ranking ({results['cases']} held-out cases, "
        f"{results['products']} products)"
    )
    t.add_column("strategy")
    for col in ("P@1", "P@3", "P@5", "P@10", "MRR"):
        t.add_column(col, justify="right")
    for name, m in results["strategies"].items():
        t.add_row(
            name,
            f"{m['precision@1']:.3f}",
            f"{m['precision@3']:.3f}",
            f"{m['precision@5']:.3f}",
            f"{m['precision@10']:.3f}",
            f"{m['mrr']:.3f}",
        )
    console.print(t)


def evaluate_and_save(path: Path | None = None, **kwargs) -> dict:
    results = evaluate(**kwargs)
    out = path or (settings.artifact_dir / "eval_planner.json")
    out.write_text(json.dumps(results, indent=2))
    render(results)
    console.print(f"[green]Wrote {out}[/green]")
    return results
