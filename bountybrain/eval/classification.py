"""Evaluate CWE classification against curated gold labels.

Two independent gold sets, which is the point — agreeing with one labeller
could be an artefact of that labeller's conventions:

    nuclei         ~7k detection templates with a hand-assigned `cwe-id`,
                   labelled by the ProjectDiscovery community.
    pentesterland  ~6.4k disclosed writeups with curated vulnerability labels,
                   normalised onto CWE through the alias table.

Both are *held out* from the classifier in the sense that nothing in the
keyword table, the embedding index, or the prompt was tuned against them.

Metrics reported per strategy:
    accuracy         exact CWE id match
    hierarchy_match  correct, or an ancestor/descendant of the gold class in
                     the CWE ChildOf tree. Predicting CWE-79 where gold says
                     CWE-80 (a child of 79) is not the same kind of error as
                     predicting CWE-89, and collapsing both into "wrong"
                     overstates the failure rate.
    macro_f1         over the classes actually present, so a few huge classes
                     cannot mask failure on the long tail.
    abstention       fraction where the strategy declined to answer. Reported
                     because a classifier that abstains often can post good
                     accuracy on what remains.
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import networkx as nx
import numpy as np
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from bountybrain.config import settings
from bountybrain.ingestion import classifier
from bountybrain.kg.db import Session
from bountybrain.kg.models import (
    Signature,
    SignatureDetectsWeakness,
    Vulnerability,
    WeaknessRelation,
)

console = Console()


@dataclass
class GoldItem:
    text: str
    gold_cwe: int
    source: str
    ref: str


# --------------------------------------------------------------------------
# gold set construction
# --------------------------------------------------------------------------


def load_nuclei_gold(limit: int | None = None, seed: int = 17) -> list[GoldItem]:
    """Templates whose description carries a single unambiguous CWE label.

    Templates with several CWE ids are dropped: with more than one correct
    answer, a single-label accuracy number is not meaningful.

    Caveat worth stating: a template's name often contains the vulnerability
    class verbatim ("Swagger UI < 3.38.0 - Cross-Site Scripting"), which makes
    this set easier than free prose and flatters the keyword baseline in
    particular. It is kept because it is the largest human-labelled set
    available and every strategy sees exactly the same input — but the
    pentester.land set, where only a title is available and the class is
    usually implied rather than named, is the harder and more telling one.
    """
    with Session() as s:
        rows = s.execute(
            select(
                Signature.id,
                Signature.name,
                Signature.description,
                Signature.impact,
                Vulnerability.cwe_id,
            )
            .join(SignatureDetectsWeakness, SignatureDetectsWeakness.signature_id == Signature.id)
            .join(Vulnerability, Vulnerability.id == SignatureDetectsWeakness.vuln_id)
        ).all()

    by_sig: dict[int, list] = defaultdict(list)
    for r in rows:
        by_sig[r.id].append(r)

    items: list[GoldItem] = []
    for sig_id, group in by_sig.items():
        if len({g.cwe_id for g in group}) != 1:
            continue
        g = group[0]
        text = " ".join(filter(None, [g.name, g.description, g.impact])).strip()
        if len(text) < 40:
            continue
        items.append(
            GoldItem(text=text, gold_cwe=g.cwe_id, source="nuclei", ref=str(sig_id))
        )

    random.Random(seed).shuffle(items)
    return items[:limit] if limit else items


def load_writeup_gold(limit: int | None = None, seed: int = 17) -> list[GoldItem]:
    """Disclosed writeups whose curated labels resolve to exactly one CWE.

    Only the *title* is available as input — we never fetched article bodies —
    which makes this a deliberately harder, shorter-context task than nuclei.
    """
    from bountybrain.datasets import cwe as cwe_ds
    from bountybrain.datasets import pentesterland as pl_ds
    from bountybrain.datasets.fetch import resolve_unpacked
    from bountybrain.datasets.registry import BY_NAME

    cwe_path = resolve_unpacked(BY_NAME["cwe"])
    if cwe_path is None:
        return []
    alias = cwe_ds.alias_map(cwe_ds.load(cwe_path))
    writeups = pl_ds.load(Path(settings.raw_cache_dir) / "pentesterland_writeups.json")
    pl_ds.normalise_labels(writeups, alias, cwe_ds.NON_VULNERABILITY_LABELS)

    items = [
        GoldItem(text=w.title, gold_cwe=w.cwe_ids[0], source="pentesterland", ref=w.url)
        for w in writeups
        if len(w.cwe_ids) == 1 and w.title and len(w.title) > 20
    ]
    random.Random(seed).shuffle(items)
    return items[:limit] if limit else items


# --------------------------------------------------------------------------
# CWE hierarchy, for partial credit
# --------------------------------------------------------------------------


def _childof_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    with Session() as s:
        rows = s.execute(
            select(WeaknessRelation.src_id, WeaknessRelation.dst_id)
            .where(WeaknessRelation.nature == "ChildOf")
        ).all()
        pk_to_cwe = dict(s.execute(select(Vulnerability.id, Vulnerability.cwe_id)).all())
    for src, dst in rows:
        if src in pk_to_cwe and dst in pk_to_cwe:
            g.add_edge(pk_to_cwe[src], pk_to_cwe[dst])  # child -> parent
    return g


def _related(g: nx.DiGraph, a: int, b: int, max_hops: int = 2) -> bool:
    """True if a and b are within `max_hops` on the ChildOf tree."""
    if a == b:
        return True
    for src, dst in ((a, b), (b, a)):
        if src not in g:
            continue
        try:
            if nx.shortest_path_length(g, src, dst) <= max_hops:
                return True
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
    return False


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------


def score(
    items: list[GoldItem], preds: list[classifier.Prediction], hierarchy: nx.DiGraph
) -> dict:
    n = len(items)
    exact = 0
    hier = 0
    abstained = 0
    per_class_tp: Counter = Counter()
    per_class_fp: Counter = Counter()
    per_class_fn: Counter = Counter()

    for item, pred in zip(items, preds, strict=True):
        if pred.cwe_id is None:
            abstained += 1
            per_class_fn[item.gold_cwe] += 1
            continue
        if pred.cwe_id == item.gold_cwe:
            exact += 1
            hier += 1
            per_class_tp[item.gold_cwe] += 1
        else:
            if _related(hierarchy, pred.cwe_id, item.gold_cwe):
                hier += 1
            per_class_fp[pred.cwe_id] += 1
            per_class_fn[item.gold_cwe] += 1

    classes = set(per_class_tp) | set(per_class_fp) | set(per_class_fn)
    f1s = []
    for c in classes:
        tp, fp, fn = per_class_tp[c], per_class_fp[c], per_class_fn[c]
        if tp == 0 and (fp or fn):
            f1s.append(0.0)
            continue
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1s.append(2 * p * r / (p + r) if (p + r) else 0.0)

    answered = n - abstained
    return {
        "n": n,
        "accuracy": round(exact / n, 4) if n else 0.0,
        "hierarchy_match": round(hier / n, 4) if n else 0.0,
        "accuracy_when_answered": round(exact / answered, 4) if answered else 0.0,
        "abstention_rate": round(abstained / n, 4) if n else 0.0,
        "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else 0.0,
        "distinct_gold_classes": len({i.gold_cwe for i in items}),
    }


SHORTLIST_KS = (1, 5, 12, 20, 50)
LLM_SHORTLIST_K = 12  # must match classify_llm's default k


def shortlist_recall(
    items: list[GoldItem],
    index: classifier.CandidateIndex,
    hierarchy: nx.DiGraph,
    ks: tuple[int, ...] = SHORTLIST_KS,
) -> tuple[dict, list[bool]]:
    """How often the embedding shortlist even contains the gold class.

    The LLM arm can only pick from its top-12 shortlist, so recall@12 is a hard
    ceiling on its accuracy. If that ceiling is low the retriever, not the
    model, is what limits the arm. Also returns, per item, whether gold was in
    the top-12, so the LLM's accuracy can be split on it.
    """
    from bountybrain.clients import embeddings

    qv = np.asarray(embeddings.embed_queries([i.text for i in items]), dtype=np.float32)
    ranked = index.topk(qv, k=max(ks))
    n = len(items)
    out: dict = {}
    in_llm_shortlist: list[bool] = []
    for k in ks:
        hits = hier_hits = 0
        for item, row in zip(items, ranked, strict=True):
            ids = [index.cwe_ids[int(p)] for p in row[:k]]
            hit = item.gold_cwe in ids
            hits += hit
            hier_hits += hit or any(_related(hierarchy, c, item.gold_cwe) for c in ids)
            if k == LLM_SHORTLIST_K:
                in_llm_shortlist.append(hit)
        out[f"recall@{k}"] = round(hits / n, 4) if n else 0.0
        out[f"hierarchy_recall@{k}"] = round(hier_hits / n, 4) if n else 0.0
    return out, in_llm_shortlist


def split_by_shortlist(
    items: list[GoldItem], preds: list[classifier.Prediction], in_shortlist: list[bool]
) -> dict:
    """LLM accuracy when gold was / was not on the shortlist it chose from."""
    out = {}
    for label, want in (("gold_in_shortlist", True), ("gold_not_in_shortlist", False)):
        rows = [
            (i, p) for i, p, s in zip(items, preds, in_shortlist, strict=True) if s == want
        ]
        correct = sum(p.cwe_id == i.gold_cwe for i, p in rows)
        abstained = sum(p.cwe_id is None for _, p in rows)
        out[label] = {
            "n": len(rows),
            "accuracy": round(correct / len(rows), 4) if rows else 0.0,
            "abstention_rate": round(abstained / len(rows), 4) if rows else 0.0,
        }
    return out


def route_keyword_then(
    keyword: list[classifier.Prediction], fallback: list[classifier.Prediction], name: str
) -> list[classifier.Prediction]:
    """Keyword when it fires, the fallback strategy only on its abstentions."""
    return [
        k if k.cwe_id is not None else classifier.Prediction(f.cwe_id, f.confidence, name)
        for k, f in zip(keyword, fallback, strict=True)
    ]


def evaluate(
    methods: list[str] | None = None,
    n_per_source: int = 500,
    seed: int = 17,
    progress: bool = True,
) -> dict:
    """Run every strategy over both gold sets."""
    methods = methods or ["keyword", "embedding", "llm"]
    hierarchy = _childof_graph()
    index = None

    gold_sets = {
        "nuclei": load_nuclei_gold(limit=n_per_source, seed=seed),
        "pentesterland": load_writeup_gold(limit=n_per_source, seed=seed),
    }

    results: dict = {"seed": seed, "sets": {}}
    for set_name, items in gold_sets.items():
        if not items:
            continue
        console.print(
            f"[cyan]{set_name}[/cyan]: {len(items)} items, "
            f"{len({i.gold_cwe for i in items})} distinct classes"
        )
        texts = [i.text for i in items]
        per_method = {}
        all_preds: dict[str, list[classifier.Prediction]] = {}
        for method in methods:
            if method in ("embedding", "llm") and index is None:
                index = classifier.build_candidate_index()
            kwargs = {"index": index} if method in ("embedding", "llm") else {}
            all_preds[method] = classifier.classify(texts, method=method, **kwargs)
        # Derived arm, no extra model calls: keyword abstains often but is
        # accurate when it fires, so route only its abstentions to the LLM.
        if "keyword" in all_preds and "llm" in all_preds:
            all_preds["keyword→llm"] = route_keyword_then(
                all_preds["keyword"], all_preds["llm"], "keyword→llm"
            )
        for method, preds in all_preds.items():
            per_method[method] = score(items, preds, hierarchy)
            if method == "llm":
                # Unparseable or failed replies fall back to the nearest
                # neighbour inside classify_llm; count them so a flaky server
                # cannot pass for a model result.
                per_method[method]["model_failures"] = sum(
                    p.reasoning.startswith("model failed") for p in preds
                )
            console.print(
                f"  {method:12s} acc={per_method[method]['accuracy']:.3f}  "
                f"hier={per_method[method]['hierarchy_match']:.3f}  "
                f"macroF1={per_method[method]['macro_f1']:.3f}  "
                f"abstain={per_method[method]['abstention_rate']:.3f}"
            )
        results["sets"][set_name] = per_method

        if index is not None:
            recall, in_shortlist = shortlist_recall(items, index, hierarchy)
            results.setdefault("shortlist", {})[set_name] = recall
            console.print(
                "  shortlist  "
                + "  ".join(f"R@{k}={recall[f'recall@{k}']:.3f}" for k in SHORTLIST_KS)
            )
            if "llm" in all_preds:
                results.setdefault("llm_by_shortlist", {})[set_name] = split_by_shortlist(
                    items, all_preds["llm"], in_shortlist
                )
    return results


def render(results: dict) -> None:
    for set_name, per_method in results.get("sets", {}).items():
        t = Table(title=f"CWE classification — {set_name}")
        t.add_column("strategy")
        for col in ("n", "accuracy", "hierarchy±2", "macro F1", "abstain"):
            t.add_column(col, justify="right")
        for method, m in per_method.items():
            t.add_row(
                method,
                f"{m['n']:,}",
                f"{m['accuracy']:.3f}",
                f"{m['hierarchy_match']:.3f}",
                f"{m['macro_f1']:.3f}",
                f"{m['abstention_rate']:.3f}",
            )
        console.print(t)


def evaluate_and_save(path: Path | None = None, **kwargs) -> dict:
    results = evaluate(**kwargs)
    out = path or (settings.artifact_dir / "eval_classification.json")
    out.write_text(json.dumps(results, indent=2))
    render(results)
    console.print(f"[green]Wrote {out}[/green]")
    return results
