"""Tools the agent calls by name.

Each one is a plain function returning JSON-able data, so the same code
backs the LangGraph agent, the FastAPI routes and the Streamlit pages
without a translation layer.

There is deliberately **no web-search tool**. An earlier version had one
behind a Brave API key; without a key it silently returned nothing, which is
worse than not having it — the agent would claim to have searched and quietly
ground its answer in nothing. Everything here answers from the local corpus,
and when the corpus has nothing the tools say so.
"""
from __future__ import annotations

import json
from pathlib import Path

from bountybrain.clients.llm import LLMError, chat, load_prompt
from bountybrain.kg import queries
from bountybrain.rag.hybrid import search as rag_search
from bountybrain.recon.parsers import parse_recon_file as _parse_file
from bountybrain.recon.planner import plan_from_findings, render_markdown

from .labs import find_practice_labs  # noqa: F401  (re-exported for the agent)


def local_rag_search(query: str, filters: dict | None = None, top_k: int = 5) -> dict:
    """Retrieve supporting passages from the local corpus."""
    result = rag_search(query, top_k=top_k, flt=filters)
    return {
        "query": query,
        "mode": result.mode,
        "hits": [
            {
                "document_id": h.document_id,
                "title": h.title,
                "url": h.url,
                "doc_type": h.doc_type,
                "source": h.source,
                "score": round(h.score, 4),
                "text": h.text,
            }
            for h in result.hits
        ],
    }


def resolve_topic(topic: str) -> dict | None:
    """Map a free-text topic onto a CWE node in the graph."""
    return queries.find_weakness(topic)


def kg_context(topic: str) -> dict:
    """Everything the graph knows about a topic, for grounding a tutorial."""
    weakness = queries.find_weakness(topic)
    if not weakness:
        return {"weakness": None}
    cwe_id = weakness["cwe_id"]
    return {
        "weakness": weakness,
        "hierarchy": queries.weakness_hierarchy(cwe_id),
        "techniques": queries.techniques_for_weakness(cwe_id),
        "writeups": queries.documents_for_weakness(cwe_id, limit=8, doc_type="writeup"),
    }


def attack_chain(topic: str, depth: int = 3) -> list[list[dict]]:
    """Multi-step chains from CAPEC `CanPrecede` edges for a topic."""
    weakness = queries.find_weakness(topic)
    if not weakness:
        return []
    chains: list[list[dict]] = []
    for technique in queries.techniques_for_weakness(weakness["cwe_id"]):
        chains.extend(queries.attack_chain(technique["capec_id"], depth=depth))
    return chains


def parse_recon_file(file_path: str, tool_hint: str | None = None) -> list[dict]:
    findings = _parse_file(Path(file_path), tool_hint=tool_hint)
    return [f.model_dump() for f in findings]


def plan_recon(findings: list[dict], top_k: int = 8) -> dict:
    """Rank next moves for parsed recon findings."""
    from bountybrain.recon.models import ReconFinding

    parsed = [ReconFinding(**f) if isinstance(f, dict) else f for f in findings]
    plans = plan_from_findings(parsed, top_k=top_k)
    return {
        "assets": len(plans),
        "plans": [p.to_dict() for p in plans],
        "markdown": render_markdown(plans),
    }


# How much of each source the tutorial prompt shows the model. The
# faithfulness evaluation judges claims against exactly this much text.
SOURCE_CHARS = 1200
TUTORIAL_SYSTEM = "You write clear, accurate security tutorials for beginners."


def tutorial_prompt(topic: str, sources: list[dict], context: dict | None = None) -> str:
    """The user prompt for a cited tutorial, shared by the UI and the eval."""
    numbered = "\n\n".join(
        f"[{i}] {s['title']} ({s['url']})\n{s['text'][:SOURCE_CHARS]}"
        for i, s in enumerate(sources, start=1)
    )
    return load_prompt(
        "tutorial",
        topic=topic,
        sources=numbered,
        kg_context=json.dumps(_context_brief(context), indent=2) if context else "{}",
    )


def generate_tutorial(topic: str, sources: list[dict], context: dict | None = None) -> str:
    """Write a cited tutorial. Falls back to a template when no LLM is up."""
    if not sources:
        return (
            f"# {topic}\n\n"
            "The local corpus has no passages for this topic. Build the index "
            "with `python index_corpus.py`, or try a different phrasing."
        )
    try:
        return chat(
            system=TUTORIAL_SYSTEM,
            user=tutorial_prompt(topic, sources, context),
            max_tokens=2048,
        )
    except (LLMError, Exception):
        return _template_tutorial(topic, sources, context)


def _context_brief(context: dict | None) -> dict:
    """Trim KG context to what usefully fits in a prompt."""
    if not context or not context.get("weakness"):
        return {}
    w = context["weakness"]
    return {
        "cwe": f"CWE-{w['cwe_id']}: {w['name']}",
        "likelihood_of_exploit": w.get("likelihood"),
        "aliases": w.get("aliases", [])[:6],
        "attack_patterns": [
            f"{t['key']}: {t['name']}" for t in (context.get("techniques") or [])[:6]
        ],
        "notable_disclosures": [
            {"title": d["title"], "bounty": d["bounty"]}
            for d in (context.get("writeups") or [])[:5]
        ],
    }


def _template_tutorial(topic: str, sources: list[dict], context: dict | None) -> str:
    """Deterministic fallback so the UI still works with no LLM running."""
    lines = [f"# {topic}", ""]
    w = (context or {}).get("weakness")
    if w:
        lines += [
            f"**{w['key']}: {w['name']}**",
            "",
            (w.get("description") or "").strip(),
            "",
        ]
        if w.get("likelihood"):
            lines.append(f"_Likelihood of exploit: {w['likelihood']}_")
            lines.append("")
    techniques = (context or {}).get("techniques") or []
    if techniques:
        lines += ["## Attack patterns", ""]
        for t in techniques[:6]:
            lines.append(f"- [{t['key']}: {t['name']}]({t['url']}) — {(t.get('description') or '')[:180]}")
        lines.append("")
    lines += ["## Sources from the corpus", ""]
    for i, s in enumerate(sources, start=1):
        lines.append(f"{i}. [{s['title']}]({s['url']}) — {s['text'][:220].strip()}…")
    writeups = (context or {}).get("writeups") or []
    if writeups:
        lines += ["", "## Real disclosures", ""]
        for d in writeups[:5]:
            amount = f" — ${d['bounty']:,.0f}" if d.get("bounty") else ""
            lines.append(f"- [{d['title'][:90]}]({d['url']}){amount}")
    lines += [
        "",
        "_No LLM server was reachable, so this is a structured summary of the "
        "retrieved sources rather than a generated tutorial. Start one with "
        "`python serve_llm.py` for prose._",
    ]
    return "\n".join(lines)


# Backwards-compatible alias used by the older API surface.
def generate_report(topic: str, sources: list[dict]) -> str:
    return generate_tutorial(topic, sources)
