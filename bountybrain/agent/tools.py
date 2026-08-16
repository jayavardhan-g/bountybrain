"""Agent-callable tools. Thin wrappers around lower-level modules.

Kept centralised so the LangGraph node can dispatch by name.
"""
from __future__ import annotations

from typing import Any

from bountybrain.clients.llm import chat, load_prompt
from bountybrain.kg.queries import compare_reports as _compare_reports
from bountybrain.kg.queries import get_bypass_chain as _get_bypass_chain
from bountybrain.kg.queries import kg_query as _kg_query
from bountybrain.rag.hybrid import search as _rag_search
from bountybrain.recon.matcher import match_findings as _match_findings
from bountybrain.recon.parsers import parse_recon_file as _parse_recon_file
from bountybrain.web.search import live_search as _live_search

from .labs import find_practice_labs as _find_practice_labs


def local_rag_search(query: str, filters: dict | None = None, top_k: int = 5) -> dict:
    result = _rag_search(query, top_k=top_k, filters=filters or {})
    return {
        "query": result.query,
        "hits": [
            {
                "report_id": h.report_id,
                "chunk_idx": h.chunk_idx,
                "text": h.text,
                "url": h.url,
                "title": h.title,
                "score": h.score,
            }
            for h in result.hits
        ],
    }


def live_web_search(query: str, count: int = 5, persist: bool = False) -> list[dict]:
    return [
        {"url": h.url, "title": h.title, "snippet": h.snippet, "summary": h.summary_md}
        for h in _live_search(query, count=count, persist=persist)
    ]


def kg_query(entity_type: str, entity_name: str, relationship: str = "reports") -> list[dict]:
    return _kg_query(entity_type, entity_name, relationship)


def get_bypass_chain(vuln_type: str, target_tech: str | None = None) -> list[dict]:
    return _get_bypass_chain(vuln_type, target_tech)


def compare_reports(report_ids: list[int]) -> dict:
    return _compare_reports(report_ids)


def parse_recon_file(file_path: str, tool_hint: str | None = None) -> list[dict]:
    return [f.model_dump() for f in _parse_recon_file(file_path, tool_hint=tool_hint)]


def match_findings_to_kg(findings: list[dict], top_k: int = 5) -> dict:
    from bountybrain.recon.models import ReconFinding

    typed = [ReconFinding(**f) for f in findings]
    return _match_findings(typed, top_k=top_k)


def find_practice_labs(topic: str) -> list[dict]:
    return _find_practice_labs(topic)


def generate_report(topic: str, sources: list[dict]) -> str:
    """Compose a markdown tutorial from RAG hits.

    `sources` is a list of hit-shaped dicts as returned by local_rag_search.
    Falls back to a simple template if LLM isn't available.
    """
    numbered = []
    for i, s in enumerate(sources, start=1):
        numbered.append(f"[{i}] {s.get('title')} — {s.get('url')}\n{s.get('text', '')[:800]}")
    joined = "\n\n---\n\n".join(numbered)
    try:
        return chat(
            system="You are a patient, plain-language tutor.",
            user=load_prompt("tutorial", topic=topic, sources=joined),
        )
    except Exception:
        return _template_report(topic, sources)


def _template_report(topic: str, sources: list[dict]) -> str:
    if not sources:
        return f"# {topic}\n\nNo local sources matched — try live web search.\n"
    lines = [
        f"# {topic}\n",
        f"## What is {topic}?\n",
        "This is a beginner overview stitched from real disclosed reports.\n",
        "## How attackers find it\n",
    ]
    for i, s in enumerate(sources, start=1):
        lines.append(f"- {s.get('title')} [[{i}]]({s.get('url')})")
    lines.append("\n## Practice labs\n(see below)\n")
    lines.append("## Key takeaways\n")
    lines.append("- Look at real reports for real patterns")
    lines.append("- Always test only in-scope targets")
    lines.append("- Read the fix, not just the exploit")
    return "\n".join(lines)


TOOLS = {
    "local_rag_search": local_rag_search,
    "live_web_search": live_web_search,
    "kg_query": kg_query,
    "get_bypass_chain": get_bypass_chain,
    "compare_reports": compare_reports,
    "parse_recon_file": parse_recon_file,
    "match_findings_to_kg": match_findings_to_kg,
    "find_practice_labs": find_practice_labs,
    "generate_report": generate_report,
}
