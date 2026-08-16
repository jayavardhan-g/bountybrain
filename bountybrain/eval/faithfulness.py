"""Faithfulness eval — for N generated tutorials, ask the LLM judge
whether every claim is supported by a cited source.

Falls back to a heuristic score when no LLM is configured: count how many
sentences in the tutorial share a 4-gram with any source chunk.
"""
from __future__ import annotations

import json
import re
from typing import Any

from bountybrain.agent.tools import generate_report, local_rag_search
from bountybrain.clients.llm import LLMError, chat, load_prompt

TOPICS = [
    "SSRF",
    "IDOR",
    "XSS",
    "SQL injection",
    "GraphQL introspection",
    "SSTI",
    "path traversal",
    "open redirect",
    "prototype pollution",
    "race condition",
]


def _heuristic_faithfulness(tutorial: str, sources_text: str) -> tuple[int, int]:
    def ngrams(text: str, n: int = 4) -> set[str]:
        toks = re.findall(r"[a-z0-9]+", text.lower())
        return {" ".join(toks[i : i + n]) for i in range(len(toks) - n + 1)}

    src_grams = ngrams(sources_text)
    sentences = re.split(r"(?<=[.!?])\s+", tutorial)
    supported = 0
    total = 0
    for s in sentences:
        s = s.strip()
        if len(s) < 20:
            continue
        total += 1
        grams = ngrams(s)
        if grams & src_grams:
            supported += 1
    return supported, total or 1


def evaluate(n: int = 10) -> dict:
    per = []
    total_ratio = 0.0
    for topic in TOPICS[:n]:
        rag = local_rag_search(topic, top_k=5)
        sources = rag["hits"]
        tutorial = generate_report(topic, sources)
        sources_joined = "\n\n".join(s.get("text", "") for s in sources)
        try:
            resp = chat(
                system="Return only JSON.",
                user=load_prompt(
                    "faithfulness", tutorial=tutorial[:6000], sources=sources_joined[:8000]
                ),
            )
            data: dict[str, Any] = json.loads(_first_json(resp))
            supp = int(data.get("supported_claims", 0))
            tot = int(data.get("total_claims", 0)) or 1
            unsupported = data.get("unsupported", [])
        except (LLMError, Exception):
            supp, tot = _heuristic_faithfulness(tutorial, sources_joined)
            unsupported = []
        ratio = supp / tot if tot else 0.0
        total_ratio += ratio
        per.append(
            {"topic": topic, "supported": supp, "total": tot, "ratio": ratio, "unsupported": unsupported}
        )
    return {"per": per, "mean_faithfulness": total_ratio / max(len(per), 1)}


def _first_json(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    return text[start : end + 1] if start != -1 and end != -1 else "{}"
