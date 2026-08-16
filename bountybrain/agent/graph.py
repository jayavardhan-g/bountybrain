"""LangGraph state machine for the 'teach me X' flow.

Behavior:
1. Try local RAG. If < 3 hits, fall back to live web search.
2. Look up practice labs.
3. Compose the final tutorial with generate_report.

The graph is intentionally small — the interesting logic sits in the
tools, which are also directly callable from the API/UI for the other
pages that don't need an agent (Explore, Recon Match, Bypass Chains).
"""
from __future__ import annotations

from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph  # type: ignore
    HAVE_LANGGRAPH = True
except ImportError:  # pragma: no cover
    HAVE_LANGGRAPH = False

from .labs import find_practice_labs
from .tools import generate_report, live_web_search, local_rag_search


class AgentState(TypedDict, total=False):
    topic: str
    rag: dict
    web: list[dict]
    labs: list[dict]
    report: str


def _node_rag(state: AgentState) -> AgentState:
    state["rag"] = local_rag_search(state["topic"], top_k=5)
    return state


def _node_web(state: AgentState) -> AgentState:
    hits = state.get("rag", {}).get("hits", [])
    if len(hits) < 3:
        state["web"] = live_web_search(state["topic"], count=5)
    else:
        state["web"] = []
    return state


def _node_labs(state: AgentState) -> AgentState:
    state["labs"] = find_practice_labs(state["topic"])
    return state


def _node_report(state: AgentState) -> AgentState:
    sources = state.get("rag", {}).get("hits", []) or []
    # merge web summaries in as extra sources
    for w in state.get("web", []) or []:
        sources.append(
            {
                "title": w.get("title"),
                "url": w.get("url"),
                "text": w.get("summary") or w.get("snippet") or "",
            }
        )
    md = generate_report(state["topic"], sources)
    if state.get("labs"):
        md += "\n\n## Practice labs\n"
        for lab in state["labs"]:
            md += f"- [{lab['name']}]({lab['url']}) — {lab['provider']}\n"
    state["report"] = md
    return state


def _linear_run(topic: str) -> AgentState:
    """Fallback runner used when LangGraph isn't installed."""
    state: AgentState = {"topic": topic}
    for node in (_node_rag, _node_web, _node_labs, _node_report):
        state = node(state)
    return state


def run_agent(topic: str) -> AgentState:
    if not HAVE_LANGGRAPH:
        return _linear_run(topic)
    g: Any = StateGraph(AgentState)
    g.add_node("rag", _node_rag)
    g.add_node("web", _node_web)
    g.add_node("labs", _node_labs)
    g.add_node("report", _node_report)
    g.set_entry_point("rag")
    g.add_edge("rag", "web")
    g.add_edge("web", "labs")
    g.add_edge("labs", "report")
    g.add_edge("report", END)
    app = g.compile()
    return app.invoke({"topic": topic})
