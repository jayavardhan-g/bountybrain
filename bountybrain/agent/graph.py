"""LangGraph state machine for the "explain this to me" flow.

    resolve → retrieve → labs → write

`resolve` grounds the topic in the knowledge graph (CWE class, its attack
patterns, real disclosures); `retrieve` pulls supporting passages from the
local corpus; `write` composes a tutorial that must cite them.

The graph is deliberately small — the interesting logic lives in `tools.py`,
which the API and the Streamlit pages call directly without going through an
agent. LangGraph is optional: if it is not installed the same nodes run in
sequence, so nothing depends on it being present.
"""
from __future__ import annotations

from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph  # type: ignore

    HAVE_LANGGRAPH = True
except ImportError:  # pragma: no cover
    HAVE_LANGGRAPH = False

from .labs import find_practice_labs
from .tools import generate_tutorial, kg_context, local_rag_search


class AgentState(TypedDict, total=False):
    topic: str
    context: dict
    rag: dict
    labs: list[dict]
    report: str


def _node_resolve(state: AgentState) -> AgentState:
    state["context"] = kg_context(state["topic"])
    return state


def _node_retrieve(state: AgentState) -> AgentState:
    state["rag"] = local_rag_search(state["topic"], top_k=6)
    return state


def _node_labs(state: AgentState) -> AgentState:
    state["labs"] = find_practice_labs(state["topic"])
    return state


def _node_write(state: AgentState) -> AgentState:
    state["report"] = generate_tutorial(
        state["topic"],
        state.get("rag", {}).get("hits", []),
        state.get("context"),
    )
    return state


_NODES = [
    ("resolve", _node_resolve),
    ("retrieve", _node_retrieve),
    ("labs", _node_labs),
    ("write", _node_write),
]


def build_graph() -> Any:
    if not HAVE_LANGGRAPH:
        return None
    g = StateGraph(AgentState)
    for name, fn in _NODES:
        g.add_node(name, fn)
    g.set_entry_point("resolve")
    for (a, _), (b, _) in zip(_NODES, _NODES[1:], strict=False):
        g.add_edge(a, b)
    g.add_edge("write", END)
    return g.compile()


def run_agent(topic: str) -> AgentState:
    """Run the flow. Falls back to a plain sequence without LangGraph."""
    state: AgentState = {"topic": topic}
    graph = build_graph()
    if graph is not None:
        return graph.invoke(state)
    for _, fn in _NODES:
        state = fn(state)
    return state
