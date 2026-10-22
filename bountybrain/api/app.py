"""FastAPI wrapper around the tools.

    uvicorn bountybrain.api.app:app --reload

Every endpoint reads the local graph and corpus. Nothing here scans a target
or calls an external service.
"""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from bountybrain.agent import tools as agent_tools
from bountybrain.agent.path import learning_path
from bountybrain.kg import queries
from bountybrain.kg.db import init_db

log = logging.getLogger(__name__)

app = FastAPI(
    title="BountyBrain API",
    version="1.0.0",
    description="Knowledge graph and retrieval over open security datasets.",
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    # Load the embedder, the reranker and the BM25 index now, not on the first
    # /search: that request otherwise pays the whole model load — minutes from
    # a cold network-storage cache. Without a built index the API still serves
    # everything graph-backed, so a failure here is logged, not fatal.
    try:
        from bountybrain.rag.hybrid import search as rag_search

        rag_search("warm-up", top_k=1)
    except Exception as e:  # noqa: BLE001
        log.warning("retrieval warm-up failed, /search will load lazily: %s", e)


# --------------------------------------------------------------- schemas


class SearchReq(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=50)
    mode: str = "hybrid_rerank"


class TopicReq(BaseModel):
    topic: str


class PlanReq(BaseModel):
    findings: list[dict[str, Any]]
    top_k: int = Field(default=8, ge=1, le=25)


class ProductReq(BaseModel):
    name: str
    limit: int = Field(default=25, ge=1, le=100)


# --------------------------------------------------------------- routes


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/stats")
def stats() -> dict:
    return queries.corpus_summary()


@app.post("/search")
def search(req: SearchReq) -> dict:
    from bountybrain.rag.hybrid import search as rag_search

    result = rag_search(req.query, top_k=req.top_k, mode=req.mode)
    return {
        "query": result.query,
        "mode": result.mode,
        "hits": [
            {
                "document_id": h.document_id,
                "title": h.title,
                "url": h.url,
                "doc_type": h.doc_type,
                "score": h.score,
                "text": h.text[:1500],
            }
            for h in result.hits
        ],
    }


@app.post("/learn")
def learn(req: TopicReq) -> dict:
    context = agent_tools.kg_context(req.topic)
    rag = agent_tools.local_rag_search(req.topic, top_k=6)
    return {
        "topic": req.topic,
        "weakness": context.get("weakness"),
        "techniques": context.get("techniques", []),
        # Numbered as the tutorial cites them: retrieved passages, then the graph.
        "sources": agent_tools.tutorial_sources(rag["hits"], context),
        "tutorial": agent_tools.generate_tutorial(req.topic, rag["hits"], context),
        "labs": agent_tools.find_practice_labs(req.topic),
    }


@app.get("/weakness/{cwe_id}")
def weakness(cwe_id: int) -> dict:
    hierarchy = queries.weakness_hierarchy(cwe_id)
    if not hierarchy:
        raise HTTPException(status_code=404, detail=f"CWE-{cwe_id} not found")
    return {
        **hierarchy,
        "techniques": queries.techniques_for_weakness(cwe_id),
        "writeups": queries.documents_for_weakness(cwe_id, limit=15, doc_type="writeup"),
    }


@app.get("/weakness")
def find_weakness(q: str) -> dict:
    result = queries.find_weakness(q)
    if not result:
        raise HTTPException(status_code=404, detail=f"no weakness matched {q!r}")
    return result


@app.post("/product/signatures")
def product_signatures(req: ProductReq) -> dict:
    return {
        "product": req.name,
        "weaknesses": queries.weaknesses_for_product(req.name),
        "signatures": queries.signatures_for_product(req.name, limit=req.limit),
    }


@app.post("/recon/parse")
async def recon_parse(file: UploadFile = File(...), tool_hint: str | None = None) -> dict:
    data = await file.read()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / (file.filename or "recon.txt")
        path.write_bytes(data)
        findings = agent_tools.parse_recon_file(str(path), tool_hint=tool_hint)
    return {"count": len(findings), "findings": findings}


@app.post("/recon/plan")
def recon_plan(req: PlanReq) -> dict:
    return agent_tools.plan_recon(req.findings, top_k=req.top_k)


@app.post("/chains")
def chains(req: TopicReq) -> dict:
    return {"topic": req.topic, "chains": agent_tools.attack_chain(req.topic)}


@app.get("/reports/related/{document_id}")
def related_reports(document_id: int, limit: int = 8) -> dict:
    """Reports connected to this one by shared weakness class or program."""
    related = queries.related_writeups(document_id, limit=limit)
    return {"document_id": document_id, "count": len(related), "related": related}


@app.get("/labs")
def labs(topic: str) -> dict:
    """Where to practise a weakness class hands-on."""
    return {"topic": topic, "labs": agent_tools.find_practice_labs(topic)}


@app.get("/path")
def get_learning_path(topic: str) -> dict:
    """Ordered study plan: weakness → attack patterns → disclosures → labs → next."""
    result = learning_path(topic)
    if not result:
        raise HTTPException(status_code=404, detail=f"no weakness matched {topic!r}")
    return result
