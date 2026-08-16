"""FastAPI wrapper around the tools.

    uvicorn bountybrain.api.app:app --reload

Every endpoint reads the local graph and corpus. Nothing here scans a target
or calls an external service.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from bountybrain.agent import tools as agent_tools
from bountybrain.kg import queries
from bountybrain.kg.db import init_db

app = FastAPI(
    title="BountyBrain API",
    version="1.0.0",
    description="Knowledge graph and retrieval over open security datasets.",
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


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
        "sources": rag["hits"],
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
