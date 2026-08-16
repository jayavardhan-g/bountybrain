"""FastAPI wrapper around the tools + agent.

Endpoints:
  POST /learn         -> {"topic": "..."}                 -> agent run
  POST /search        -> {"query", "filters", "top_k"}    -> hybrid RAG hits
  POST /kg            -> {"entity_type", "entity_name"}   -> kg_query
  POST /bypass        -> {"vuln_type", "target_tech?"}    -> bypass chains
  POST /compare       -> {"report_ids": [..]}             -> compare
  POST /recon/match   -> {"findings": [...], "top_k": 5}  -> matches
  POST /recon/parse   -> upload file, returns findings
  GET  /stats         -> corpus stats
  GET  /health        -> {"ok": true}
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel

from bountybrain.agent import run_agent
from bountybrain.agent import tools as agent_tools
from bountybrain.kg.db import init_db
from bountybrain.kg.queries import corpus_stats

app = FastAPI(title="BountyBrain API", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    init_db()


class LearnReq(BaseModel):
    topic: str


class SearchReq(BaseModel):
    query: str
    top_k: int = 5
    filters: dict[str, Any] | None = None


class KGReq(BaseModel):
    entity_type: str
    entity_name: str
    relationship: str = "reports"


class BypassReq(BaseModel):
    vuln_type: str
    target_tech: str | None = None


class CompareReq(BaseModel):
    report_ids: list[int]


class MatchReq(BaseModel):
    findings: list[dict]
    top_k: int = 5


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/stats")
def stats() -> dict:
    return corpus_stats()


@app.post("/learn")
def learn(req: LearnReq) -> dict:
    return run_agent(req.topic)


@app.post("/search")
def search(req: SearchReq) -> dict:
    return agent_tools.local_rag_search(req.query, filters=req.filters, top_k=req.top_k)


@app.post("/kg")
def kg(req: KGReq) -> list[dict]:
    return agent_tools.kg_query(req.entity_type, req.entity_name, req.relationship)


@app.post("/bypass")
def bypass(req: BypassReq) -> list[dict]:
    return agent_tools.get_bypass_chain(req.vuln_type, req.target_tech)


@app.post("/compare")
def compare(req: CompareReq) -> dict:
    return agent_tools.compare_reports(req.report_ids)


@app.post("/recon/match")
def recon_match(req: MatchReq) -> dict:
    return agent_tools.match_findings_to_kg(req.findings, top_k=req.top_k)


@app.post("/recon/parse")
async def recon_parse(file: UploadFile = File(...), tool_hint: str | None = None) -> list[dict]:
    body = await file.read()
    with tempfile.NamedTemporaryFile("wb", suffix=Path(file.filename or "in").suffix, delete=False) as f:
        f.write(body)
        tmp_path = f.name
    return agent_tools.parse_recon_file(tmp_path, tool_hint=tool_hint)
