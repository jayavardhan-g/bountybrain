"""Smoke tests: every API route and every Streamlit page runs without error.

They use a tiny fixture graph and stub out retrieval and the LLM, so they need
no datasets, no GPU and no model server — the point is to catch a page or a
route that crashes on render, which unit tests of the query layer never see.
The real end-to-end run against the built graph and a served model is
recorded in RESULTS.md.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("streamlit")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from streamlit.testing.v1 import AppTest

from bountybrain.agent import tools
from bountybrain.clients.llm import LLMError
from bountybrain.kg import db
from bountybrain.kg.models import (
    Base,
    Document,
    DocumentCoversWeakness,
    Product,
    Signature,
    SignatureDetectsWeakness,
    SignatureTargetsProduct,
    Technique,
    TechniqueRelation,
    TechniqueTargetsWeakness,
    Vulnerability,
    WeaknessRelation,
)

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "bountybrain" / "ui"
PAGES = sorted((UI / "pages").glob("*.py"))
EXAMPLES = ROOT / "examples"

FAKE_HIT = {
    "document_id": 1,
    "title": "SSRF via image proxy",
    "url": "https://example.com/ssrf",
    "doc_type": "writeup",
    "source": "fixture",
    "score": 0.9,
    "text": "The image proxy fetched any URL, including http://169.254.169.254/.",
}


@pytest.fixture
def fixture_graph(monkeypatch):
    """A handful of nodes around SSRF and IDOR, in a shared in-memory database."""
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},  # AppTest runs scripts in a thread
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    monkeypatch.setattr(db, "_engine", engine)
    monkeypatch.setattr(
        db, "_Session", sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    )

    with db.Session() as s:
        access = Vulnerability(cwe_id=284, name="Improper Access Control", abstraction="Pillar")
        idor = Vulnerability(
            cwe_id=639,
            name="Authorization Bypass Through User-Controlled Key",
            abstraction="Base",
            aliases_json=json.dumps(["IDOR"]),
        )
        proxy = Vulnerability(cwe_id=441, name="Unintended Proxy or Intermediary", abstraction="Class")
        ssrf = Vulnerability(
            cwe_id=918,
            name="Server-Side Request Forgery (SSRF)",
            abstraction="Base",
            description="The server fetches a URL supplied by the user.",
            aliases_json=json.dumps(["SSRF"]),
        )
        s.add_all([access, idor, proxy, ssrf])
        s.flush()
        s.add_all(
            [
                WeaknessRelation(src_id=idor.id, dst_id=access.id, nature="ChildOf"),
                WeaknessRelation(src_id=ssrf.id, dst_id=proxy.id, nature="ChildOf"),
            ]
        )
        flow = [{"phase": "Explore", "description": "Find URL parameters", "techniques": []}]
        t1 = Technique(
            capec_id=664,
            name="Server Side Request Forgery",
            min_skill="Medium",
            execution_flow_json=json.dumps(flow),
        )
        t2 = Technique(capec_id=100, name="Follow-on", min_skill="Low")
        s.add_all([t1, t2])
        s.flush()
        s.add_all(
            [
                TechniqueTargetsWeakness(technique_id=t1.id, vuln_id=ssrf.id),
                TechniqueRelation(src_id=t1.id, dst_id=t2.id, nature="CanPrecede"),
            ]
        )
        doc = Document(
            doc_type="writeup",
            source="pentesterland",
            url="https://example.com/ssrf",
            title="SSRF via image proxy",
            body="",
            program="Acme",
            bounty=5000.0,
        )
        s.add(doc)
        s.flush()
        s.add(DocumentCoversWeakness(document_id=doc.id, vuln_id=ssrf.id))
        product = Product(name="wordpress")
        sig = Signature(template_id="wp-ssrf", name="WordPress SSRF", path="wp/ssrf.yaml", severity="high")
        s.add_all([product, sig])
        s.flush()
        s.add_all(
            [
                SignatureTargetsProduct(signature_id=sig.id, product_id=product.id),
                SignatureDetectsWeakness(signature_id=sig.id, vuln_id=ssrf.id),
            ]
        )

    # Retrieval and generation are the two parts that need built indexes and
    # a model server. Stub both; the tutorial then takes its template path.
    from bountybrain.rag import hybrid

    class _Result:
        query, mode = "q", "stub"
        hits = [type("Hit", (), {**FAKE_HIT, "text": FAKE_HIT["text"]})()]

    def fake_search(query, top_k=5, mode="hybrid_rerank", flt=None):
        return _Result()

    def no_llm(*args, **kwargs):
        raise LLMError("no model in tests")

    monkeypatch.setattr(hybrid, "search", fake_search)
    monkeypatch.setattr(tools, "rag_search", fake_search)
    monkeypatch.setattr(tools, "chat", no_llm)
    monkeypatch.chdir(ROOT)
    return engine


# ------------------------------------------------------------------- API


@pytest.fixture
def client(fixture_graph):
    from bountybrain.api.app import app

    with TestClient(app) as c:
        yield c


def test_api_get_routes(client):
    assert client.get("/health").json() == {"ok": True}
    assert client.get("/stats").json()["weaknesses"] == 4
    assert client.get("/weakness/918").json()["weakness"]["cwe_id"] == 918
    assert client.get("/weakness/99999").status_code == 404
    assert client.get("/weakness", params={"q": "IDOR"}).json()["cwe_id"] == 639
    assert client.get("/labs", params={"topic": "SSRF"}).json()["labs"]
    assert client.get("/reports/related/1").status_code == 200


def test_api_learning_path(client):
    body = client.get("/path", params={"topic": "SSRF"}).json()
    assert [s["key"] for s in body["stages"]] == ["weakness", "patterns", "writeups", "labs", "next"]
    assert body["complete"] is True
    assert client.get("/path", params={"topic": "no such thing"}).status_code == 404


def test_api_post_routes(client):
    hits = client.post("/search", json={"query": "ssrf"}).json()["hits"]
    assert hits[0]["title"] == FAKE_HIT["title"]

    learn = client.post("/learn", json={"topic": "SSRF"}).json()
    assert learn["weakness"]["cwe_id"] == 918
    assert "CWE-918" in learn["tutorial"]  # template fallback, no model

    chains = client.post("/chains", json={"topic": "SSRF"}).json()["chains"]
    assert [step["capec_id"] for step in chains[0]] == [664, 100]

    prod = client.post("/product/signatures", json={"name": "wordpress"}).json()
    assert prod["signatures"]


def test_api_recon_parse_then_plan(client):
    path = EXAMPLES / "httpx.jsonl"
    with path.open("rb") as f:
        parsed = client.post("/recon/parse", files={"file": (path.name, f)}).json()
    assert parsed["count"] > 0
    plan = client.post("/recon/plan", json={"findings": parsed["findings"]})
    assert plan.status_code == 200
    assert "markdown" in plan.json()


# -------------------------------------------------------------------- UI


def _run(script: Path) -> AppTest:
    at = AppTest.from_file(str(script), default_timeout=30)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def test_every_page_is_covered():
    names = {p.name for p in PAGES}
    assert {
        "0_Learning_Path.py", "1_Learn.py", "2_Explore.py",
        "3_Attack_Chains.py", "4_Recon_Planner.py", "5_Metrics.py",
    } <= names


def test_home_page(fixture_graph):
    at = _run(UI / "streamlit_app.py")
    assert at.metric[0].value == "4"  # weaknesses in the fixture graph


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_page_renders(fixture_graph, page):
    _run(page)


def test_learning_path_page_shows_every_stage(fixture_graph):
    at = _run(UI / "pages" / "0_Learning_Path.py")
    headers = [h.value for h in at.subheader]
    assert len(headers) == 5
    assert headers[0].startswith("1. Understand CWE-918")


def test_learn_page_explain_button(fixture_graph):
    at = _run(UI / "pages" / "1_Learn.py")
    at.button[0].click().run()
    assert not at.exception, [e.value for e in at.exception]
    rendered = " ".join(m.value for m in at.markdown)
    assert "CWE-918" in rendered
    assert "No LLM server was reachable" in rendered


def test_explore_page_unknown_term(fixture_graph):
    at = AppTest.from_file(str(UI / "pages" / "2_Explore.py"), default_timeout=30)
    at.run()
    at.text_input[0].input("zzzz-not-a-weakness").run()
    assert not at.exception
    assert at.warning


def test_attack_chains_page_lists_chain(fixture_graph):
    at = _run(UI / "pages" / "3_Attack_Chains.py")
    assert any("CAPEC-100" in m.value for m in at.markdown)
