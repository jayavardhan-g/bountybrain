"""Learning-path fallbacks and the faithfulness claim splitter.

Both are pure logic over small inputs: the path builder over a fixture graph,
the splitter over literal markdown. No model, no indexes.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from bountybrain.agent.path import learning_path
from bountybrain.eval.faithfulness import lexical_overlap, split_claims
from bountybrain.kg import db
from bountybrain.kg.models import (
    Base,
    Document,
    DocumentCoversWeakness,
    Technique,
    TechniqueTargetsWeakness,
    Vulnerability,
    WeaknessRelation,
)


@pytest.fixture
def graph(monkeypatch):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    monkeypatch.setattr(db, "_engine", engine)
    monkeypatch.setattr(
        db, "_Session", sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    )
    return engine


@pytest.fixture
def family(graph):
    """Injection (parent, has a pattern + lab) → SQLi (child, has a writeup)."""
    with db.Session() as s:
        parent = Vulnerability(cwe_id=74, name="Injection", abstraction="Class")
        child = Vulnerability(
            cwe_id=89, name="SQL Injection", abstraction="Base", aliases_json=json.dumps(["SQLi"])
        )
        s.add_all([parent, child])
        s.flush()
        s.add(WeaknessRelation(src_id=child.id, dst_id=parent.id, nature="ChildOf"))
        hard = Technique(capec_id=2, name="Hard pattern", min_skill="High")
        easy = Technique(capec_id=3, name="Easy pattern", min_skill="Low")
        unrated = Technique(capec_id=1, name="Unrated pattern", min_skill=None)
        s.add_all([hard, easy, unrated])
        s.flush()
        for t in (hard, easy, unrated):
            s.add(TechniqueTargetsWeakness(technique_id=t.id, vuln_id=parent.id))
        doc = Document(doc_type="writeup", source="x", url="u", title="SQLi in search", body="")
        s.add(doc)
        s.flush()
        s.add(DocumentCoversWeakness(document_id=doc.id, vuln_id=child.id))
    return graph


def _stage(path: dict, key: str) -> dict:
    return next(s for s in path["stages"] if s["key"] == key)


def test_patterns_are_ordered_easiest_first_unrated_last(family):
    path = learning_path("CWE-74")
    names = [p["name"] for p in _stage(path, "patterns")["items"]]
    assert names == ["Easy pattern", "Hard pattern", "Unrated pattern"]


def test_child_inherits_patterns_from_parent_and_says_so(family):
    path = learning_path("SQLi")
    patterns = _stage(path, "patterns")
    assert patterns["items"]
    assert patterns["inherited_from"] == "CWE-74"
    assert _stage(path, "writeups")["inherited_from"] is None


def test_parent_borrows_disclosures_from_child(family):
    writeups = _stage(learning_path("CWE-74"), "writeups")
    assert [d["title"] for d in writeups["items"]] == ["SQLi in search"]
    assert writeups["inherited_from"] == "CWE-89"


def test_unknown_topic_has_no_path(family):
    assert learning_path("definitely not a weakness") is None


# ------------------------------------------------------------ faithfulness


def test_split_claims_attaches_citations_and_drops_structure():
    md = """# SSRF

## What it is

SSRF lets an attacker make the server send requests to internal hosts [1].
It often targets cloud metadata endpoints. [2] Filters can be bypassed with redirects [1, 3].

```
curl http://169.254.169.254/
```

- Check every parameter that takes a URL [2-4].
**Key takeaways**
"""
    claims = split_claims(md)
    assert [c["cites"] for c in claims] == [[1], [2], [1, 3], [2, 3, 4]]
    assert claims[1]["text"].startswith("It often targets")
    assert not any("curl" in c["text"] for c in claims)


def test_lexical_overlap_ignores_stopwords_and_citations():
    assert lexical_overlap("The server fetches internal URLs [1].", ["server fetches internal urls"]) == 1.0
    assert lexical_overlap("Payload uses gopher scheme.", ["nothing relevant here"]) == 0.0

