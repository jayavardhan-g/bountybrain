"""Round-trip KG test: insert 2 reports, query by vuln, expect them both."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch, tmp_path):
    # steer the KG to a fresh sqlite for the test
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'test.sqlite'}"
    )
    # force config reload
    from importlib import reload

    import bountybrain.config as cfg
    reload(cfg)
    import bountybrain.kg.db as db

    reload(db)
    db.init_db()
    yield


def test_kg_roundtrip():
    from bountybrain.kg.db import Session
    from bountybrain.kg.models import Report, ReportExploitsVuln, Vulnerability
    from bountybrain.kg.queries import kg_query, upsert, link

    with Session() as s:
        r1 = Report(source="seed", url="seed://t/1", title="T1", raw_markdown="x")
        r2 = Report(source="seed", url="seed://t/2", title="T2", raw_markdown="x")
        s.add_all([r1, r2])
        s.flush()
        v = upsert(s, Vulnerability, "name", "SSRF")
        link(s, ReportExploitsVuln, report_id=r1.id, vuln_id=v.id)
        link(s, ReportExploitsVuln, report_id=r2.id, vuln_id=v.id)

    rows = kg_query("vulnerability", "SSRF", "reports")
    titles = sorted(r["title"] for r in rows)
    assert titles == ["T1", "T2"]
