"""Graph query tests against a small in-memory graph.

These build a handful of rows rather than loading the real 112k-node graph, so
they run in milliseconds with no downloads. Each one pins a behaviour that was
either broken or absent before: chain traversal that ignored half its edges,
the curated alias layer never reaching the database, and the recon -> disclosed
report join.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from bountybrain.datasets import cwe as cwe_ds
from bountybrain.kg import db, queries
from bountybrain.kg.build import _merged_aliases
from bountybrain.kg.models import (
    Base,
    Document,
    DocumentCoversWeakness,
    Technique,
    TechniqueRelation,
    Vulnerability,
)


@pytest.fixture
def graph(monkeypatch):
    """Point `kg.db.Session` at a throwaway in-memory database."""
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


# ------------------------------------------------------------ attack chains


@pytest.fixture
def chain_graph(graph):
    """Alpha -> Beta stated as CanPrecede; Beta -> Gamma stated as CanFollow.

    CAPEC records a link from whichever side the author wrote it, so a correct
    walk has to read both directions to recover the same chain.
    """
    with db.Session() as s:
        alpha = Technique(capec_id=100, name="Alpha")
        beta = Technique(capec_id=200, name="Beta")
        gamma = Technique(capec_id=300, name="Gamma")
        s.add_all([alpha, beta, gamma])
        s.flush()
        s.add_all(
            [
                # "Alpha CanPrecede Beta"
                TechniqueRelation(src_id=alpha.id, dst_id=beta.id, nature="CanPrecede"),
                # "Gamma CanFollow Beta" — same fact, opposite direction
                TechniqueRelation(src_id=gamma.id, dst_id=beta.id, nature="CanFollow"),
            ]
        )
    return graph


def test_attack_chain_follows_canprecede_and_canfollow(chain_graph):
    chains = queries.attack_chain(100, depth=3)
    assert chains, "expected at least one chain"
    assert [step["capec_id"] for step in chains[0]] == [100, 200, 300]


def test_attack_chain_recovers_chains_stated_only_as_canfollow(chain_graph):
    """Starting at Beta, the only outgoing edge is a CanFollow written by Gamma.

    Before the fix this returned nothing at all, which is what made the Attack
    Chains page empty for every topic.
    """
    chains = queries.attack_chain(200, depth=3)
    assert [step["capec_id"] for step in chains[0]] == [200, 300]


def test_attack_chain_does_not_report_a_single_node_as_a_chain(chain_graph):
    assert queries.attack_chain(300, depth=3) == []


def test_attack_chain_is_empty_for_unknown_pattern(chain_graph):
    assert queries.attack_chain(999_999) == []


def test_attack_chain_terminates_on_a_cycle(graph):
    """Mutually-preceding patterns must not recurse forever."""
    with db.Session() as s:
        a = Technique(capec_id=1, name="A")
        b = Technique(capec_id=2, name="B")
        s.add_all([a, b])
        s.flush()
        s.add_all(
            [
                TechniqueRelation(src_id=a.id, dst_id=b.id, nature="CanPrecede"),
                TechniqueRelation(src_id=b.id, dst_id=a.id, nature="CanPrecede"),
            ]
        )
    chains = queries.attack_chain(1, depth=3)
    assert chains and all(len(c) <= 4 for c in chains)


# --------------------------------------------------------- curated aliases


def test_curated_aliases_invert_to_every_class():
    by_cwe = cwe_ds.curated_aliases_by_cwe()
    assert "idor" in by_cwe[639]
    assert "ssti" in by_cwe[1336]
    # nothing is lost in the inversion
    assert sum(len(v) for v in by_cwe.values()) == len(cwe_ds.COMMUNITY_ALIASES)


def test_merged_aliases_keeps_official_terms_first_and_dedupes():
    w = cwe_ds.Weakness(
        cwe_id=639,
        name="Authorization Bypass Through User-Controlled Key",
        abstraction="Base",
        status="Draft",
        description="d",
        aliases=["IDOR"],  # MITRE happens to state it too, in different case
    )
    merged = _merged_aliases(w, {639: ["idor", "insecure direct object reference"]})
    assert merged[0] == "IDOR", "official spelling should lead"
    assert merged.count("IDOR") == 1
    assert "idor" not in merged, "case-insensitive duplicate should be dropped"
    assert "insecure direct object reference" in merged


def test_find_weakness_resolves_a_curated_alias_from_the_database(graph):
    """The regression this whole fix exists for: 'IDOR' must resolve.

    The alias only reaches the database because the builder persists the
    curated layer, so this is an end-to-end check of that path.
    """
    curated = cwe_ds.curated_aliases_by_cwe()
    w = cwe_ds.Weakness(
        cwe_id=639,
        name="Authorization Bypass Through User-Controlled Key",
        abstraction="Base",
        status="Draft",
        description="d",
    )
    with db.Session() as s:
        s.add(
            Vulnerability(
                cwe_id=639,
                name=w.name,
                abstraction="Base",
                aliases_json=json.dumps(_merged_aliases(w, curated)),
            )
        )

    found = queries.find_weakness("idor")
    assert found is not None and found["cwe_id"] == 639


# ------------------------------------------------- recon -> disclosed reports


@pytest.fixture
def report_graph(graph):
    with db.Session() as s:
        ssrf = Vulnerability(cwe_id=918, name="Server-Side Request Forgery (SSRF)")
        xss = Vulnerability(cwe_id=79, name="Cross-site Scripting")
        s.add_all([ssrf, xss])
        s.flush()

        on_stack = Document(
            doc_type="writeup", source="pentesterland", url="https://e.com/1",
            title="SSRF in GitLab CI runner", body="b", program="GitLab", bounty=1_000.0,
        )
        richer = Document(
            doc_type="writeup", source="pentesterland", url="https://e.com/2",
            title="A generic SSRF write-up", body="b", program="Acme", bounty=5_000.0,
        )
        same_program = Document(
            doc_type="writeup", source="pentesterland", url="https://e.com/3",
            title="Stored XSS in the issue tracker", body="b", program="GitLab", bounty=250.0,
        )
        s.add_all([on_stack, richer, same_program])
        s.flush()
        s.add_all(
            [
                DocumentCoversWeakness(document_id=on_stack.id, vuln_id=ssrf.id, provenance="labelled"),
                DocumentCoversWeakness(document_id=richer.id, vuln_id=ssrf.id, provenance="labelled"),
                DocumentCoversWeakness(document_id=same_program.id, vuln_id=xss.id, provenance="labelled"),
            ]
        )
    return graph


def test_reports_naming_the_fingerprinted_stack_outrank_richer_ones(report_graph):
    """A $1k report on the stack you are actually looking at beats a $5k generic one."""
    reports = queries.writeups_for_recon([918], ["gitlab"])
    assert [r["title"] for r in reports][0] == "SSRF in GitLab CI runner"
    assert reports[0]["matched_products"] == ["gitlab"]
    assert reports[1]["matched_products"] == []


def test_reports_fall_back_to_bounty_without_a_stack_match(report_graph):
    reports = queries.writeups_for_recon([918], [])
    assert [r["bounty"] for r in reports] == [5_000.0, 1_000.0]


def test_reports_do_not_match_products_inside_longer_words(report_graph):
    """'git' must not fire inside 'GitLab' and claim a match that is not there."""
    reports = queries.writeups_for_recon([918], ["git"])
    assert all(r["matched_products"] == [] for r in reports)


def test_writeups_for_recon_is_empty_without_classes(report_graph):
    assert queries.writeups_for_recon([], ["gitlab"]) == []


def test_product_boundaries_hold_for_every_alternative(report_graph):
    """`|` binds looser than the look-arounds, so a middle alternative is the
    one that escapes its boundaries if the pattern is not grouped."""
    reports = queries.writeups_for_recon([918], ["nginx", "git", "apache"])
    assert all(r["matched_products"] == [] for r in reports)


def test_product_match_is_reported_for_the_right_product(report_graph):
    reports = queries.writeups_for_recon([918], ["gitlab", "jenkins"])
    assert reports[0]["matched_products"] == ["gitlab"]


def test_related_reports_link_by_shared_weakness_and_by_program(report_graph):
    with db.Session() as s:
        first = s.query(Document).filter_by(url="https://e.com/1").one()
        doc_id = first.id

    related = queries.related_writeups(doc_id)
    by_url = {r["url"]: r for r in related}

    # same weakness class, different program
    assert by_url["https://e.com/2"]["shared_weaknesses"] == [918]
    # same program, different weakness class
    assert by_url["https://e.com/3"]["shared_program"] is True
    assert by_url["https://e.com/3"]["shared_weaknesses"] == []
    # a shared class is the stronger signal and ranks first
    assert related[0]["url"] == "https://e.com/2"


def test_related_reports_excludes_the_report_itself(report_graph):
    with db.Session() as s:
        doc_id = s.query(Document).filter_by(url="https://e.com/1").one().id
    assert all(r["id"] != doc_id for r in queries.related_writeups(doc_id))


def test_related_reports_of_unknown_document_is_empty(report_graph):
    assert queries.related_writeups(999_999) == []


def test_exact_alias_beats_a_more_specific_name_match(graph):
    """"SQL injection" is CWE-89's alias; it must not resolve to a Variant whose
    *name* merely contains the phrase."""
    with db.Session() as s:
        s.add_all(
            [
                Vulnerability(
                    cwe_id=89,
                    name="Improper Neutralization ... ('SQL Injection')",
                    abstraction="Base",
                    aliases_json=json.dumps(["SQL injection", "SQLi"]),
                ),
                Vulnerability(cwe_id=564, name="SQL Injection: Hibernate", abstraction="Variant"),
            ]
        )
    assert queries.find_weakness("SQL injection")["cwe_id"] == 89
    assert queries.find_weakness("sql INJECTION")["cwe_id"] == 89
    assert queries.find_weakness("Hibernate")["cwe_id"] == 564
