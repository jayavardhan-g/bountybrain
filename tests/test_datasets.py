"""Dataset parser tests.

These run against small inline fixtures rather than the real downloads, so
the suite stays fast and works in CI without fetching ~1 GB. The one
exception is `test_curated_aliases_are_real_cwes`, which is skipped unless
the catalogue is present — it guards a class of bug that inline fixtures
cannot catch.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from bountybrain.datasets import cwe as cwe_ds
from bountybrain.datasets import docs as docs_ds
from bountybrain.datasets import exploitdb as edb_ds
from bountybrain.datasets import nuclei as nuclei_ds
from bountybrain.datasets import pentesterland as pl_ds
from bountybrain.datasets.fetch import resolve_unpacked
from bountybrain.datasets.registry import BY_NAME, DATASETS

# --------------------------------------------------------------- registry


def test_every_dataset_declares_a_licence():
    for d in DATASETS:
        assert d.license, f"{d.name} has no licence recorded"
        assert d.attribution, f"{d.name} has no attribution recorded"


def test_dataset_names_are_unique():
    names = [d.name for d in DATASETS]
    assert len(names) == len(set(names))


# --------------------------------------------------------------------- CWE


CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="89" Name="Improper Neutralization ('SQL Injection')" Abstraction="Base" Status="Stable">
      <Description>The product constructs SQL from untrusted input.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="943" View_ID="1000"/>
        <Related_Weakness Nature="Nonsense" CWE_ID="1" View_ID="1000"/>
      </Related_Weaknesses>
      <Alternate_Terms>
        <Alternate_Term><Term>SQLi</Term></Alternate_Term>
      </Alternate_Terms>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Observed_Examples>
        <Observed_Example><Reference>CVE-2021-1234</Reference></Observed_Example>
        <Observed_Example><Reference>BID-999</Reference></Observed_Example>
      </Observed_Examples>
    </Weakness>
    <Weakness ID="943" Name="Improper Neutralization in Data Query Logic" Abstraction="Class" Status="Draft">
      <Description>Parent class.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


@pytest.fixture
def cwe_file(tmp_path: Path) -> Path:
    p = tmp_path / "cwec.xml"
    p.write_text(CWE_XML, encoding="utf-8")
    return p


def test_cwe_parses_weaknesses_and_relations(cwe_file):
    ws = cwe_ds.load(cwe_file)
    assert len(ws) == 2
    sqli = next(w for w in ws if w.cwe_id == 89)
    assert sqli.likelihood == "High"
    assert ("ChildOf", 943) in sqli.relations
    # unknown natures are dropped rather than polluting the graph
    assert all(n in cwe_ds.KEPT_NATURES for n, _ in sqli.relations)


def test_cwe_observed_examples_keep_only_cves(cwe_file):
    sqli = next(w for w in cwe_ds.load(cwe_file) if w.cwe_id == 89)
    assert sqli.observed_cves == ["CVE-2021-1234"]


def test_alias_map_resolves_abbreviations_and_parentheticals(cwe_file):
    aliases = cwe_ds.alias_map(cwe_ds.load(cwe_file))
    assert aliases["sqli"] == 89
    assert aliases["sql injection"] == 89  # from the quoted parenthetical


def test_alias_map_prefers_specific_abstraction(cwe_file):
    """A Base weakness should win over a Class one for a shared alias."""
    aliases = cwe_ds.alias_map(cwe_ds.load(cwe_file))
    assert aliases.get("improper neutralization in data query logic") == 943


def test_community_aliases_do_not_collide_with_non_vulnerability_labels():
    overlap = set(cwe_ds.COMMUNITY_ALIASES) & set(cwe_ds.NON_VULNERABILITY_LABELS)
    assert not overlap, f"labels are both mapped and excluded: {overlap}"


@pytest.mark.skipif(
    resolve_unpacked(BY_NAME["cwe"]) is None,
    reason="CWE catalogue not downloaded; run python fetch_data.py",
)
def test_curated_aliases_are_real_cwes():
    """Every hand-curated alias must point at a weakness that exists.

    CWE-840 and CWE-16 are *categories*, not weaknesses, and are absent from
    the Weaknesses container — mapping to them would create dangling edges.
    """
    path = resolve_unpacked(BY_NAME["cwe"])
    valid = {w.cwe_id for w in cwe_ds.load(path)}
    dangling = {k: v for k, v in cwe_ds.COMMUNITY_ALIASES.items() if v not in valid}
    assert not dangling, f"aliases point at non-existent weaknesses: {dangling}"


# ------------------------------------------------------------------ nuclei


TEMPLATE = """
id: CVE-2022-1234
info:
  name: Example Product - Cross-Site Scripting
  author: someone
  severity: medium
  description: A reflected XSS in the search parameter.
  tags: cve,cve2022,xss,wordpress
  classification:
    cvss-score: 6.1
    cve-id: CVE-2022-1234
    cwe-id: CWE-79
    epss-score: 0.42
    cpe: "cpe:2.3:a:vendorname:productname:*:*:*:*:*:wordpress:*:*"
  metadata:
    vendor: vendorname
    product: productname
http:
  - method: GET
"""


def test_nuclei_parses_classification(tmp_path: Path):
    root = tmp_path
    p = root / "t.yaml"
    p.write_text(TEMPLATE, encoding="utf-8")
    sig = nuclei_ds.parse_template(p, root)
    assert sig is not None
    assert sig.cwe_ids == [79]
    assert sig.cve_ids == ["CVE-2022-1234"]
    assert sig.epss_score == 0.42
    assert sig.protocol == "http"
    assert sig.severity == "medium"


def test_nuclei_tech_keys_include_cpe_and_tags(tmp_path: Path):
    root = tmp_path
    p = root / "t.yaml"
    p.write_text(TEMPLATE, encoding="utf-8")
    keys = nuclei_ds.parse_template(p, root).tech_keys
    assert "vendorname" in keys and "productname" in keys
    assert "wordpress" in keys  # from tags


def test_nuclei_handles_csv_tags_and_missing_fields(tmp_path: Path):
    root = tmp_path
    p = root / "bare.yaml"
    p.write_text("id: x\ninfo:\n  name: Bare template\n", encoding="utf-8")
    sig = nuclei_ds.parse_template(p, root)
    assert sig is not None and sig.cwe_ids == [] and sig.tags == []


def test_nuclei_rejects_non_template_yaml(tmp_path: Path):
    root = tmp_path
    p = root / "notatemplate.yaml"
    p.write_text("some: mapping\nwithout: info\n", encoding="utf-8")
    assert nuclei_ds.parse_template(p, root) is None


# -------------------------------------------------------------- exploit-db


def test_exploitdb_deduplicates_ids(tmp_path: Path):
    """The published CSV repeats ~460 rows; id must still be unique."""
    csv_path = tmp_path / "files_exploits.csv"
    csv_path.write_text(
        "id,file,description,date_published,author,type,platform,port,date_added,"
        "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
        "1,a.rb,First,2010-01-01,x,dos,aix,,,,1,CVE-2009-3699;OSVDB-1,,,,,\n"
        "1,a.rb,First,2010-01-01,x,dos,aix,,,,1,CVE-2009-3699;OSVDB-1,,,,,\n"
        "2,b.rb,Second,2011-02-02,y,webapps,php,,,,0,,,,,,\n",
        encoding="utf-8",
    )
    exploits = edb_ds.load(csv_path)
    assert [e.edb_id for e in exploits] == [1, 2]
    assert exploits[0].cve_ids == ["CVE-2009-3699"]  # OSVDB codes are ignored
    assert exploits[0].verified is True and exploits[1].verified is False


# ---------------------------------------------------------- pentester.land


def test_pentesterland_parses_bounty_and_dates(tmp_path: Path):
    p = tmp_path / "writeups.json"
    p.write_text(
        '{"data":[{"Links":[{"Title":"A great SSRF","Link":"https://example.com/a"}],'
        '"Authors":["someone"],"Programs":["Acme"],"Bugs":["SSRF"],"Bounty":"2,500",'
        '"PublicationDate":"2022-03-04","AddedDate":"2022-03-05"}]}',
        encoding="utf-8",
    )
    writeups = pl_ds.load(p)
    assert len(writeups) == 1
    w = writeups[0]
    assert w.bounty == 2500.0
    assert w.year == 2022
    assert w.bugs == ["SSRF"]


def test_pentesterland_treats_dash_bounty_as_missing(tmp_path: Path):
    p = tmp_path / "writeups.json"
    p.write_text(
        '{"data":[{"Links":[{"Title":"T","Link":"https://e.com/x"}],"Bugs":["XSS"],'
        '"Bounty":"-","PublicationDate":"2021-01-01"}]}',
        encoding="utf-8",
    )
    assert pl_ds.load(p)[0].bounty is None


def test_coverage_excludes_non_vulnerability_labels():
    """Platform tags must not be counted as mapping failures."""
    writeups = [
        pl_ds.Writeup(title="a", url="u1", bugs=["SSRF"]),
        pl_ds.Writeup(title="b", url="u2", bugs=["Android"]),
    ]
    stats = pl_ds.normalise_labels(
        writeups, {"ssrf": 918}, frozenset({"android"})
    )
    # only the SSRF writeup is mappable, and it mapped -> 100%
    assert stats["mappable_writeups"] == 1
    assert stats["coverage"] == 1.0
    assert stats["coverage_all"] == 0.5


# -------------------------------------------------------------------- docs


def _long(text: str) -> str:
    """Pad past `docs.MIN_SECTION_CHARS` so the section is not filtered out."""
    return (text + " ") * 6


def test_docs_split_on_h2_and_percent_encode_urls(tmp_path: Path):
    root = tmp_path / "SQL Injection"
    root.mkdir()
    (root / "README.md").write_text(
        "# SQL Injection\n\n"
        + _long("Intro text about SQL injection fundamentals and how it arises.")
        + "\n\n## Entry Point Detection\n\n"
        + _long("How to locate injectable parameters across an application surface.")
        + "\n\n## Blind Injection\n\n"
        + _long("Extracting data when the response body reveals nothing directly.")
        + "\n",
        encoding="utf-8",
    )
    articles = docs_ds.load_payloads(tmp_path)
    sections = {a.section for a in articles}
    assert "Entry Point Detection" in sections and "Blind Injection" in sections
    assert all(" " not in a.url for a in articles)
    assert any(a.url.endswith("#entry-point-detection") for a in articles)


def test_docs_skip_table_of_contents_sections(tmp_path: Path):
    root = tmp_path / "Topic"
    root.mkdir()
    (root / "README.md").write_text(
        "# Topic\n\n"
        + _long("Intro paragraph kept in the index for retrieval purposes.")
        + "\n\n## Summary\n\n"
        + "* [One](https://example.com/1)\n* [Two](https://example.com/2)\n"
        + "* [Three](https://example.com/3)\n* [Four](https://example.com/4)\n"
        + "* [Five](https://example.com/5)\n* [Six](https://example.com/6)\n"
        + "* [Seven](https://example.com/7)\n* [Eight](https://example.com/8)\n"
        + "* [Nine](https://example.com/9)\n* [Ten](https://example.com/10)\n",
        encoding="utf-8",
    )
    assert all(a.section != "Summary" for a in docs_ds.load_payloads(tmp_path))
