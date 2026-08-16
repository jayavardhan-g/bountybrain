from __future__ import annotations

import json
from pathlib import Path

from bountybrain.recon.parsers import parse_recon_file


def _write(tmp_path: Path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_parse_subfinder(tmp_path):
    p = _write(
        tmp_path,
        "subfinder.txt",
        "api.acme.com\nadmin.acme.com\nnot a host\n",
    )
    out = parse_recon_file(p, tool_hint="subfinder")
    assert len(out) == 2
    assert out[0].type == "subdomain"
    assert out[0].target == "acme.com"


def test_parse_httpx_jsonl(tmp_path):
    lines = [
        json.dumps(
            {
                "url": "https://api.acme.com/",
                "host": "api.acme.com",
                "status_code": 200,
                "tech": ["rails"],
            }
        ),
        json.dumps({"url": "https://x.acme.com/", "host": "x.acme.com", "status_code": 404}),
    ]
    p = _write(tmp_path, "httpx.jsonl", "\n".join(lines))
    out = parse_recon_file(p, tool_hint="httpx")
    types = [f.type for f in out]
    assert "url" in types and "tech" in types


def test_parse_nuclei(tmp_path):
    lines = [
        json.dumps(
            {
                "template-id": "cve-2021-44228",
                "host": "https://vuln.example.com",
                "matched-at": "https://vuln.example.com/",
                "info": {
                    "severity": "critical",
                    "name": "Log4Shell",
                    "classification": {"cve-id": ["CVE-2021-44228"]},
                },
            }
        )
    ]
    p = _write(tmp_path, "nuclei.jsonl", "\n".join(lines))
    out = parse_recon_file(p, tool_hint="nuclei")
    kinds = {f.type for f in out}
    assert "endpoint" in kinds
    assert any(f.type == "cve" and "CVE-2021-44228" in f.value for f in out)


def test_parse_urls(tmp_path):
    p = _write(
        tmp_path,
        "wayback.txt",
        "https://a.acme.com/x\nhttps://a.acme.com/y?z=1\nnot-a-url\n",
    )
    out = parse_recon_file(p, tool_hint="waybackurls")
    assert all(f.type == "url" for f in out)
    assert len(out) == 2


def test_parse_wappalyzer(tmp_path):
    payload = json.dumps(
        [
            {"url": "https://acme.com", "technologies": [{"name": "Nginx"}, {"name": "Rails"}]}
        ]
    )
    p = _write(tmp_path, "wapp.json", payload)
    out = parse_recon_file(p, tool_hint="wappalyzer")
    values = sorted(f.value for f in out)
    assert values == ["Nginx", "Rails"]


def test_nuclei_cve_id_string_is_not_iterated_per_character(tmp_path):
    """nuclei writes `cve-id` as a bare string for single-CVE templates.

    Looping it directly yields one finding per character, which silently
    floods the planner with garbage CVE ids.
    """
    p = _write(
        tmp_path,
        "nuclei.jsonl",
        json.dumps(
            {
                "template-id": "CVE-2021-22205",
                "host": "https://git.acme.example",
                "matched-at": "https://git.acme.example/x",
                "info": {
                    "name": "GitLab RCE",
                    "severity": "critical",
                    "classification": {"cve-id": "CVE-2021-22205"},
                },
            }
        ),
    )
    findings = parse_recon_file(p, tool_hint="nuclei")
    cves = [f.value for f in findings if f.type == "cve"]
    assert cves == ["CVE-2021-22205"]


def test_nuclei_cve_id_list_still_works(tmp_path):
    p = _write(
        tmp_path,
        "nuclei.jsonl",
        json.dumps(
            {
                "template-id": "multi",
                "host": "https://x.example",
                "info": {
                    "name": "Multi",
                    "severity": "high",
                    "classification": {"cve-id": ["CVE-2020-1111", "CVE-2020-2222"]},
                },
            }
        ),
    )
    cves = {f.value for f in parse_recon_file(p, tool_hint="nuclei") if f.type == "cve"}
    assert cves == {"CVE-2020-1111", "CVE-2020-2222"}


def test_host_is_normalised_across_tools(tmp_path):
    """httpx says `git.acme.example`, nuclei says `https://git.acme.example`.

    Without normalisation the same machine becomes two assets and its plan
    is split in half.
    """
    from bountybrain.recon.parsers import _normalise_host

    for raw in (
        "git.acme.example",
        "https://git.acme.example",
        "https://git.acme.example/path",
        "git.acme.example:8443",
        "HTTPS://GIT.ACME.EXAMPLE",
        "git.acme.example.",
    ):
        assert _normalise_host(raw) == "git.acme.example", raw


def test_findings_from_different_tools_share_an_asset(tmp_path):
    httpx = _write(
        tmp_path,
        "httpx.jsonl",
        json.dumps(
            {"url": "https://git.acme.example/", "host": "git.acme.example", "tech": ["GitLab"]}
        ),
    )
    nuclei = _write(
        tmp_path,
        "nuclei.jsonl",
        json.dumps(
            {
                "template-id": "CVE-2021-22205",
                "host": "https://git.acme.example",
                "info": {"name": "x", "classification": {"cve-id": "CVE-2021-22205"}},
            }
        ),
    )
    findings = parse_recon_file(httpx) + parse_recon_file(nuclei)
    assert {f.asset for f in findings} == {"git.acme.example"}
