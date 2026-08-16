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
