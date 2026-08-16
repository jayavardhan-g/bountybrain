"""Parsers for recon-tool output files.

Auto-detects format from file extension + content. Each parser returns a
list of `ReconFinding`. Never sends any network requests.
"""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Iterable

from .models import ReconFinding

URL_RE = re.compile(r"https?://[^\s\"']+")
HOST_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)


def parse_recon_file(path: str | Path, tool_hint: str | None = None) -> list[ReconFinding]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="ignore")
    tool = (tool_hint or _detect_tool(p, text)).lower()

    if tool in ("subfinder", "amass"):
        return _parse_subdomain_list(text, tool)
    if tool == "httpx":
        return _parse_httpx(text)
    if tool == "nuclei":
        return _parse_nuclei(text)
    if tool in ("waybackurls", "gau"):
        return _parse_url_list(text, tool)
    if tool == "wappalyzer":
        return _parse_wappalyzer(text)
    if tool == "csv":
        return _parse_csv(text)
    # generic best-effort
    return _parse_generic(text)


def _detect_tool(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    stripped = text.strip()
    name = path.name.lower()

    if "subfinder" in name:
        return "subfinder"
    if "amass" in name:
        return "amass"
    if "httpx" in name:
        return "httpx"
    if "nuclei" in name:
        return "nuclei"
    if "wayback" in name or name.endswith("_urls.txt"):
        return "waybackurls"
    if "gau" in name:
        return "gau"
    if "wappalyzer" in name:
        return "wappalyzer"
    if suffix == ".csv":
        return "csv"

    first_line = stripped.split("\n", 1)[0].strip()
    if first_line.startswith("{"):
        # jsonl vs single object
        try:
            obj = json.loads(first_line)
            if "template-id" in obj or "matcher-name" in obj:
                return "nuclei"
            if "status_code" in obj or "scheme" in obj:
                return "httpx"
            if "technologies" in obj:
                return "wappalyzer"
        except Exception:
            pass
    if all(URL_RE.fullmatch(line.strip()) for line in stripped.splitlines()[:5] if line.strip()):
        return "waybackurls"
    if all(HOST_RE.match(line.strip()) for line in stripped.splitlines()[:5] if line.strip()):
        return "subfinder"
    return "generic"


def _parse_subdomain_list(text: str, tool: str) -> list[ReconFinding]:
    out: list[ReconFinding] = []
    for line in text.splitlines():
        host = line.strip()
        if not host or not HOST_RE.match(host):
            continue
        out.append(
            ReconFinding(target=_root_domain(host), type="subdomain", value=host, source_tool=tool)
        )
    return out


def _parse_url_list(text: str, tool: str) -> list[ReconFinding]:
    out: list[ReconFinding] = []
    for line in text.splitlines():
        url = line.strip()
        if not URL_RE.fullmatch(url):
            continue
        host = url.split("//", 1)[-1].split("/", 1)[0]
        out.append(
            ReconFinding(
                target=_root_domain(host), type="url", value=url, source_tool=tool
            )
        )
    return out


def _parse_httpx(text: str) -> list[ReconFinding]:
    out: list[ReconFinding] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input") or ""
        host = obj.get("host") or url.split("//", 1)[-1].split("/", 1)[0]
        tech = obj.get("tech") or obj.get("technologies") or []
        if url:
            out.append(
                ReconFinding(
                    target=_root_domain(host),
                    type="url",
                    value=url,
                    evidence=f"status={obj.get('status_code')}",
                    source_tool="httpx",
                )
            )
        for t in tech or []:
            out.append(
                ReconFinding(
                    target=_root_domain(host),
                    type="tech",
                    value=str(t),
                    source_tool="httpx",
                )
            )
    return out


def _parse_nuclei(text: str) -> list[ReconFinding]:
    out: list[ReconFinding] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("matched-at", "").split("//", 1)[-1].split("/", 1)[0]
        template = obj.get("template-id") or obj.get("templateID") or obj.get("template")
        info = obj.get("info") or {}
        severity = info.get("severity")
        name = info.get("name") or template
        # `cve-id` is a bare string for single-CVE templates and a list for
        # multi-CVE ones. Iterating the string form yields one finding per
        # *character*, so it has to be normalised before the loop below.
        raw_cves = (info.get("classification") or {}).get("cve-id") or []
        if isinstance(raw_cves, str):
            raw_cves = [raw_cves]
        cves = [c for c in raw_cves if str(c).upper().startswith("CVE-")]
        if template:
            out.append(
                ReconFinding(
                    target=_root_domain(host or ""),
                    type="endpoint",
                    value=obj.get("matched-at") or template,
                    evidence=f"template={template} severity={severity} name={name}",
                    source_tool="nuclei",
                )
            )
        for c in cves or []:
            out.append(
                ReconFinding(
                    target=_root_domain(host or ""),
                    type="cve",
                    value=str(c).upper(),
                    source_tool="nuclei",
                )
            )
    return out


def _parse_wappalyzer(text: str) -> list[ReconFinding]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[ReconFinding] = []
    items = payload if isinstance(payload, list) else [payload]
    for entry in items:
        url = entry.get("url", "")
        host = url.split("//", 1)[-1].split("/", 1)[0]
        for t in entry.get("technologies", []) or []:
            name = t.get("name") if isinstance(t, dict) else str(t)
            out.append(
                ReconFinding(
                    target=_root_domain(host),
                    type="tech",
                    value=name,
                    source_tool="wappalyzer",
                )
            )
    return out


def _parse_csv(text: str) -> list[ReconFinding]:
    reader = csv.DictReader(io.StringIO(text))
    out: list[ReconFinding] = []
    for row in reader:
        target = row.get("target") or row.get("host") or row.get("domain") or ""
        for k, v in row.items():
            if not v or k in ("target", "host", "domain"):
                continue
            key = k.lower()
            if key == "cve":
                out.append(
                    ReconFinding(target=target, type="cve", value=v, source_tool="csv")
                )
            elif key in ("tech", "technology"):
                out.append(
                    ReconFinding(target=target, type="tech", value=v, source_tool="csv")
                )
            elif key in ("url", "endpoint"):
                out.append(
                    ReconFinding(target=target, type="url", value=v, source_tool="csv")
                )
            elif key in ("subdomain", "host"):
                out.append(
                    ReconFinding(
                        target=target or _root_domain(v),
                        type="subdomain",
                        value=v,
                        source_tool="csv",
                    )
                )
            else:
                out.append(
                    ReconFinding(
                        target=target, type="other", value=v, evidence=k, source_tool="csv"
                    )
                )
    return out


def _parse_generic(text: str) -> list[ReconFinding]:
    out: list[ReconFinding] = []
    for line in text.splitlines():
        s = line.strip()
        if URL_RE.fullmatch(s):
            host = s.split("//", 1)[-1].split("/", 1)[0]
            out.append(
                ReconFinding(
                    target=_root_domain(host), type="url", value=s, source_tool="generic"
                )
            )
        elif HOST_RE.match(s):
            out.append(
                ReconFinding(
                    target=_root_domain(s),
                    type="subdomain",
                    value=s,
                    source_tool="generic",
                )
            )
    return out


def _root_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])
