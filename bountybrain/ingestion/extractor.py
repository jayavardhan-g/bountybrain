"""Structured extraction over report bodies.

Primary path: LLM (via clients.llm.structured). Because the whole system
must run without any LLM configured (e.g. in CI), we also have a rule-
based fallback that pulls obvious signals with regex — enough to populate
the KG for the seed corpus and let the UI light up.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from bountybrain.clients.llm import LLMError, chat, load_prompt


class ReportExtraction(BaseModel):
    vuln_type: str
    root_cause: str | None = None
    techniques: list[str] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    target_tech: list[str] = Field(default_factory=list)
    patch_description: str | None = None
    bypasses_report_urls: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    difficulty: str = "beginner"
    key_takeaway: str | None = None


# --- fallback ---

VULN_PATTERNS = [
    ("SSRF", r"\bSSRF\b|server[- ]side request forgery"),
    ("IDOR", r"\bIDOR\b|insecure direct object reference"),
    ("RCE", r"\bRCE\b|remote code execution|arbitrary code execution"),
    ("SQLi", r"\bSQL ?injection\b|\bSQLi\b"),
    ("XSS", r"\bXSS\b|cross[- ]site scripting"),
    ("CSRF", r"\bCSRF\b|cross[- ]site request forgery"),
    ("SSTI", r"\bSSTI\b|server[- ]side template injection"),
    ("XXE", r"\bXXE\b|xml external entity"),
    ("Auth Bypass", r"authentication bypass|auth bypass"),
    ("Path Traversal", r"path traversal|directory traversal|\.\./"),
    ("Open Redirect", r"open redirect"),
    ("GraphQL", r"graphql (introspection|abuse)"),
    ("Prototype Pollution", r"prototype pollution"),
    ("Race Condition", r"race condition|toctou"),
    ("Business Logic", r"business logic"),
]

TOOL_HINTS = [
    "burp",
    "burp suite",
    "nuclei",
    "ffuf",
    "gobuster",
    "sqlmap",
    "amass",
    "subfinder",
    "httpx",
    "waybackurls",
    "gau",
    "wappalyzer",
    "nmap",
    "postman",
    "curl",
    "graphql-voyager",
]

TARGET_HINTS = [
    "rails",
    "django",
    "flask",
    "spring",
    "express",
    "nginx",
    "apache",
    "jira",
    "confluence",
    "gitlab",
    "github",
    "aws",
    "s3",
    "kubernetes",
    "docker",
    "wordpress",
]


def _rule_based(title: str, body: str) -> ReportExtraction:
    text = f"{title}\n\n{body}"
    lower = text.lower()

    vuln = "Other"
    for name, pat in VULN_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            vuln = name
            break

    tools = sorted({t for t in TOOL_HINTS if t in lower})
    targets = sorted({t for t in TARGET_HINTS if t in lower})
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
    bypass_urls = re.findall(
        r"https?://\S*hackerone\.com/reports/\d+", text
    )

    # naive payload extraction: fenced code blocks that look like URLs/tags
    payloads = []
    for block in re.findall(r"```[\s\S]{0,400}?```", text):
        stripped = block.strip("`").strip()
        if len(stripped) < 200 and (
            "<" in stripped or "http" in stripped or "'" in stripped or "%00" in stripped
        ):
            payloads.append(stripped[:200])
    payloads = payloads[:5]

    takeaway = _first_sentence(body) or f"A {vuln} finding worth reviewing."

    difficulty = "beginner"
    if any(k in lower for k in ("chain", "novel", "bypass", "0day", "race")):
        difficulty = "intermediate"
    if any(k in lower for k in ("kernel", "sandbox escape", "jit")):
        difficulty = "advanced"

    return ReportExtraction(
        vuln_type=vuln,
        root_cause=None,
        techniques=[],
        payloads=payloads,
        tools_used=tools,
        target_tech=targets,
        patch_description=None,
        bypasses_report_urls=bypass_urls,
        cve_ids=cves,
        difficulty=difficulty,
        key_takeaway=takeaway,
    )


def _first_sentence(text: str) -> str | None:
    m = re.search(r"[^\n\.\!\?]{20,240}[\.\!\?]", text)
    return m.group(0).strip() if m else None


# --- main entry ---


def extract(title: str, url: str, body: str, use_llm: bool = True) -> ReportExtraction:
    """Return structured facts about a report.

    If `use_llm` is True we ask the configured LLM first, then validate.
    Any failure (network, JSON error, missing provider) transparently
    falls through to the rule-based extractor.
    """
    if use_llm:
        try:
            prompt = load_prompt("extract", title=title, url=url, body=body[:8000])
            raw = chat(
                system="You are a careful information extractor.",
                user=prompt,
            )
            data = _first_json(raw)
            if data:
                data.setdefault("difficulty", "beginner")
                return ReportExtraction.model_validate(data)
        except (LLMError, Exception):
            pass
    return _rule_based(title, body)


def _first_json(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
