"""Smoke: agent falls through to template when LLM and Qdrant are absent."""
from __future__ import annotations

from bountybrain.agent.tools import _template_report


def test_template_report_no_sources():
    md = _template_report("SSRF", [])
    assert "SSRF" in md


def test_template_report_with_sources():
    md = _template_report(
        "SSRF",
        [{"title": "Example report", "url": "seed://ssrf-001", "text": "body"}],
    )
    assert "Example report" in md
    assert "[[1]](seed://ssrf-001)" in md
