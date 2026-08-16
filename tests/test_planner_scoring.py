"""Planner scoring unit tests.

These exercise the pure-function parts — normalisation and the scale helpers —
without needing a built graph, so they run in CI. The end-to-end ranking
quality is measured separately by `bountybrain/eval/planner.py`, which needs
the real corpus.
"""
from __future__ import annotations

import pytest

from bountybrain.recon.planner import (
    LIKELIHOOD_ONLY,
    ScoringWeights,
    _log_scale,
    _money_scale,
    normalise_tech_token,
)

# ------------------------------------------------------------- weights


def test_weights_normalise_to_one():
    w = ScoringWeights(applicability=2, exploitability=1, weaponisation=1, economics=1).normalised()
    total = w.applicability + w.exploitability + w.weaponisation + w.economics
    assert total == pytest.approx(1.0)
    assert w.applicability == pytest.approx(0.4)


def test_likelihood_only_ignores_value_terms():
    w = LIKELIHOOD_ONLY.normalised()
    assert w.applicability == pytest.approx(1.0)
    assert w.exploitability == w.weaponisation == w.economics == 0.0


def test_zero_weights_fall_back_to_defaults():
    w = ScoringWeights(0, 0, 0, 0).normalised()
    assert w.applicability > 0


# --------------------------------------------------------------- scales


def test_log_scale_is_bounded_and_monotonic():
    assert _log_scale(0, 40) == 0.0
    assert _log_scale(-5, 40) == 0.0
    values = [_log_scale(n, 40) for n in (1, 5, 20, 40, 400)]
    assert all(0.0 <= v <= 1.0 for v in values)
    assert values == sorted(values)
    assert _log_scale(40, 40) == pytest.approx(1.0)


def test_money_scale_spans_the_useful_bounty_range():
    assert _money_scale(None) == 0.0
    assert _money_scale(0) == 0.0
    assert _money_scale(100) == pytest.approx(0.0, abs=1e-9)
    assert _money_scale(10_000) == pytest.approx(1.0)
    assert _money_scale(1_000_000) == 1.0  # clamped
    assert _money_scale(1000) == pytest.approx(0.5)


# -------------------------------------------------- fingerprint parsing


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("WordPress", "wordpress"),
        ("Apache HTTP Server:2.4.41", "apache http server"),
        ("nginx 1.18.0", "nginx"),
        ("Node.js", "node.js"),
    ],
)
def test_tech_tokens_strip_versions(raw, expected):
    assert expected in normalise_tech_token(raw)


def test_tech_tokens_emit_word_variants():
    tokens = normalise_tech_token("Apache HTTP Server")
    # both the joined forms and the individual words, so either can match a
    # product node however it happens to be spelled in the graph
    assert "apache http server" in tokens
    assert "apache_http_server" in tokens
    assert "apache-http-server" in tokens
    assert "apache" in tokens


def test_tech_tokens_are_deduplicated_and_handle_empty():
    assert normalise_tech_token("") == []
    tokens = normalise_tech_token("nginx")
    assert len(tokens) == len(set(tokens))
