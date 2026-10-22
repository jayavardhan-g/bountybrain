"""Are the claims in generated tutorials supported by the sources they cite?

The tutorial prompt demands a citation per technical claim and forbids
inventing them. This suite checks both halves of that promise on the same
path the Learn page uses — graph context, hybrid + rerank retrieval, the
tutorial prompt — over a fixed list of topics.

Pipeline:

1. **Generate** one tutorial per topic and keep the exact sources shown.
2. **Split** each tutorial into sentences, deterministically (no model), and
   attach each sentence's `[n]` citation markers.
3. **Score** with three checks of increasing cost:
     citation_rate          sentences carrying at least one citation
     invalid_citation_rate  markers pointing at a source number that was never
                            given — a hallucinated citation, checkable exactly
     lexical floor          content-word overlap with the cited excerpts; a
                            cheap red flag, not a verdict
     judge verdict          an LLM judge reads the cited excerpts — truncated
                            exactly as the generator saw them — and labels the
                            sentence supported / partial / unsupported
4. **Calibrate the judge** against hand labels on a blind sample
   (`export_handcheck` → label → `agreement`). The judge is the same model as
   the generator, which is a known bias towards leniency; the hand check is
   what measures how much that matters.
"""
from __future__ import annotations

import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from rich.console import Console

from bountybrain.config import settings

console = Console()

# Thirty classes a bug bounty learner is likely to ask about, spread across
# injection, access control, client-side, protocol and logic bugs. Fixed so
# runs are comparable; chosen before any tutorial was generated.
TOPICS = [
    "SSRF", "IDOR", "Cross-site scripting", "SQL injection", "SSTI",
    "XXE", "CSRF", "Open redirect", "HTTP request smuggling", "Race condition",
    "Prototype pollution", "Insecure deserialization", "Path traversal",
    "Unrestricted file upload", "JWT", "CORS misconfiguration",
    "Subdomain takeover", "Web cache poisoning", "OS command injection",
    "Local file inclusion", "Clickjacking", "Mass assignment",
    "Business logic", "Information disclosure", "Account takeover",
    "OAuth", "Privilege escalation", "CRLF injection", "NoSQL injection",
    "Authentication bypass",
]

TOP_K = 6
SAMPLES_FILE = "faithfulness_samples.jsonl"
JUDGED_FILE = "faithfulness_claims.jsonl"
HANDCHECK_BLIND = "faithfulness_handcheck_blind.md"
HANDCHECK_LABELS = Path(__file__).resolve().parents[1] / "fixtures" / "faithfulness_handcheck.json"

Verdict = Literal["supported", "partial", "unsupported"]


class Judgement(BaseModel):
    verdict: Verdict
    reason: str = ""


# --------------------------------------------------------------------------
# 1. generation
# --------------------------------------------------------------------------


def generate(topics: list[str] = TOPICS, top_k: int = TOP_K) -> list[dict]:
    """One tutorial per topic, with the sources it was shown."""
    from bountybrain.agent import tools
    from bountybrain.clients.llm import achat_many

    rows, requests = [], []
    for topic in topics:
        context = tools.kg_context(topic)
        hits = tools.local_rag_search(topic, top_k=top_k)["hits"]
        rows.append(
            {
                "topic": topic,
                "weakness": (context.get("weakness") or {}).get("key"),
                "sources": [
                    {"n": i, "title": h["title"], "url": h["url"], "doc_type": h["doc_type"],
                     "text": h["text"][: tools.SOURCE_CHARS]}
                    for i, h in enumerate(hits, start=1)
                ],
            }
        )
        requests.append((tools.TUTORIAL_SYSTEM, tools.tutorial_prompt(topic, hits, context)))

    # Calls the model directly rather than through generate_tutorial, whose
    # template fallback would quietly turn a dead server into a "tutorial".
    replies = achat_many(requests, max_tokens=2048, concurrency=8)
    for row, reply in zip(rows, replies, strict=True):
        row["tutorial"] = reply
    return rows


# --------------------------------------------------------------------------
# 2. claim splitting
# --------------------------------------------------------------------------

_CITE = re.compile(r"\[(\d+(?:\s*[,–-]\s*\d+)*)\]")
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9`*_\"(\[])")
_LEADING_CITES = re.compile(r"^((?:\[\d+(?:\s*[,–-]\s*\d+)*\]\s*)+)")
_WORD = re.compile(r"[a-z0-9]+")
STOP = set(
    "a an the and or of to in on for with by is are be as it its this that these those can "
    "from at into if not no but you your an may will which when how what such than then "
    "they them their there also more most any all other use used using".split()
)


def _cited_numbers(text: str) -> list[int]:
    nums: list[int] = []
    for group in _CITE.findall(text):
        for part in re.split(r"\s*,\s*", group):
            if re.search(r"[–-]", part):
                a, b = (int(x) for x in re.split(r"\s*[–-]\s*", part))
                nums.extend(range(a, b + 1))
            else:
                nums.append(int(part))
    return sorted(set(nums))


def split_claims(markdown: str) -> list[dict]:
    """Sentences of a tutorial with the citation numbers each one carries.

    Headings and fenced code are not sentences. A citation that lands after a
    sentence's full stop (`... input. [3] Next ...`) belongs to the sentence
    before it, so leading markers are moved back.
    """
    text = re.sub(r"```.*?```", " ", markdown or "", flags=re.DOTALL)
    sentences: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or set(line) <= set("-*_= "):
            continue
        line = re.sub(r"^(?:[-*+]|\d+\.)\s+", "", line)  # list markers
        for part in _SENT_SPLIT.split(line):
            part = part.strip()
            lead = _LEADING_CITES.match(part)
            if lead and sentences:
                sentences[-1] += " " + lead.group(1).strip()
                part = part[lead.end():].strip()
            if part:
                sentences.append(part)

    claims = []
    for s in sentences:
        bare = _CITE.sub("", s)
        words = _WORD.findall(bare.lower())
        # Fragments like "**What it is**" or "Key takeaways:" are structure.
        if len(words) < 5:
            continue
        claims.append({"text": s, "cites": _cited_numbers(s)})
    return claims


def lexical_overlap(claim: str, excerpts: list[str]) -> float:
    """Share of the claim's content words that appear in its cited excerpts."""
    words = {w for w in _WORD.findall(_CITE.sub("", claim).lower()) if w not in STOP and len(w) > 2}
    if not words:
        return 1.0
    pool = set(_WORD.findall(" ".join(excerpts).lower()))
    return len(words & pool) / len(words)


# --------------------------------------------------------------------------
# 3. judging
# --------------------------------------------------------------------------


def _excerpts(sample: dict, cites: list[int]) -> list[str]:
    by_n = {s["n"]: s for s in sample["sources"]}
    return [f"[{n}] {by_n[n]['title']}\n{by_n[n]['text']}" for n in cites if n in by_n]


def build_claims(samples: list[dict]) -> list[dict]:
    claims = []
    for si, sample in enumerate(samples):
        valid = {s["n"] for s in sample["sources"]}
        for ci, c in enumerate(split_claims(sample.get("tutorial") or "")):
            excerpts = _excerpts(sample, c["cites"])
            claims.append(
                {
                    "id": f"{si:02d}-{ci:02d}",
                    "topic": sample["topic"],
                    "text": c["text"],
                    "cites": c["cites"],
                    "invalid_cites": [n for n in c["cites"] if n not in valid],
                    "overlap": round(lexical_overlap(c["text"], excerpts), 3) if excerpts else None,
                }
            )
    return claims


def judge(claims: list[dict], samples: list[dict]) -> list[dict]:
    """Label every claim that cites at least one real source."""
    from bountybrain.clients.llm import load_prompt, structured_many

    by_topic = {s["topic"]: s for s in samples}
    todo = [c for c in claims if set(c["cites"]) - set(c["invalid_cites"])]
    requests = [
        (
            "You are a strict fact-checker. You answer only with JSON.",
            load_prompt(
                "judge_claim",
                excerpts="\n\n".join(_excerpts(by_topic[c["topic"]], c["cites"])),
                claim=_CITE.sub("", c["text"]).strip(),
            ),
        )
        for c in todo
    ]
    replies = structured_many(Judgement, requests, max_tokens=200, concurrency=16)
    for c, r in zip(todo, replies, strict=True):
        c["verdict"] = r.verdict if r else None
        c["reason"] = r.reason if r else "judge reply unparseable"
    return claims


# --------------------------------------------------------------------------
# 4. metrics
# --------------------------------------------------------------------------


def summarise(claims: list[dict], samples: list[dict]) -> dict:
    n = len(claims)
    cited = [c for c in claims if c["cites"]]
    markers = sum(len(c["cites"]) for c in claims)
    invalid = sum(len(c["invalid_cites"]) for c in claims)
    judged = [c for c in claims if c.get("verdict")]
    verdicts = Counter(c["verdict"] for c in judged)
    low_overlap = [c for c in cited if c["overlap"] is not None and c["overlap"] < 0.2]

    per_topic = {}
    for s in samples:
        tc = [c for c in judged if c["topic"] == s["topic"]]
        per_topic[s["topic"]] = {
            "claims": sum(c["topic"] == s["topic"] for c in claims),
            "judged": len(tc),
            "supported": round(sum(c["verdict"] == "supported" for c in tc) / len(tc), 3) if tc else None,
        }

    def rate(x: int, d: int) -> float:
        return round(x / d, 4) if d else 0.0

    return {
        "topics": len(samples),
        "tutorials_generated": sum(bool(s.get("tutorial")) for s in samples),
        "sources_per_tutorial": TOP_K,
        "claims": n,
        "claims_per_tutorial": round(n / len(samples), 1) if samples else 0.0,
        "citation_rate": rate(len(cited), n),
        "citation_markers": markers,
        "invalid_citation_rate": rate(invalid, markers),
        "claims_with_invalid_citation": sum(bool(c["invalid_cites"]) for c in claims),
        "low_overlap_rate": rate(len(low_overlap), len(cited)),
        "judged": len(judged),
        "judge_failures": sum(c.get("verdict") is None for c in claims if set(c["cites"]) - set(c["invalid_cites"])),
        "supported_rate": rate(verdicts["supported"], len(judged)),
        "partial_rate": rate(verdicts["partial"], len(judged)),
        "unsupported_rate": rate(verdicts["unsupported"], len(judged)),
        # Of every sentence written, how many are backed by a cited source.
        "supported_of_all_claims": rate(verdicts["supported"], n),
        "per_topic": per_topic,
    }


# --------------------------------------------------------------------------
# hand check
# --------------------------------------------------------------------------


def export_handcheck(claims: list[dict], samples: list[dict], n: int = 40, seed: int = 7) -> Path:
    """A blind sample for hand labelling — the judge's verdicts are not shown.

    Stratified on the judge's label (up to half `supported`) so the
    disagreements that matter are not drowned out when the judge says
    `supported` most of the time; the shuffled output does not reveal which
    half a claim came from.
    """
    rng = random.Random(seed)
    judged = [c for c in claims if c.get("verdict")]
    pos = [c for c in judged if c["verdict"] == "supported"]
    neg = [c for c in judged if c["verdict"] != "supported"]
    # Up to half from each side; if one side is short, fill from the other.
    take_pos = min(len(pos), n // 2)
    take_neg = min(len(neg), n - take_pos)
    take_pos = min(len(pos), n - take_neg)
    pick = rng.sample(neg, take_neg) + rng.sample(pos, take_pos)
    rng.shuffle(pick)

    by_topic = {s["topic"]: s for s in samples}
    lines = ["# Faithfulness hand check (blind)", "",
             "Label each claim supported / partial / unsupported against the excerpts only.", ""]
    for c in pick:
        lines += [f"## {c['id']} — {c['topic']}", "", f"**Claim:** {c['text']}", ""]
        for ex in _excerpts(by_topic[c["topic"]], c["cites"]):
            lines += ["```", ex, "```", ""]
    out = settings.artifact_dir / HANDCHECK_BLIND
    out.write_text("\n".join(lines))
    return out


def agreement(claims: list[dict], labels_path: Path = HANDCHECK_LABELS) -> dict:
    """Judge vs hand labels: raw agreement, Cohen's kappa, and per-label precision."""
    labels = json.loads(labels_path.read_text())["labels"]
    by_id = {c["id"]: c for c in claims}
    # Labels are keyed by claim id *and* carry the claim text: regenerating the
    # tutorials reuses ids for different sentences, and a stale label must not
    # be silently compared against a new claim.
    live = {k: v for k, v in labels.items() if k in by_id and by_id[k]["text"] == v["text"]}
    pairs = [(by_id[k]["verdict"], v["label"]) for k, v in live.items()]

    def stats(pairs: list[tuple[str, str]]) -> dict:
        n = len(pairs)
        agree = sum(j == h for j, h in pairs)
        jc, hc = Counter(j for j, _ in pairs), Counter(h for _, h in pairs)
        pe = sum(jc[k] * hc[k] for k in set(jc) | set(hc)) / (n * n) if n else 0.0
        po = agree / n if n else 0.0
        return {
            "n": n,
            "agreement": round(po, 4),
            "cohen_kappa": round((po - pe) / (1 - pe), 4) if pe < 1 else 1.0,
        }

    three_way = stats(pairs)
    # Collapsed: is the sentence fully supported or not? This is the question
    # the headline supported_rate answers.
    binary = stats([(j == "supported" and "yes" or "no", h == "supported" and "yes" or "no") for j, h in pairs])
    confusion = Counter(f"judge={j} / hand={h}" for j, h in pairs)
    precision = {}
    for label in ("supported", "partial", "unsupported"):
        said = [(j, h) for j, h in pairs if j == label]
        precision[label] = {
            "judge_said": len(said),
            "hand_agreed": sum(h == label for _, h in said),
        }
    # The sample is stratified on the judge's label, so the hand labels alone
    # do not estimate the population. Reweight: for each judge label, the share
    # of that bucket a careful reader calls supported, times the bucket's size.
    judged = Counter(c["verdict"] for c in claims if c.get("verdict"))
    hand_supported = 0.0
    for label, n in judged.items():
        said = [h for j, h in pairs if j == label]
        if said:
            hand_supported += n * sum(h == "supported" for h in said) / len(said)
    return {
        "stale_labels": len(labels) - len(live),
        "hand_calibrated_supported_rate": round(hand_supported / sum(judged.values()), 4)
        if judged
        else 0.0,
        "three_way": three_way,
        "binary_supported": binary,
        "judge_precision": precision,
        "confusion": dict(sorted(confusion.items())),
        "note": "Sample is stratified on the judge's label (up to half supported), so raw "
        "agreement is not the population agreement; read per-label precision, and "
        "hand_calibrated_supported_rate for the population estimate.",
    }


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def _write_jsonl(name: str, rows: list[dict]) -> None:
    path = settings.artifact_dir / name
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def _read_jsonl(name: str) -> list[dict]:
    path = settings.artifact_dir / name
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def evaluate_and_save(regenerate: bool = True) -> dict:
    """Generate (or reuse), judge, and score. Writes three artefacts."""
    if regenerate or not (settings.artifact_dir / SAMPLES_FILE).exists():
        samples = generate()
        _write_jsonl(SAMPLES_FILE, samples)
    else:
        samples = _read_jsonl(SAMPLES_FILE)

    claims = judge(build_claims(samples), samples)
    _write_jsonl(JUDGED_FILE, claims)
    result = summarise(claims, samples)
    if HANDCHECK_LABELS.exists():
        result["judge_vs_hand"] = agreement(claims)
    else:
        path = export_handcheck(claims, samples)
        console.print(f"[yellow]No hand labels yet — blind sample written to {path}[/yellow]")

    out = settings.artifact_dir / "eval_faithfulness.json"
    out.write_text(json.dumps(result, indent=2))
    console.print(
        f"claims={result['claims']} cited={result['citation_rate']:.3f} "
        f"invalid={result['invalid_citation_rate']:.3f} "
        f"supported={result['supported_rate']:.3f} partial={result['partial_rate']:.3f} "
        f"unsupported={result['unsupported_rate']:.3f}"
    )
    console.print(f"[green]Wrote {out}[/green]")
    return result
