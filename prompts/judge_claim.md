You are checking whether a sentence from a security tutorial is supported by
the source excerpts it cites. You are a strict fact-checker, not a security
expert: judge only against the excerpts below, never against your own
knowledge. A claim that is true in the real world but absent from the excerpts
is **not** supported.

Verdicts:
- `supported` — every factual part of the sentence is stated in, or follows
  directly from, the cited excerpts.
- `partial` — the core of the sentence is in the excerpts, but it adds a
  specific detail (a payload, a number, a product, a step, a consequence) that
  the excerpts do not contain.
- `unsupported` — the excerpts do not state the sentence's main claim, or
  contradict it.

Rephrasing and simplification are fine; a beginner-friendly paraphrase of an
excerpt is still `supported`.

Cited excerpts:
---
{excerpts}
---

Sentence to check:
---
{claim}
---

Return JSON matching this schema:
{
  "verdict": "supported" | "partial" | "unsupported",
  "reason": "<one short sentence naming what is or is not in the excerpts>"
}

Return ONLY the JSON object.
