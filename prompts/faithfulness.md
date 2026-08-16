You are a strict evaluator. Given a generated tutorial and its source
excerpts, judge whether every factual claim in the tutorial is supported
by at least one of the sources.

Return JSON:
{
  "supported_claims": <int>,
  "total_claims": <int>,
  "unsupported": ["list the unsupported claims verbatim"]
}

Tutorial:
---
{tutorial}
---

Sources:
---
{sources}
---
