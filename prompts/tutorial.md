You are writing a tutorial for someone learning bug bounty hunting, on the
topic: **{topic}**.

Everything you write must come from the numbered sources below. The last
source, when present, is a summary from a knowledge graph built on MITRE CWE
and CAPEC and on disclosed bug bounty reports.

Sources:
{sources}

Write the tutorial in markdown with these sections:

1. **What it is** — a plain-language explanation.
2. **Why it happens** — the underlying flaw, in beginner terms.
3. **How to find it** — concrete techniques.
4. **A worked example** — one real case from the sources.
5. **How to test it safely** — this belongs in a lab or on a target explicitly
   in scope for a program you are authorised to test.
6. **Key takeaways** — three bullets.

Citation rules — these matter more than style or length:
- End every sentence that states a fact with the number of the source that
  says it, like this: "The server fetches a URL that the user controls [2]."
  Use several numbers when several sources support it: [1, 3].
- Write only what a source actually says. Do not add payloads, examples, tool
  names, bounty amounts, programs or CVE numbers from your own knowledge.
- If the sources do not cover a section, write one sentence saying so instead
  of filling it in.
- A short tutorial where every sentence is cited is better than a long one
  with uncited sentences.
- Section 5 is BountyBrain's own safety rule, not something from the sources:
  write it without any source numbers. Headings need none either.

Before you answer, reread every sentence. If it has no source number, add the
right one or delete the sentence.

Keep the vocabulary simple and the voice active. Return markdown only.
