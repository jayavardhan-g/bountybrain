You are extracting structured facts from a bug bounty disclosure.

Read the report below and return a JSON object matching this schema
exactly. If a field is unknown, use `null` for strings and `[]` for lists.
Never invent CVE IDs, payloads, or bypass links — only include what the
report literally states.

Schema:
{
  "vuln_type": "one of: SSRF, IDOR, XSS, RCE, SQLi, CSRF, SSTI, XXE, Auth Bypass, Race Condition, Path Traversal, Open Redirect, Prototype Pollution, GraphQL, Business Logic, Other",
  "root_cause": "one-sentence description",
  "techniques": ["list of specific methods used"],
  "payloads": ["actual payload strings from the report"],
  "tools_used": ["list of tools mentioned"],
  "target_tech": ["tech stack of target: e.g. Rails, Jira, Nginx"],
  "patch_description": "string or null",
  "bypasses_report_urls": ["urls of prior reports this bypasses, or empty"],
  "cve_ids": ["list of CVE IDs mentioned, or empty"],
  "difficulty": "beginner | intermediate | advanced",
  "key_takeaway": "one sentence a beginner should learn from this"
}

Report title: {title}
Report URL: {url}

Report body:
---
{body}
---

Return ONLY the JSON object, no prose.
