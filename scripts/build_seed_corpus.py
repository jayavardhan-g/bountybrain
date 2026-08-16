"""Generate a synthetic seed corpus of bug bounty style reports.

These are intentionally SYNTHETIC — they teach the shape of real disclosures
without claiming to be them. Marked with `seed://` URLs so nobody mistakes
them for actual public disclosures.

Run: `python scripts/build_seed_corpus.py`
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "bountybrain" / "seed" / "reports.json"

TEMPLATES = [
    # (vuln, template, tools, targets)
    (
        "SSRF",
        "The API endpoint `/api/preview?url=` fetched user-supplied URLs "
        "server-side without validation. Sending `http://169.254.169.254/latest/meta-data/` "
        "revealed AWS instance credentials.\n\n"
        "**Payload used:**\n```\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\n```\n\n"
        "**Fix:** blocklist internal IP ranges and require a URL scheme allowlist.\n\n"
        "Impact: exfiltration of AWS metadata.",
        ["burp", "curl"],
        ["nginx", "aws"],
    ),
    (
        "IDOR",
        "The endpoint `GET /api/v2/orders/{id}` returned any order when a numeric "
        "ID was substituted. Incrementing the ID leaked other customers' PII.\n\n"
        "**Payload:**\n```\nGET /api/v2/orders/12345 HTTP/1.1\nAuthorization: Bearer <victim>\n```\n\n"
        "**Fix:** enforce owner check before serialization.",
        ["burp"],
        ["rails"],
    ),
    (
        "XSS",
        "A reflected XSS in the search page rendered the `q` parameter into a "
        "`<script>` block. Encoding was applied to HTML entities but not JS strings.\n\n"
        "**Payload:**\n```\n?q=\"; alert(1);//\n```\n\n"
        "**Fix:** use JSON.stringify server-side before templating into JS.",
        ["burp"],
        ["express"],
    ),
    (
        "RCE",
        "A markdown preview feature invoked `pandoc` with user-controlled args. "
        "Injecting `--lua-filter=/tmp/payload.lua` executed arbitrary Lua code.\n\n"
        "**Payload:** filename `--lua-filter=/tmp/x.lua`\n\n"
        "**Fix:** pass user args via `--` separator, whitelist filter path.",
        ["burp", "curl"],
        ["flask"],
    ),
    (
        "SQLi",
        "The reporting endpoint concatenated the `sort_by` parameter directly into "
        "an SQL ORDER BY clause. Time-based blind extraction worked with sleep.\n\n"
        "**Payload:**\n```\n?sort_by=1,(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END)\n```\n\n"
        "**Fix:** use an ORDER BY column allowlist.",
        ["sqlmap", "burp"],
        ["django", "postgresql"],
    ),
    (
        "CSRF",
        "The email-change endpoint accepted GET requests and used only session "
        "cookies for auth. An attacker could host `<img src>` to change victim email.\n\n"
        "**Fix:** require POST + SameSite=Lax cookies + CSRF token.",
        ["burp"],
        ["wordpress"],
    ),
    (
        "SSTI",
        "The templating engine `Jinja2` was used with `render_template_string` on "
        "the `name` query parameter. `{{7*7}}` returned `49`.\n\n"
        "**Payload:**\n```\n{{ config.items() }}\n```\n\n"
        "**Fix:** render fixed templates only; pass variables via context.",
        ["burp"],
        ["flask"],
    ),
    (
        "XXE",
        "The document upload parser used a default XML parser with external entity "
        "expansion enabled. A crafted DOCX manifest read `/etc/passwd`.\n\n"
        "**Fix:** disable external entity resolution in the XML parser.",
        ["burp"],
        ["spring"],
    ),
    (
        "Auth Bypass",
        "The password-reset flow returned the reset token in the JSON response. Any "
        "authenticated user could request another account's reset and log in as them.\n\n"
        "**Fix:** never return tokens in the response; only email them.",
        [],
        ["jira"],
    ),
    (
        "Path Traversal",
        "The file-download endpoint accepted a `path` parameter used with `open()`. "
        "`../../../../etc/passwd` returned the file.\n\n"
        "**Fix:** resolve to absolute path and confirm it lives under an allowed root.",
        ["ffuf"],
        ["nginx", "flask"],
    ),
    (
        "Open Redirect",
        "The `return_to` parameter after login was not validated. It was used to "
        "chain a phishing attack against SSO users.\n\n"
        "**Fix:** allowlist redirect targets.",
        [],
        ["github"],
    ),
    (
        "GraphQL",
        "GraphQL introspection was enabled in production. The `__schema` query "
        "revealed an internal `adminUsers` field exposed without a role check.\n\n"
        "**Fix:** disable introspection in prod; enforce field-level auth.",
        ["burp", "graphql-voyager"],
        ["express"],
    ),
    (
        "Prototype Pollution",
        "A merge helper walked user-controlled JSON keys with `Object.assign` on the "
        "prototype chain. Adding `__proto__.admin = true` promoted the request.\n\n"
        "**Fix:** use `Object.create(null)` and reject `__proto__` keys.",
        ["burp"],
        ["express"],
    ),
    (
        "Race Condition",
        "The coupon-redemption endpoint checked usage count then debited in two "
        "queries. Firing 40 requests in parallel let a single-use coupon apply many times.\n\n"
        "**Fix:** database-level `UPDATE ... RETURNING` with a WHERE guard.",
        ["burp"],
        ["rails"],
    ),
    (
        "Business Logic",
        "The cart accepted a negative `quantity`, producing a credit on checkout.\n\n"
        "**Fix:** validate `quantity >= 1` on the server, not just in the UI.",
        [],
        ["wordpress"],
    ),
]

PROGRAMS = [
    "Acme",
    "Acme Cloud",
    "Widgetco",
    "PetalPay",
    "GreenMail",
    "OrbitDocs",
    "NimbusCI",
    "PaperTrail",
    "LumenBank",
    "SkyRepo",
]

SEVERITY_BY_VULN = {
    "SSRF": "high",
    "IDOR": "high",
    "XSS": "medium",
    "RCE": "critical",
    "SQLi": "critical",
    "CSRF": "medium",
    "SSTI": "high",
    "XXE": "high",
    "Auth Bypass": "critical",
    "Path Traversal": "high",
    "Open Redirect": "low",
    "GraphQL": "medium",
    "Prototype Pollution": "high",
    "Race Condition": "medium",
    "Business Logic": "medium",
}


def build(target_count: int = 500) -> list[dict]:
    """Generate up to `target_count` synthetic reports by cycling templates
    × programs × date/severity variants."""
    reports = []
    idx = 0
    variants = ["found", "reproduced", "chained", "escalated", "bypassed"]
    while len(reports) < target_count:
        for vuln, body, tools, targets in TEMPLATES:
            for prog in PROGRAMS:
                for variant in variants:
                    idx += 1
                    year = 2022 + (idx % 4)
                    month = (idx % 12) + 1
                    day = (idx % 27) + 1
                    date = f"{year:04d}-{month:02d}-{day:02d}"
                    bounty = 250 * (idx % 12) + 500
                    severity = SEVERITY_BY_VULN[vuln]
                    title = (
                        f"{vuln} {variant} in {prog} — {body.splitlines()[0][:60]}"
                    )
                    reports.append(
                        {
                            "url": f"seed://{vuln.lower().replace(' ', '-')}-{idx:04d}",
                            "title": title,
                            "date": date,
                            "program": prog,
                            "bounty": bounty,
                            "severity": severity,
                            "raw_markdown": (
                                f"# {title}\n\n"
                                f"**Program:** {prog}  \n"
                                f"**Severity:** {severity}  \n"
                                f"**Bounty:** ${bounty}  \n\n"
                                f"{body}\n\n"
                                f"**Tools mentioned:** "
                                f"{', '.join(tools) if tools else 'n/a'}\n"
                            ),
                        }
                    )
                    if len(reports) >= target_count:
                        break
                if len(reports) >= target_count:
                    break
            if len(reports) >= target_count:
                break
    # a few bypass chains so the Bypass Chains page shows something at scale
    for r in reports:
        if r["url"].endswith("idor-0002") or r["url"].endswith("idor-0007"):
            r["raw_markdown"] += (
                "\n\nThis bypasses the earlier fix in "
                "seed://idor-0001.\n"
            )
        if r["url"].endswith("ssrf-0005"):
            r["raw_markdown"] += (
                "\n\nThis bypasses the earlier fix in "
                "seed://ssrf-0001.\n"
            )
    return reports


def main() -> None:
    import sys

    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = build(target_count=n)
    OUT.write_text(json.dumps(payload, indent=2))
    print(f"wrote {len(payload)} reports to {OUT}")


if __name__ == "__main__":
    main()
