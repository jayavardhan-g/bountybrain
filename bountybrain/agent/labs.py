"""Where to go and practise a weakness class, hands-on.

Keyed by **CWE id** rather than by topic string. Keying on strings meant
"IDOR" and "Insecure Direct Object Reference" and "CWE-639" were three
different lookups and only the first one hit; resolving the topic through the
graph first means every alias the corpus knows about lands on the same entry.

When a class has no labs of its own the lookup walks *up* the CWE hierarchy —
there is no lab for "CWE-1336 SSTI on Jinja specifically", but its parent
injection class has one, and that is still the right place to start.

Curated by hand and deliberately small: every entry is a free or
widely-used training resource that actually covers the class. This is the one
place in the project that points outside the local corpus, and it points at
learning material only — never at a target.
"""
from __future__ import annotations

PORTSWIGGER = "PortSwigger Web Security Academy"
PENTESTERLAB = "PentesterLab"
TRYHACKME = "TryHackMe"
HACKTHEBOX = "HackTheBox Academy"


def _lab(name: str, url: str, provider: str) -> dict:
    return {"name": name, "url": url, "provider": provider}


LABS_BY_CWE: dict[int, list[dict]] = {
    79: [
        _lab("Cross-site scripting", "https://portswigger.net/web-security/cross-site-scripting", PORTSWIGGER),
        _lab("XSS room", "https://tryhackme.com/room/xss", TRYHACKME),
    ],
    89: [
        _lab("SQL injection", "https://portswigger.net/web-security/sql-injection", PORTSWIGGER),
        _lab("SQL injection module", "https://academy.hackthebox.com/module/details/33", HACKTHEBOX),
    ],
    918: [
        _lab("Server-side request forgery", "https://portswigger.net/web-security/ssrf", PORTSWIGGER),
        _lab("SSRF badge", "https://pentesterlab.com/badges/ssrf", PENTESTERLAB),
    ],
    639: [
        _lab("Access control vulnerabilities", "https://portswigger.net/web-security/access-control", PORTSWIGGER),
        _lab("IDOR room", "https://tryhackme.com/room/idor", TRYHACKME),
    ],
    284: [
        _lab("Access control vulnerabilities", "https://portswigger.net/web-security/access-control", PORTSWIGGER),
    ],
    285: [
        _lab("Access control vulnerabilities", "https://portswigger.net/web-security/access-control", PORTSWIGGER),
    ],
    287: [
        _lab("Authentication vulnerabilities", "https://portswigger.net/web-security/authentication", PORTSWIGGER),
        _lab("OAuth authentication", "https://portswigger.net/web-security/oauth", PORTSWIGGER),
    ],
    1336: [
        _lab("Server-side template injection", "https://portswigger.net/web-security/server-side-template-injection", PORTSWIGGER),
    ],
    94: [
        _lab("OS command injection", "https://portswigger.net/web-security/os-command-injection", PORTSWIGGER),
    ],
    77: [
        _lab("OS command injection", "https://portswigger.net/web-security/os-command-injection", PORTSWIGGER),
    ],
    78: [
        _lab("OS command injection", "https://portswigger.net/web-security/os-command-injection", PORTSWIGGER),
        _lab("Command injection room", "https://tryhackme.com/room/oscommandinjection", TRYHACKME),
    ],
    22: [
        _lab("Path traversal", "https://portswigger.net/web-security/file-path-traversal", PORTSWIGGER),
    ],
    98: [
        _lab("File inclusion", "https://portswigger.net/web-security/file-path-traversal", PORTSWIGGER),
        _lab("File inclusion room", "https://tryhackme.com/room/fileinc", TRYHACKME),
    ],
    611: [
        _lab("XML external entity injection", "https://portswigger.net/web-security/xxe", PORTSWIGGER),
        _lab("XXE badge", "https://pentesterlab.com/badges/xxe", PENTESTERLAB),
    ],
    502: [
        _lab("Insecure deserialization", "https://portswigger.net/web-security/deserialization", PORTSWIGGER),
    ],
    352: [
        _lab("Cross-site request forgery", "https://portswigger.net/web-security/csrf", PORTSWIGGER),
    ],
    601: [
        _lab("DOM-based open redirection", "https://portswigger.net/web-security/dom-based/open-redirection", PORTSWIGGER),
    ],
    444: [
        _lab("HTTP request smuggling", "https://portswigger.net/web-security/request-smuggling", PORTSWIGGER),
    ],
    524: [
        _lab("Web cache poisoning", "https://portswigger.net/web-security/web-cache-poisoning", PORTSWIGGER),
        _lab("Web cache deception", "https://portswigger.net/web-security/web-cache-deception", PORTSWIGGER),
    ],
    942: [
        _lab("Cross-origin resource sharing", "https://portswigger.net/web-security/cors", PORTSWIGGER),
    ],
    1321: [
        _lab("Prototype pollution", "https://portswigger.net/web-security/prototype-pollution", PORTSWIGGER),
    ],
    362: [
        _lab("Race conditions", "https://portswigger.net/web-security/race-conditions", PORTSWIGGER),
    ],
    347: [
        _lab("JWT attacks", "https://portswigger.net/web-security/jwt", PORTSWIGGER),
        _lab("JWT badge", "https://pentesterlab.com/badges/jwt", PENTESTERLAB),
    ],
    269: [
        _lab("Privilege escalation", "https://tryhackme.com/room/linprivesc", TRYHACKME),
    ],
    200: [
        _lab("Information disclosure", "https://portswigger.net/web-security/information-disclosure", PORTSWIGGER),
    ],
    434: [
        _lab("File upload vulnerabilities", "https://portswigger.net/web-security/file-upload", PORTSWIGGER),
    ],
    915: [
        _lab("Mass assignment / API testing", "https://portswigger.net/web-security/api-testing", PORTSWIGGER),
    ],
    841: [
        _lab("Business logic vulnerabilities", "https://portswigger.net/web-security/logic-flaws", PORTSWIGGER),
    ],
    693: [
        _lab("Bypassing defences (XSS contexts)", "https://portswigger.net/web-security/cross-site-scripting/contexts", PORTSWIGGER),
    ],
}

# Fallback only, for when the graph is not built yet — keeps the tool honest
# in a fresh clone instead of returning nothing with no explanation.
_KEYWORD_FALLBACK: dict[str, int] = {
    "xss": 79, "sqli": 89, "sql injection": 89, "ssrf": 918, "idor": 639,
    "ssti": 1336, "rce": 94, "xxe": 611, "csrf": 352, "jwt": 347,
    "path traversal": 22, "lfi": 98, "deserialization": 502,
    "open redirect": 601, "request smuggling": 444, "race condition": 362,
    "prototype pollution": 1321, "file upload": 434, "cors": 942,
}


def _labs_for_cwe(cwe_id: int) -> list[dict]:
    return LABS_BY_CWE.get(cwe_id, [])


def find_practice_labs(topic: str | int) -> list[dict]:
    """Practice labs for a topic, resolved through the CWE graph.

    Falls back to the parent class when a specific weakness has no lab of its
    own, and to a small keyword table when the graph is unavailable.
    """
    from bountybrain.kg import queries

    weakness = None
    try:
        weakness = queries.find_weakness(topic)
    except Exception:  # noqa: BLE001 - graph not built yet; fall through
        weakness = None

    if weakness:
        direct = _labs_for_cwe(weakness["cwe_id"])
        if direct:
            return direct
        # No lab for this exact class — walk up to the parent, which is where
        # the generic training material lives.
        try:
            hierarchy = queries.weakness_hierarchy(weakness["cwe_id"])
        except Exception:  # noqa: BLE001
            hierarchy = {}
        for parent in hierarchy.get("parents", []):
            inherited = _labs_for_cwe(parent["cwe_id"])
            if inherited:
                return inherited
        return []

    key = str(topic).lower().strip()
    for term, cwe_id in _KEYWORD_FALLBACK.items():
        if term in key:
            return _labs_for_cwe(cwe_id)
    return []
