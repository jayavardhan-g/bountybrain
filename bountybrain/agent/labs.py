"""Curated map of practice labs by topic.

Small JSON-shaped dict for MVP. Expand as we ingest more topics.
"""
from __future__ import annotations

LABS: dict[str, list[dict]] = {
    "ssrf": [
        {
            "name": "PortSwigger Web Security Academy — SSRF",
            "url": "https://portswigger.net/web-security/ssrf",
            "provider": "PortSwigger",
        },
        {
            "name": "PentesterLab — SSRF badge",
            "url": "https://pentesterlab.com/badges/ssrf",
            "provider": "PentesterLab",
        },
    ],
    "idor": [
        {
            "name": "PortSwigger — Access control vulnerabilities",
            "url": "https://portswigger.net/web-security/access-control",
            "provider": "PortSwigger",
        },
        {
            "name": "TryHackMe — IDOR room",
            "url": "https://tryhackme.com/room/idor",
            "provider": "TryHackMe",
        },
    ],
    "xss": [
        {
            "name": "PortSwigger — XSS labs",
            "url": "https://portswigger.net/web-security/cross-site-scripting",
            "provider": "PortSwigger",
        },
    ],
    "sqli": [
        {
            "name": "PortSwigger — SQL injection labs",
            "url": "https://portswigger.net/web-security/sql-injection",
            "provider": "PortSwigger",
        },
        {
            "name": "HackTheBox — SQL Injection tracks",
            "url": "https://academy.hackthebox.com/module/details/33",
            "provider": "HackTheBox",
        },
    ],
    "rce": [
        {
            "name": "PortSwigger — OS command injection",
            "url": "https://portswigger.net/web-security/os-command-injection",
            "provider": "PortSwigger",
        },
    ],
    "graphql": [
        {
            "name": "PortSwigger — GraphQL API vulnerabilities",
            "url": "https://portswigger.net/web-security/graphql",
            "provider": "PortSwigger",
        },
    ],
    "ssti": [
        {
            "name": "PortSwigger — Server-side template injection",
            "url": "https://portswigger.net/web-security/server-side-template-injection",
            "provider": "PortSwigger",
        },
    ],
}


def find_practice_labs(topic: str) -> list[dict]:
    key = topic.lower().strip()
    for k, v in LABS.items():
        if k in key or key in k:
            return v
    return []
