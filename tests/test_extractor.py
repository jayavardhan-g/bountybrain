from bountybrain.ingestion.extractor import extract


def test_rule_based_ssrf():
    body = (
        "The API endpoint fetched user-supplied URLs. Sending "
        "http://169.254.169.254/latest/meta-data/ returned AWS metadata. "
        "This is an SSRF vulnerability. Tools used: burp."
    )
    r = extract("SSRF in preview", "seed://ssrf-t1", body, use_llm=False)
    assert r.vuln_type == "SSRF"
    assert "burp" in r.tools_used
    assert "aws" in r.target_tech


def test_rule_based_cve_extraction():
    body = "This is related to CVE-2021-44228 (Log4Shell). RCE possible."
    r = extract("Log4Shell reproduction", "seed://rce-t1", body, use_llm=False)
    assert r.vuln_type == "RCE"
    assert "CVE-2021-44228" in r.cve_ids
