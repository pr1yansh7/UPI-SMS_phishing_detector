"""
allowlist.py — official-domain safety net.

Edit THIS file if genuine UPI/Aadhaar sites are being flagged (or a lookalike
slips through the allowlist). The domain list itself lives in config.py
(OFFICIAL_DOMAINS).

A URL counts as official only if it is HTTPS and its hostname is EXACTLY an
official domain or a real subdomain of one. These all fail on purpose:
    https://uidai.gov.in.evil.xyz/     (official name used as a subdomain of evil.xyz)
    https://evil-uidai.gov.in/         (different registered domain)
    https://uidai.gov.in@evil.xyz/     (user-info trick — real host is evil.xyz)
    http://uidai.gov.in/               (not HTTPS — left to the model)
"""

from urllib.parse import urlparse

from config import OFFICIAL_DOMAINS


def is_official_domain(url: str) -> bool:
    if not url:
        return False
    parsed = urlparse(url if "://" in url else "https://" + url)
    if parsed.scheme.lower() != "https":
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in OFFICIAL_DOMAINS)


def apply_allowlist(result: dict) -> dict:
    """
    Post-process a /predict result: if the URL is an official HTTPS domain and the
    model said PHISHING, flip it to LEGITIMATE (keeping the raw model score in
    `model_probability` and marking `override`). Never makes anything MORE suspicious.
    """
    official = is_official_domain(result.get("url", ""))
    result["official_domain"] = official
    if official and result.get("is_phishing"):
        result["model_probability"] = result["probability"]
        result["probability"] = min(result["probability"], 0.05)
        result["is_phishing"] = False
        result["label"] = "LEGITIMATE"
        result["confidence"] = round(1 - result["probability"], 4)
        result["override"] = "official_domain_allowlist"
    return result
