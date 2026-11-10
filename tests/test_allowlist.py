"""tests/test_allowlist.py — allowlist.py ONLY (official-domain safety net)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from allowlist import apply_allowlist, is_official_domain


@pytest.mark.parametrize("url", [
    "https://uidai.gov.in/", "https://resident.uidai.gov.in/x", "https://www.phonepe.com/",
    "https://pay.google.com/about", "https://PHONEPE.com./", "phonepe.com", "https://paytm.com:8443/",
])
def test_official(url):
    assert is_official_domain(url)


@pytest.mark.parametrize("url", [
    "http://uidai.gov.in/",                 # not HTTPS — leave to the model
    "https://uidai.gov.in.evil.xyz/",       # official name as a subdomain of evil.xyz
    "https://evil-uidai.gov.in/",           # different registered domain
    "https://uidai.gov.in@evil.xyz/",       # user-info trick, real host is evil.xyz
    "https://google.com/", "https://sites.google.com/x", "https://example.gov.in/", "", None,
])
def test_not_official(url):
    assert not is_official_domain(url)


def _result(url, phishing, prob):
    return {"url": url, "is_phishing": phishing, "probability": prob,
            "label": "PHISHING" if phishing else "LEGITIMATE", "confidence": prob}


def test_flips_false_positive_on_official_domain_and_keeps_model_score():
    r = apply_allowlist(_result("https://uidai.gov.in/", True, 0.93))
    assert r["is_phishing"] is False and r["label"] == "LEGITIMATE"
    assert r["probability"] <= 0.05 and r["model_probability"] == 0.93
    assert r["official_domain"] is True and r["override"] == "official_domain_allowlist"


def test_never_makes_anything_more_suspicious():
    r = apply_allowlist(_result("https://uidai.gov.in/", False, 0.02))
    assert r["is_phishing"] is False and "override" not in r and r["official_domain"] is True


def test_non_official_untouched():
    r = apply_allowlist(_result("http://uidai-update-kyc.xyz/", True, 0.97))
    assert r["is_phishing"] is True and r["probability"] == 0.97 and r["official_domain"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
