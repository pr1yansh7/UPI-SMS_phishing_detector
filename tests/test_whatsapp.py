"""tests/test_whatsapp.py — features/whatsapp_features.py ONLY."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from features.whatsapp_features import analyse_whatsapp, extract_urls, link_risk

SCAMS = {
    "kbc": "Congratulations! You have won Rs 25 lakh in KBC lucky draw. Forward this to 10 contacts and claim at http://kbc-prize.xyz",
    "apk": "RTO challan pending. Download app http://rto-echallan.top/challan.apk and pay fine today",
    "job": "Work from home! Earn ₹5000 daily. Join telegram t.me/jobs123 now",
    "otp": "Share your OTP to verify KYC",
    "threat": "Your Aadhaar will be blocked. Update now",
    "upi_inside": "Pay your fee here upi://pay?pa=uidai.support@ybl&pn=UIDAI&am=20000&tn=kyc",
}
SAFE = {
    "location": "Hi! Dinner at 8? Location https://maps.google.com/?q=cafe",
    "birthday": "Happy birthday! Forward this to your friends",
    "official": "Check the official site https://uidai.gov.in/ for details.",
    "empty": "",
}


@pytest.mark.parametrize("name", SCAMS)
def test_scams_flagged(name):
    r = analyse_whatsapp(SCAMS[name])
    assert r["is_phishing"] and r["flags"], (name, r["risk_score"])


@pytest.mark.parametrize("name", SAFE)
def test_safe_messages_not_flagged(name):
    assert not analyse_whatsapp(SAFE[name])["is_phishing"]


def test_warning_tier_for_ambiguous_utility_threat():
    """Real utilities do send overdue notices, so a lone disconnection threat is a warning, not a scam verdict."""
    r = analyse_whatsapp("Your electricity bill is unpaid, power will be disconnected tonight. Call now")
    assert not r["is_phishing"] and r["risk_score"] >= 0.2 and r["flags"]


def test_expected_reasons():
    assert any(".apk" in f for f in analyse_whatsapp(SCAMS["apk"])["flags"])
    assert any("prize" in f for f in analyse_whatsapp(SCAMS["kbc"])["flags"])
    assert any("OTP" in f for f in analyse_whatsapp(SCAMS["otp"])["flags"])
    assert any(f.startswith("UPI link:") for f in analyse_whatsapp(SCAMS["upi_inside"])["flags"])


def test_embedded_links_are_extracted():
    r = analyse_whatsapp(SCAMS["upi_inside"])
    assert r["upi_links_found"] and "uidai.support@ybl" in r["upi_links_found"][0]
    assert analyse_whatsapp(SCAMS["apk"])["urls_found"] == ["http://rto-echallan.top/challan.apk"]


def test_extract_urls_strips_punctuation_and_adds_scheme():
    assert extract_urls("see (https://bit.ly/abc).") == ["https://bit.ly/abc"]
    assert extract_urls("go to www.evil-phonepe.top/login now") == ["https://www.evil-phonepe.top/login"]
    assert extract_urls("meet.co/x is not a shortener link") == []


class TestLinkRisk:
    def test_official_link_has_zero_risk(self):
        assert link_risk("https://uidai.gov.in/") == (0.0, [])

    def test_shortener_tld_brand_http_apk_all_add_risk(self):
        assert link_risk("https://bit.ly/x")[0] == 0.40
        assert link_risk("https://random.xyz/x")[0] == 0.40
        assert link_risk("http://phonepe-kyc.xyz/a.apk")[0] == 1.0

    def test_plain_https_site_is_zero(self):
        assert link_risk("https://maps.google.com/?q=x")[0] == 0.0


def test_result_shape_and_bounds():
    r = analyse_whatsapp(SCAMS["kbc"])
    for k in ("risk_score", "whatsapp_risk_score", "is_phishing", "flags", "advice", "urls_found", "upi_links_found"):
        assert k in r
    assert 0.0 <= r["risk_score"] <= 1.0 and r["risk_score"] == r["whatsapp_risk_score"]


def test_none_input_does_not_crash():
    assert analyse_whatsapp(None)["risk_score"] == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
