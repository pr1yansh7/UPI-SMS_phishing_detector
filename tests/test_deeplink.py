"""tests/test_deeplink.py — features/deeplink_features.py ONLY (UPI upi:// links)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from features.deeplink_features import analyse_upi_deeplink, contains_term, extract_upi_links, parse_upi_link

SCAM = "upi://pay?pa=phonepe.refund@ybl&pn=PhonePe%20Refund%20Dept&am=15000&tn=Refund%20claim"
LEGIT = "upi://pay?pa=merchant@okaxis&pn=Sharma%20Store&am=250&cu=INR&tn=Groceries"


class TestParse:
    def test_parses_action_and_params(self):
        p = parse_upi_link("upi://pay?pa=a@ybl&pn=John+Doe&am=5")
        assert p["action"] == "pay" and p["params"]["pn"] == "John Doe" and p["params"]["am"] == "5"

    def test_case_insensitive_scheme_and_keys(self):
        p = parse_upi_link("UPI://PAY?PA=a@ybl&AM=1")
        assert p["action"] == "pay" and p["params"]["pa"] == "a@ybl"

    def test_first_duplicate_wins(self):
        assert parse_upi_link("upi://pay?pa=a@ybl&pa=b@ybl")["params"]["pa"] == "a@ybl"

    def test_non_upi_returns_none(self):
        assert parse_upi_link("http://evil.xyz/pay") is None
        assert parse_upi_link("") is None and parse_upi_link(None) is None


class TestExtract:
    def test_extracts_and_strips_trailing_punctuation(self):
        assert extract_upi_links("pay upi://pay?pa=a@ybl&am=1, thanks") == ["upi://pay?pa=a@ybl&am=1"]

    def test_none_found(self):
        assert extract_upi_links("no link here") == [] and extract_upi_links(None) == []


class TestContainsTerm:
    def test_whole_token(self):
        assert contains_term("care.support", "care") and contains_term("phonepe.refund", "refund")

    def test_does_not_match_inside_words(self):
        assert not contains_term("healthcare.store", "care") and not contains_term("Daycare Centre", "care")

    def test_long_words_match_as_prefix(self):
        assert contains_term("refunds", "refund")

    def test_phrases_match_as_substring(self):
        assert contains_term("Customer Care Desk", "customer care")


class TestScoring:
    def test_scam_link_is_high_risk(self):
        r = analyse_upi_deeplink(SCAM)
        assert r["risk_level"] == "high" and r["is_suspicious_link"] and r["is_phishing"]
        assert any("scam-bait" in f for f in r["flags"])

    def test_normal_merchant_link_is_low_risk(self):
        r = analyse_upi_deeplink(LEGIT)
        assert r["risk_level"] == "low" and not r["is_suspicious_link"]
        assert r["payee_vpa"] == "merchant@okaxis" and r["amount"] == "250"

    def test_not_a_upi_link(self):
        r = analyse_upi_deeplink("http://evil.xyz")
        assert r["valid_upi_link"] == 0 and r["flags"] == ["Not a upi:// link"]

    def test_missing_or_malformed_payee_flagged(self):
        assert any("No payee" in f for f in analyse_upi_deeplink("upi://pay?am=100")["flags"])
        assert any("malformed" in f for f in analyse_upi_deeplink("upi://pay?pa=abc&am=100")["flags"])

    def test_mandate_and_unusual_action(self):
        assert any("auto-debit" in f for f in analyse_upi_deeplink("upi://mandate?pa=s@ybl&am=1")["flags"])
        assert any("Unusual UPI action" in f for f in analyse_upi_deeplink("upi://collect?pa=s@ybl")["flags"])

    def test_non_inr_currency_and_bad_amount(self):
        assert any("USD" in f for f in analyse_upi_deeplink("upi://pay?pa=s@ybl&cu=USD")["flags"])
        assert any("not a valid number" in f for f in analyse_upi_deeplink("upi://pay?pa=s@ybl&am=5,000")["flags"])

    def test_unknown_handle_is_only_a_soft_signal(self):
        r = analyse_upi_deeplink("upi://pay?pa=shop@weirdbank&am=10")
        assert any("Unrecognised UPI handle" in f for f in r["flags"]) and not r["is_suspicious_link"]

    def test_legit_merchant_names_with_care_not_flagged(self):
        r = analyse_upi_deeplink("upi://pay?pa=healthcare.store@oksbi&pn=Daycare%20Centre&am=3500")
        assert not any("scam-bait" in f or "imitates" in f for f in r["flags"])

    def test_score_bounds_and_advice(self):
        for uri in (SCAM, LEGIT, "upi://", "upi://pay"):
            r = analyse_upi_deeplink(uri)
            assert 0.0 <= r["risk_score"] <= 1.0 and "PIN" in r["advice"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
