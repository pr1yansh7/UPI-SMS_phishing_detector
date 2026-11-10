"""
tests/test_sms_features.py — Unit tests for features/sms_features.py ONLY.

If a test here fails, the bug is in sms_features.py — check:
  - sms_urgency_score()
  - has_url_in_sms()
  - sender_id_spoofed()
  - sms_phish_keyword_count()
  - sms_impersonates_brand()
  - sms_asks_for_otp()
  - sms_threatens_account()
  - sms_hinglish_phish_score()
  - analyse_sms()

Run:
    python -m pytest tests/test_sms_features.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from features.sms_features import (
    sms_urgency_score,
    has_url_in_sms,
    sender_id_spoofed,
    sms_phish_keyword_count,
    sms_impersonates_brand,
    sms_asks_for_otp,
    sms_threatens_account,
    sms_hinglish_phish_score,
    analyse_sms,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

PHISH_SMS_EN = (
    "URGENT: Your Aadhaar will be suspended immediately. "
    "Verify now at http://uidai-kyc.xyz to avoid account blocked."
)
PHISH_SMS_OTP = (
    "Your UPI OTP is 847291. Share OTP with our executive to "
    "complete KYC verification. Do not delay."
)
PHISH_SMS_THREAT = (
    "Dear PhonePe user, your account will be closed within 24 hours. "
    "Click here to reactivate: http://phonepe-secure.online/kyc"
)
PHISH_SMS_HINDI = "आपका खाता बंद हो जाएगा। तुरंत सत्यापन करें।"
PHISH_SMS_TAMIL = "உங்கள் கணக்கு தடுக்கப்பட்டது. இப்போதே சரிபார்க்க."

LEGIT_SMS_OTP  = "Your PhonePe OTP is 482910. Valid for 10 minutes. Do NOT share with anyone."
LEGIT_SMS_BANK = "INR 500 credited to your account via UPI. Ref: 12345678. -HDFC Bank"
LEGIT_SMS_UIDAI = "Your Aadhaar update request has been received. Ref: UA2024001. -UIDAI"

FAKE_SENDER = "VK-UIDAI"
REAL_SENDER = "HDFCBK"
UNKNOWN_SENDER = "987654321"


# ══════════════════════════════════════════════════════════════════════════════
# sms_urgency_score()
# ══════════════════════════════════════════════════════════════════════════════

class TestSMSUrgencyScore:

    def test_high_urgency_phishing(self):
        score = sms_urgency_score(PHISH_SMS_EN)
        assert score > 0.1, f"Expected urgency > 0.1, got {score}"

    def test_low_urgency_legit(self):
        score = sms_urgency_score(LEGIT_SMS_OTP)
        assert score < 0.2, f"Expected urgency < 0.2 for legit OTP, got {score}"

    def test_empty_text(self):
        assert sms_urgency_score("") == 0.0

    def test_returns_float(self):
        result = sms_urgency_score(PHISH_SMS_EN)
        assert isinstance(result, float)
        assert 0.0 <= result <= 1.0

    def test_urgency_words_detected(self):
        text = "Your account will be blocked immediately. urgent action required."
        score = sms_urgency_score(text)
        assert score > 0.0


# ══════════════════════════════════════════════════════════════════════════════
# has_url_in_sms()
# ══════════════════════════════════════════════════════════════════════════════

class TestHasURLInSMS:

    def test_http_url_detected(self):
        assert has_url_in_sms("Click http://evil.xyz to verify") == 1

    def test_https_url_detected(self):
        assert has_url_in_sms("Visit https://uidai-kyc.xyz now") == 1

    def test_bitly_detected(self):
        assert has_url_in_sms("Click bit.ly/aadhaar-update") == 1

    def test_www_url_detected(self):
        assert has_url_in_sms("Visit www.evil-upi.com immediately") == 1

    def test_no_url_legit_otp(self):
        assert has_url_in_sms(LEGIT_SMS_OTP) == 0

    def test_no_url_bank_sms(self):
        assert has_url_in_sms(LEGIT_SMS_BANK) == 0

    def test_empty_text(self):
        assert has_url_in_sms("") == 0


# ══════════════════════════════════════════════════════════════════════════════
# sender_id_spoofed()
# ══════════════════════════════════════════════════════════════════════════════

class TestSenderIDSpoofed:

    def test_uidai_spoof(self):
        assert sender_id_spoofed("VK-UIDAI") == 1

    def test_npci_spoof(self):
        assert sender_id_spoofed("BW-NPCI-FAKE") == 1

    def test_paytm_spoof(self):
        assert sender_id_spoofed("AD-PAYTM") == 1

    def test_phonepe_spoof(self):
        assert sender_id_spoofed("TX-PHONEPE") == 1

    def test_numeric_sender_not_spoofed(self):
        assert sender_id_spoofed("9876543210") == 0

    def test_unknown_sender_not_spoofed(self):
        assert sender_id_spoofed("AMAZON1") == 0

    def test_empty_sender(self):
        assert sender_id_spoofed("") == 0


# ══════════════════════════════════════════════════════════════════════════════
# sms_phish_keyword_count()
# ══════════════════════════════════════════════════════════════════════════════

class TestSMSPhishKeywordCount:

    def test_multiple_keywords_phishing(self):
        count = sms_phish_keyword_count(PHISH_SMS_EN)
        assert count >= 2

    def test_zero_keywords_legit(self):
        count = sms_phish_keyword_count(LEGIT_SMS_BANK)
        assert count == 0

    def test_otp_sharing_sms(self):
        count = sms_phish_keyword_count(PHISH_SMS_OTP)
        assert count >= 1

    def test_empty_text(self):
        assert sms_phish_keyword_count("") == 0

    def test_returns_int(self):
        assert isinstance(sms_phish_keyword_count(PHISH_SMS_EN), int)


# ══════════════════════════════════════════════════════════════════════════════
# sms_impersonates_brand()
# ══════════════════════════════════════════════════════════════════════════════

class TestSMSImpersonatesBrand:

    def test_aadhaar_brand(self):
        assert sms_impersonates_brand("Your Aadhaar update is pending") == 1

    def test_phonepe_brand(self):
        assert sms_impersonates_brand("Dear PhonePe user click here") == 1

    def test_uidai_brand(self):
        assert sms_impersonates_brand("UIDAI alert: verify now") == 1

    def test_no_brand(self):
        assert sms_impersonates_brand("Your transaction is complete") == 0

    def test_empty_text(self):
        assert sms_impersonates_brand("") == 0


# ══════════════════════════════════════════════════════════════════════════════
# sms_asks_for_otp()
# ══════════════════════════════════════════════════════════════════════════════

class TestSMSAsksForOTP:

    def test_share_otp(self):
        assert sms_asks_for_otp("Please share your OTP with our agent") == 1

    def test_send_otp(self):
        assert sms_asks_for_otp("Send the OTP to complete verification") == 1

    def test_give_otp(self):
        assert sms_asks_for_otp("Give OTP to the executive") == 1

    def test_enter_otp_on_link(self):
        assert sms_asks_for_otp("Enter OTP on this link http://evil.xyz") == 1

    def test_legitimate_otp_sms(self):
        # Legit OTP SMSes CONTAIN an OTP but don't ASK you to share it
        assert sms_asks_for_otp(LEGIT_SMS_OTP) == 0

    def test_no_otp_mention(self):
        assert sms_asks_for_otp("Your transaction is approved") == 0

    def test_empty_text(self):
        assert sms_asks_for_otp("") == 0


# ══════════════════════════════════════════════════════════════════════════════
# sms_threatens_account()
# ══════════════════════════════════════════════════════════════════════════════

class TestSMSThreatsAccount:

    def test_account_blocked_threat(self):
        assert sms_threatens_account("Your account will be blocked") == 1

    def test_upi_suspended(self):
        assert sms_threatens_account("Your UPI will be suspended") == 1

    def test_aadhaar_deactivated(self):
        assert sms_threatens_account("Your Aadhaar will be deactivated") == 1

    def test_service_blocked(self):
        assert sms_threatens_account("Service will be blocked") == 1

    def test_legit_no_threat(self):
        assert sms_threatens_account(LEGIT_SMS_BANK) == 0

    def test_empty_text(self):
        assert sms_threatens_account("") == 0


# ══════════════════════════════════════════════════════════════════════════════
# sms_hinglish_phish_score()
# ══════════════════════════════════════════════════════════════════════════════

class TestSMSHinglishScore:

    def test_hindi_phishing_detected(self):
        score = sms_hinglish_phish_score(PHISH_SMS_HINDI)
        assert score > 0.0, f"Expected Hindi phishing score > 0, got {score}"

    def test_tamil_phishing_detected(self):
        score = sms_hinglish_phish_score(PHISH_SMS_TAMIL)
        assert score > 0.0, f"Expected Tamil phishing score > 0, got {score}"

    def test_english_only_returns_low(self):
        score = sms_hinglish_phish_score("Your transaction is complete")
        assert score == 0.0

    def test_empty_text(self):
        assert sms_hinglish_phish_score("") == 0.0

    def test_returns_float_in_range(self):
        score = sms_hinglish_phish_score(PHISH_SMS_HINDI)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


# ══════════════════════════════════════════════════════════════════════════════
# analyse_sms() — master function
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalyseSMS:

    def test_returns_all_required_keys(self):
        result = analyse_sms(PHISH_SMS_EN, FAKE_SENDER)
        required = {
            "sms_urgency_score", "has_url_in_sms", "sender_id_spoofed",
            "sms_phish_keyword_count", "sms_impersonates_brand",
            "sms_asks_for_otp", "sms_threatens_account",
            "sms_hinglish_phish_score", "sms_risk_score", "is_phishing_sms",
        }
        assert required.issubset(result.keys())

    def test_phishing_sms_flagged(self):
        result = analyse_sms(PHISH_SMS_EN, FAKE_SENDER)
        assert result["is_phishing_sms"] is True
        assert result["sms_risk_score"] >= 0.40

    def test_otp_sharing_sms_flagged(self):
        result = analyse_sms(PHISH_SMS_OTP)
        assert result["is_phishing_sms"] is True

    def test_threat_sms_flagged(self):
        result = analyse_sms(PHISH_SMS_THREAT)
        assert result["is_phishing_sms"] is True

    def test_hindi_phishing_flagged(self):
        result = analyse_sms(PHISH_SMS_HINDI)
        assert result["sms_hinglish_phish_score"] > 0.0

    def test_legit_otp_not_flagged(self):
        result = analyse_sms(LEGIT_SMS_OTP)
        assert result["is_phishing_sms"] is False

    def test_legit_bank_not_flagged(self):
        result = analyse_sms(LEGIT_SMS_BANK)
        assert result["is_phishing_sms"] is False

    def test_risk_score_in_range(self):
        result = analyse_sms(PHISH_SMS_EN)
        assert 0.0 <= result["sms_risk_score"] <= 1.0

    def test_empty_sms(self):
        result = analyse_sms("", "")
        assert result["sms_risk_score"] == 0.0
        assert result["is_phishing_sms"] is False

    def test_with_sender_spoofed(self):
        result = analyse_sms("Normal text message", "VK-UIDAI")
        assert result["sender_id_spoofed"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
