"""
tests/test_predictor.py — Unit tests for predictor.py ONLY.

Scope: this file tests prediction logic, feature-flagging thresholds, and
CLI output formatting. It does NOT test feature_extractor.py internals
(see test_features.py) or collector.py (see test_collector.py).

If a test in THIS file fails, the bug is in predictor.py — check:
  - is_feature_suspicious()
  - format_feature_value()
  - SUSPICIOUS_HIGH / SUSPICIOUS_LOW / FEATURE_WARN_THRESHOLDS

Run:
    python -m pytest tests/test_predictor.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from thresholds import (
    is_feature_suspicious,
    format_feature_value,
    SUSPICIOUS_HIGH,
    SUSPICIOUS_LOW,
    FEATURE_WARN_THRESHOLDS,
)
from config import FEATURE_COLUMNS, PHISH_PROBABILITY_THRESHOLD


# ══════════════════════════════════════════════════════════════════════════════
# is_feature_suspicious() — binary flags (1 = suspicious)
# ══════════════════════════════════════════════════════════════════════════════

class TestBinaryHighFlags:
    """Features where value == 1 means suspicious."""

    @pytest.mark.parametrize("name", [
        "has_ip_address", "has_at_symbol", "suspicious_tld",
        "brand_in_subdomain", "brand_in_path", "is_self_signed",
        "hosting_country_suspicious", "is_url_shortener",
        "google_safe_browsing", "has_homograph_chars",
        "is_punycode_domain", "has_double_slash_in_path",
        "has_non_standard_port", "sensitive_query_params",
        "https_form_mismatch", "favicon_external", "asn_is_suspicious",
    ])
    def test_flag_one_is_suspicious(self, name):
        assert is_feature_suspicious(name, 1) is True

    @pytest.mark.parametrize("name", [
        "has_ip_address", "has_at_symbol", "suspicious_tld",
        "brand_in_subdomain", "brand_in_path", "is_self_signed",
    ])
    def test_flag_zero_is_not_suspicious(self, name):
        assert is_feature_suspicious(name, 0) is False


class TestBinaryLowFlags:
    """Features where value == 0 means suspicious."""

    def test_has_https_zero_is_suspicious(self):
        assert is_feature_suspicious("has_https", 0) is True

    def test_has_https_one_is_not_suspicious(self):
        assert is_feature_suspicious("has_https", 1) is False

    def test_trusted_ca_zero_is_suspicious(self):
        assert is_feature_suspicious("trusted_ca", 0) is True

    def test_trusted_ca_one_is_not_suspicious(self):
        assert is_feature_suspicious("trusted_ca", 1) is False

    def test_has_mx_record_zero_is_suspicious(self):
        assert is_feature_suspicious("has_mx_record", 0) is True

    def test_has_mx_record_one_is_not_suspicious(self):
        assert is_feature_suspicious("has_mx_record", 1) is False


# ══════════════════════════════════════════════════════════════════════════════
# is_feature_suspicious() — numeric thresholds
# ══════════════════════════════════════════════════════════════════════════════

class TestNumericThresholds:

    def test_url_length_above_threshold(self):
        threshold = FEATURE_WARN_THRESHOLDS["url_length"]
        assert is_feature_suspicious("url_length", threshold + 1) is True

    def test_url_length_below_threshold(self):
        threshold = FEATURE_WARN_THRESHOLDS["url_length"]
        assert is_feature_suspicious("url_length", threshold - 1) is False

    def test_domain_age_below_threshold_is_suspicious(self):
        # domain_age_days is a LOW-bad feature: < 30 days = suspicious
        threshold = FEATURE_WARN_THRESHOLDS["domain_age_days"]
        assert is_feature_suspicious("domain_age_days", threshold - 1) is True

    def test_domain_age_above_threshold_is_safe(self):
        threshold = FEATURE_WARN_THRESHOLDS["domain_age_days"]
        assert is_feature_suspicious("domain_age_days", threshold + 100) is False

    def test_domain_age_negative_one_not_suspicious(self):
        # -1 means "unknown" (WHOIS not configured) — should not be flagged
        assert is_feature_suspicious("domain_age_days", -1) is False

    def test_dns_ttl_low_is_suspicious(self):
        threshold = FEATURE_WARN_THRESHOLDS["dns_ttl"]
        assert is_feature_suspicious("dns_ttl", threshold - 1) is True

    def test_dns_ttl_high_is_safe(self):
        threshold = FEATURE_WARN_THRESHOLDS["dns_ttl"]
        assert is_feature_suspicious("dns_ttl", threshold + 1000) is False

    def test_dns_ttl_negative_one_not_suspicious(self):
        assert is_feature_suspicious("dns_ttl", -1) is False

    def test_min_brand_edit_distance_low_is_suspicious(self):
        # distance <= 3 means typosquatting
        assert is_feature_suspicious("min_brand_edit_distance", 1) is True
        assert is_feature_suspicious("min_brand_edit_distance", 0) is True

    def test_min_brand_edit_distance_high_is_safe(self):
        assert is_feature_suspicious("min_brand_edit_distance", 15) is False

    def test_phish_keyword_count_threshold(self):
        threshold = FEATURE_WARN_THRESHOLDS["phish_keyword_count"]
        assert is_feature_suspicious("phish_keyword_count", threshold) is True
        assert is_feature_suspicious("phish_keyword_count", threshold - 1) is False

    def test_unknown_feature_name_returns_false(self):
        # Defensive: unrecognised feature name should never crash, just return False
        assert is_feature_suspicious("totally_made_up_feature", 999) is False


# ══════════════════════════════════════════════════════════════════════════════
# format_feature_value()
# ══════════════════════════════════════════════════════════════════════════════

class TestFormatFeatureValue:

    def test_float_formatting(self):
        result = format_feature_value("digit_ratio", 0.123456)
        assert result == "0.1235"  # rounded to 4 decimal places

    def test_int_formatting(self):
        result = format_feature_value("url_length", 42)
        assert result == "42"

    def test_negative_one_formatting(self):
        # -1 is the "unknown / not configured" sentinel — should still format cleanly
        result = format_feature_value("domain_age_days", -1)
        assert result == "-1"

    def test_zero_formatting(self):
        result = format_feature_value("has_https", 0)
        assert result == "0"


# ══════════════════════════════════════════════════════════════════════════════
# Config sanity — thresholds reference real feature names
# ══════════════════════════════════════════════════════════════════════════════

class TestThresholdConfigSanity:
    """
    Catches a common bug class: someone renames a feature in feature_extractor.py
    or config.py but forgets to update the threshold dict in predictor.py.
    """

    def test_all_threshold_keys_are_real_features(self):
        for key in FEATURE_WARN_THRESHOLDS:
            assert key in FEATURE_COLUMNS, (
                f"'{key}' in FEATURE_WARN_THRESHOLDS is not a real feature "
                f"in config.FEATURE_COLUMNS — likely a typo or stale entry"
            )

    def test_all_suspicious_high_keys_are_real_features(self):
        for key in SUSPICIOUS_HIGH:
            assert key in FEATURE_COLUMNS, (
                f"'{key}' in SUSPICIOUS_HIGH is not a real feature column"
            )

    def test_all_suspicious_low_keys_are_real_features(self):
        for key in SUSPICIOUS_LOW:
            assert key in FEATURE_COLUMNS, (
                f"'{key}' in SUSPICIOUS_LOW is not a real feature column"
            )

    def test_no_feature_in_both_high_and_low(self):
        overlap = SUSPICIOUS_HIGH & SUSPICIOUS_LOW
        assert not overlap, (
            f"Features cannot be in both SUSPICIOUS_HIGH and SUSPICIOUS_LOW: {overlap}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Threshold value sanity
# ══════════════════════════════════════════════════════════════════════════════

class TestThresholdValueSanity:

    def test_phish_probability_threshold_is_valid_probability(self):
        assert 0.0 < PHISH_PROBABILITY_THRESHOLD < 1.0

    def test_url_length_threshold_is_positive(self):
        assert FEATURE_WARN_THRESHOLDS["url_length"] > 0

    def test_domain_age_threshold_is_positive(self):
        assert FEATURE_WARN_THRESHOLDS["domain_age_days"] > 0

    def test_dns_ttl_threshold_is_positive(self):
        assert FEATURE_WARN_THRESHOLDS["dns_ttl"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
