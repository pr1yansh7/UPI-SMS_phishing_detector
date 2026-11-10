"""
tests/test_features.py — Unit tests for all 38 features.

Run:
    python -m pytest tests/ -v
    python -m pytest tests/ -v --tb=short -q
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from bs4 import BeautifulSoup
from features.url_features import (
    url_length, dot_count, digit_ratio, special_char_count,
    subdomain_depth, has_ip_address, has_at_symbol, url_entropy,
    path_depth, has_double_slash_in_path, has_non_standard_port,
    sensitive_query_params, phish_keyword_count,
)
from features.domain_features import (
    suspicious_tld, brand_in_subdomain, brand_in_path,
    min_brand_edit_distance, has_homograph_chars, is_punycode_domain,
)
from features.ssl_features import has_https
from features.html_features import (
    form_count, password_field_count, hidden_field_count,
    external_resource_ratio, html_similarity_score,
    https_form_mismatch, favicon_external,
)
from features.osint_features import is_url_shortener, dns_ttl, google_safe_browsing

# ─── Fixtures ─────────────────────────────────────────────────────────────────

PHISH_URL        = "http://phonepe-upi-kyc-verify.xyz/login?token=abc123"
LEGIT_URL        = "https://www.phonepe.com/en/help.html"
IP_URL           = "http://192.168.1.100/phonepe/login"
AT_URL           = "http://real.com@evil.xyz/steal"
SUBDOMAIN_PHISH  = "http://phonepe.upi-kyc.evil.xyz/verify"
SHORTENER_URL    = "https://bit.ly/3phishme"
PUNYCODE_URL     = "http://xn--pytm-qra.com/login"
PORT_URL         = "http://evil.xyz:8080/login"
DBLSLASH_URL     = "http://evil.xyz//phonepe//login"
SENSITIVE_URL    = "http://evil.xyz/pay?otp=1234&pin=5678"
DEEP_PATH_URL    = "http://evil.xyz/phonepe/kyc/verify/otp/step2"
KW_URL           = "http://evil.xyz/verify-kyc-otp-pin-reward"

PHISH_HTML = """
<html><body>
  <img src="https://www.phonepe.com/assets/logo.png" alt="phonepe-logo"/>
  <link rel="icon" href="https://cdn.phonepe.com/favicon.ico"/>
  <h1>Enter UPI PIN</h1>
  <form action="http://evil.xyz/collect">
    <input type="text" name="upi_id"/>
    <input type="password" name="pin"/>
    <input type="hidden" name="session" value="abc"/>
    <input type="hidden" name="redirect" value="http://evil.xyz"/>
    <button type="submit">Verify</button>
  </form>
</body></html>
"""

LEGIT_HTML = """
<html><body>
  <link rel="icon" href="/favicon.ico"/>
  <nav><a href="/about">About</a></nav>
  <main><p>Welcome to PhonePe. Scan and pay securely.</p></main>
  <script src="/static/app.js"></script>
</body></html>
"""

MISMATCH_HTML = """
<html><body>
  <form action="http://evil.xyz/steal">
    <input type="password" name="pin"/>
  </form>
</body></html>
"""

PHISH_SOUP    = BeautifulSoup(PHISH_HTML, "html.parser")
LEGIT_SOUP    = BeautifulSoup(LEGIT_HTML, "html.parser")
MISMATCH_SOUP = BeautifulSoup(MISMATCH_HTML, "html.parser")


# ══════════════════════════════════════════════════════════════════════════════
# A. URL STRUCTURE (13 features)
# ══════════════════════════════════════════════════════════════════════════════

class TestURLStructure:

    def test_url_length_phishing(self):
        assert url_length(PHISH_URL) > 40

    def test_url_length_legit(self):
        assert url_length(LEGIT_URL) < 50

    def test_dot_count_phishing(self):
        assert dot_count(SUBDOMAIN_PHISH) >= 3

    def test_dot_count_legit(self):
        assert dot_count(LEGIT_URL) == 2

    def test_digit_ratio_high(self):
        assert digit_ratio("http://pay1234567890.upi.xyz/") > 0.1

    def test_digit_ratio_low(self):
        assert digit_ratio(LEGIT_URL) < 0.05

    def test_special_char_count(self):
        url = "http://evil.xyz/login?user=foo&pass=bar&redir=http%3A%2F%2Fevil.xyz"
        assert special_char_count(url) >= 4

    def test_subdomain_depth_phishing(self):
        assert subdomain_depth(SUBDOMAIN_PHISH) >= 2

    def test_subdomain_depth_legit(self):
        assert subdomain_depth(LEGIT_URL) == 1

    def test_subdomain_depth_no_sub(self):
        assert subdomain_depth("https://phonepe.com/") == 0

    def test_has_ip_address_true(self):
        assert has_ip_address(IP_URL) == 1

    def test_has_ip_address_false(self):
        assert has_ip_address(LEGIT_URL) == 0

    def test_has_at_symbol_true(self):
        assert has_at_symbol(AT_URL) == 1

    def test_has_at_symbol_false(self):
        assert has_at_symbol(LEGIT_URL) == 0

    def test_url_entropy_high(self):
        assert url_entropy("http://xk3j9pqmz.xyz/aB7dK2mN9pR") > 4.0

    def test_url_entropy_empty(self):
        assert url_entropy("") == 0.0

    # ── NEW: path_depth ──

    def test_path_depth_deep(self):
        assert path_depth(DEEP_PATH_URL) >= 4

    def test_path_depth_shallow(self):
        assert path_depth("https://phonepe.com/") == 0

    def test_path_depth_normal(self):
        assert path_depth(LEGIT_URL) == 2  # /en/help.html

    # ── NEW: has_double_slash_in_path ──

    def test_double_slash_positive(self):
        assert has_double_slash_in_path(DBLSLASH_URL) == 1

    def test_double_slash_negative(self):
        assert has_double_slash_in_path(LEGIT_URL) == 0

    # ── NEW: has_non_standard_port ──

    def test_non_standard_port_positive(self):
        assert has_non_standard_port(PORT_URL) == 1

    def test_non_standard_port_negative_443(self):
        assert has_non_standard_port("https://phonepe.com/") == 0

    def test_non_standard_port_negative_80(self):
        assert has_non_standard_port("http://phonepe.com/") == 0

    # ── NEW: sensitive_query_params ──

    def test_sensitive_params_positive(self):
        assert sensitive_query_params(SENSITIVE_URL) == 1
        assert sensitive_query_params("http://evil.xyz/?token=xyz") == 1
        assert sensitive_query_params("http://evil.xyz/?upi_id=abc") == 1

    def test_sensitive_params_negative(self):
        assert sensitive_query_params(LEGIT_URL) == 0
        assert sensitive_query_params("http://evil.xyz/?page=2") == 0

    # ── NEW: phish_keyword_count ──

    def test_phish_keyword_count_high(self):
        assert phish_keyword_count(KW_URL) >= 3

    def test_phish_keyword_count_zero(self):
        assert phish_keyword_count("https://example.com/about") == 0

    def test_phish_keyword_count_single(self):
        assert phish_keyword_count("http://evil.xyz/login") >= 1


# ══════════════════════════════════════════════════════════════════════════════
# B. DOMAIN (7 features)
# ══════════════════════════════════════════════════════════════════════════════

class TestDomain:

    def test_suspicious_tld_positive(self):
        for url in ["http://evil.xyz/","http://phish.tk/","http://fake.ml/","http://bad.click/"]:
            assert suspicious_tld(url) == 1, f"Expected suspicious for {url}"

    def test_suspicious_tld_negative(self):
        for url in ["https://phonepe.com/","https://paytm.com/"]:
            assert suspicious_tld(url) == 0, f"Expected safe for {url}"

    def test_brand_in_subdomain_positive(self):
        assert brand_in_subdomain("http://phonepe.evil.xyz/login") == 1
        assert brand_in_subdomain("http://paytm.upi.tk/verify") == 1

    def test_brand_in_subdomain_negative(self):
        assert brand_in_subdomain("https://www.phonepe.com/") == 0

    def test_brand_in_path_positive(self):
        assert brand_in_path("http://evil.xyz/phonepe/login") == 1

    def test_brand_in_path_negative(self):
        assert brand_in_path("http://evil.xyz/verify/user") == 0

    # ── NEW: brand_in_hostname ──

    def test_brand_in_hostname_positive_aadhaar(self):
        from features.domain_features import brand_in_hostname
        assert brand_in_hostname("http://uidai-update-kyc.xyz/verify") == 1
        assert brand_in_hostname("http://aadhaar-card-download.tk/login") == 1
        assert brand_in_hostname("http://maadhaar-biometric.xyz/update") == 1

    def test_brand_in_hostname_positive_upi(self):
        from features.domain_features import brand_in_hostname
        assert brand_in_hostname("http://phonepe-kyc.xyz/login") == 1
        assert brand_in_hostname("http://paytm-secure.online/otp") == 1

    def test_brand_in_hostname_legit_also_returns_1(self):
        from features.domain_features import brand_in_hostname
        # Legitimate domains also return 1 — ML model separates them via
        # has_https, trusted_ca, cert_age, suspicious_tld etc.
        assert brand_in_hostname("https://www.phonepe.com/") == 1
        assert brand_in_hostname("https://uidai.gov.in/") == 1

    def test_brand_in_hostname_unrelated_domain(self):
        from features.domain_features import brand_in_hostname
        assert brand_in_hostname("http://evil-scam.xyz/login") == 0
        assert brand_in_hostname("http://update-verify.online/kyc") == 0

    def test_edit_distance_typosquat(self):
        # 'phonpe.com' is distance 1 from 'phonepe.com'
        d = min_brand_edit_distance("http://phonpe.com/")
        assert d <= 3

    def test_edit_distance_legit(self):
        # Exact match — distance 0
        d = min_brand_edit_distance("https://phonepe.com/")
        assert d == 0

    def test_edit_distance_unrelated(self):
        d = min_brand_edit_distance("https://google.com/")
        assert d > 3

    def test_edit_distance_returns_int(self):
        result = min_brand_edit_distance("http://evil.xyz/")
        assert isinstance(result, int)

    # ── NEW: has_homograph_chars ──

    def test_homograph_positive(self):
        # Simulate non-ASCII in host
        assert has_homograph_chars("http://рaypal.com/") == 1  # Cyrillic р

    def test_homograph_negative(self):
        assert has_homograph_chars("https://phonepe.com/") == 0
        assert has_homograph_chars("http://evil-phish.xyz/login") == 0

    # ── NEW: is_punycode_domain ──

    def test_punycode_positive(self):
        assert is_punycode_domain(PUNYCODE_URL) == 1
        assert is_punycode_domain("http://xn--80ak6aa92e.com/") == 1

    def test_punycode_negative(self):
        assert is_punycode_domain("https://phonepe.com/") == 0
        assert is_punycode_domain("http://evil.xyz/login") == 0


# ══════════════════════════════════════════════════════════════════════════════
# C. SSL (1 testable without network)
# ══════════════════════════════════════════════════════════════════════════════

class TestSSL:

    def test_has_https_true(self):
        assert has_https(LEGIT_URL) == 1

    def test_has_https_false(self):
        assert has_https(PHISH_URL) == 0
        assert has_https(IP_URL) == 0

    def test_has_https_ftp(self):
        assert has_https("ftp://evil.xyz/file") == 0


# ══════════════════════════════════════════════════════════════════════════════
# D. HTML CONTENT (7 features)
# ══════════════════════════════════════════════════════════════════════════════

class TestHTMLFeatures:

    def test_form_count_phishing(self):
        assert form_count(PHISH_SOUP) == 1

    def test_form_count_legit(self):
        assert form_count(LEGIT_SOUP) == 0

    def test_form_count_none(self):
        assert form_count(None) == 0

    def test_password_field_phishing(self):
        assert password_field_count(PHISH_SOUP) == 1

    def test_password_field_legit(self):
        assert password_field_count(LEGIT_SOUP) == 0

    def test_hidden_field_phishing(self):
        assert hidden_field_count(PHISH_SOUP) == 2

    def test_hidden_field_legit(self):
        assert hidden_field_count(LEGIT_SOUP) == 0

    def test_external_resource_ratio_legit(self):
        ratio = external_resource_ratio(LEGIT_SOUP, "https://www.phonepe.com/")
        assert ratio == 0.0

    def test_external_resource_ratio_phishing(self):
        ratio = external_resource_ratio(PHISH_SOUP, "http://evil.xyz/")
        assert ratio > 0.0

    def test_html_similarity_phishing(self):
        score = html_similarity_score(PHISH_SOUP)
        assert score > 0.0

    def test_html_similarity_none(self):
        assert html_similarity_score(None) == 0.0

    # ── NEW: https_form_mismatch ──

    def test_https_form_mismatch_positive(self):
        # HTTPS page with form posting to HTTP
        result = https_form_mismatch(MISMATCH_SOUP, "https://evil.xyz/login")
        assert result == 1

    def test_https_form_mismatch_no_http_page(self):
        # HTTP page — mismatch feature not applicable
        result = https_form_mismatch(MISMATCH_SOUP, "http://evil.xyz/login")
        assert result == 0

    def test_https_form_mismatch_legit(self):
        # Legit page has no form at all
        result = https_form_mismatch(LEGIT_SOUP, "https://www.phonepe.com/")
        assert result == 0

    def test_https_form_mismatch_none_soup(self):
        assert https_form_mismatch(None, "https://evil.xyz/") == 0

    # ── NEW: favicon_external ──

    def test_favicon_external_phishing(self):
        # Phishing page hotlinks PhonePe's favicon from cdn.phonepe.com
        result = favicon_external(PHISH_SOUP, "http://evil.xyz/")
        assert result == 1

    def test_favicon_external_legit(self):
        # Legit page uses local /favicon.ico
        result = favicon_external(LEGIT_SOUP, "https://www.phonepe.com/")
        assert result == 0

    def test_favicon_external_none_soup(self):
        assert favicon_external(None, "http://evil.xyz/") == 0


# ══════════════════════════════════════════════════════════════════════════════
# F. OSINT / INTEL (3 features)
# ══════════════════════════════════════════════════════════════════════════════

class TestOSINT:

    # ── is_url_shortener ──

    def test_shortener_positive(self):
        assert is_url_shortener("https://bit.ly/3xPhish") == 1
        assert is_url_shortener("https://tinyurl.com/abc123") == 1
        assert is_url_shortener("https://t.co/xyz") == 1
        assert is_url_shortener("https://ow.ly/pqr") == 1

    def test_shortener_negative(self):
        assert is_url_shortener("https://www.phonepe.com/") == 0
        assert is_url_shortener("http://evil-phish.xyz/login") == 0

    def test_shortener_subdomain_not_flagged(self):
        assert is_url_shortener("https://notbit.ly.evil.com/") == 0

    # ── dns_ttl ──

    def test_dns_ttl_returns_int_or_minus_one(self):
        result = dns_ttl("https://www.google.com/")
        assert isinstance(result, int)
        assert result == -1 or result > 0

    def test_dns_ttl_nonexistent(self):
        result = dns_ttl("http://thisdoesnotexist1234567890abc.xyz/")
        assert result == -1

    def test_dns_ttl_invalid_url(self):
        assert dns_ttl("not-a-url") == -1

    # ── google_safe_browsing ──

    def test_gsb_no_key(self):
        result = google_safe_browsing("http://evil.xyz/")
        assert result == -1  # no key configured

    def test_gsb_valid_return(self):
        result = google_safe_browsing("https://www.phonepe.com/")
        assert result in (-1, 0, 1)


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION — full extract_features()
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:

    def test_all_feature_columns_present(self):
        from feature_extractor import extract_features
        from config import FEATURE_COLUMNS
        feats = extract_features(PHISH_URL, fetch_html_content=False)
        for col in FEATURE_COLUMNS:
            assert col in feats, f"Missing feature column: {col}"

    def test_feature_count(self):
        from config import FEATURE_COLUMNS
        assert len(FEATURE_COLUMNS) == 39, f"Expected 39, got {len(FEATURE_COLUMNS)}"

    def test_phishing_url_signals(self):
        from feature_extractor import extract_features
        feats = extract_features(
            "http://phonepe.upi-kyc.xyz/login?otp=1",
            fetch_html_content=False,
        )
        assert feats["suspicious_tld"]         == 1
        assert feats["brand_in_subdomain"]     == 1
        assert feats["has_https"]              == 0
        assert feats["sensitive_query_params"] == 1

    def test_aadhaar_phishing_signals(self):
        from feature_extractor import extract_features
        feats = extract_features(
            "http://uidai-update-kyc.xyz/verify",
            fetch_html_content=False,
        )
        assert feats["suspicious_tld"]      == 1
        assert feats["brand_in_hostname"]   == 1
        assert feats["has_https"]           == 0
        assert feats["phish_keyword_count"] >= 2

    def test_aadhaar_legit_signals(self):
        from feature_extractor import extract_features
        feats = extract_features("https://uidai.gov.in/", fetch_html_content=False)
        assert feats["suspicious_tld"]  == 0
        assert feats["has_https"]       == 1
        assert feats["has_ip_address"]  == 0

    def test_legit_url_signals(self):
        from feature_extractor import extract_features
        feats = extract_features("https://www.phonepe.com/", fetch_html_content=False)
        assert feats["has_https"]       == 1
        assert feats["suspicious_tld"]  == 0
        assert feats["has_ip_address"]  == 0

    def test_shortener_url_signals(self):
        from feature_extractor import extract_features
        feats = extract_features("https://bit.ly/xyz123", fetch_html_content=False)
        assert feats["is_url_shortener"] == 1

    def test_punycode_url_signals(self):
        from feature_extractor import extract_features
        feats = extract_features(PUNYCODE_URL, fetch_html_content=False)
        assert feats["is_punycode_domain"] == 1

    def test_port_url_signals(self):
        from feature_extractor import extract_features
        feats = extract_features(PORT_URL, fetch_html_content=False)
        assert feats["has_non_standard_port"] == 1

    def test_deep_path_signals(self):
        from feature_extractor import extract_features
        feats = extract_features(DEEP_PATH_URL, fetch_html_content=False)
        assert feats["path_depth"] >= 4

    def test_keyword_url_signals(self):
        from feature_extractor import extract_features
        feats = extract_features(KW_URL, fetch_html_content=False)
        assert feats["phish_keyword_count"] >= 3


# ══════════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_empty_url(self):
        assert url_length("") == 0
        assert url_entropy("") == 0.0
        assert digit_ratio("") == 0.0

    def test_very_long_url(self):
        url = "http://evil.xyz/" + "a" * 500
        assert url_length(url) > 500

    def test_url_no_path(self):
        assert path_depth("http://evil.xyz") == 0

    def test_double_slash_http_prefix_not_counted(self):
        # The // in http:// is in the scheme, not path
        assert has_double_slash_in_path("http://evil.xyz/normal") == 0

    def test_non_standard_port_8443(self):
        assert has_non_standard_port("https://evil.xyz:8443/") == 1

    def test_homograph_empty(self):
        assert has_homograph_chars("") == 0

    def test_punycode_false_positive_guard(self):
        # 'xn--' appearing only in path, not hostname — should not flag
        assert is_punycode_domain("http://evil.xyz/xn--test") == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
