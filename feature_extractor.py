"""
feature_extractor.py — Assembles all 38 features from the features/ package.

THIS FILE IS AN ASSEMBLER ONLY — it contains no feature logic.
All feature logic lives in separate files under features/:

  features/url_features.py      → 13 URL structure features (A)
  features/domain_features.py   → 7  domain intelligence features (B)
  features/ssl_features.py      → 4  SSL/TLS cert features (C)
  features/html_features.py     → 7  HTML content features (D)
  features/network_features.py  → 4  network infrastructure features (E)
  features/osint_features.py    → 3  OSINT/threat intel features (F)

Edit THIS file ONLY if:
  - A feature column is missing from the output dict
  - extract_features() or extract_features_batch() behaviour is wrong
  - You want to add a new feature group (add the import here + in features/__init__.py)

For a bug in a specific feature value, open the matching features/*.py file —
each function has a docstring explaining exactly when and why it can be wrong.
"""

import logging
import time
from typing import Optional

import requests
from bs4 import BeautifulSoup

from config import FEATURE_COLUMNS, REQUEST_TIMEOUT, USER_AGENT

# ── Import every feature function from its dedicated module ───────────────────
from features.url_features import (
    url_length, dot_count, digit_ratio, special_char_count,
    subdomain_depth, has_ip_address, has_at_symbol, url_entropy,
    path_depth, has_double_slash_in_path, has_non_standard_port,
    sensitive_query_params, phish_keyword_count,
)
from features.domain_features import (
    suspicious_tld, brand_in_subdomain, brand_in_path, brand_in_hostname,
    get_domain_age_days, min_brand_edit_distance,
    has_homograph_chars, is_punycode_domain,
)
from features.ssl_features import (
    has_https, cert_age_days, is_self_signed, trusted_ca,
)
from features.html_features import (
    form_count, password_field_count, hidden_field_count,
    external_resource_ratio, html_similarity_score,
    https_form_mismatch, favicon_external,
)
from features.network_features import (
    redirect_count, hosting_country_suspicious,
    asn_is_suspicious, has_mx_record,
)
from features.osint_features import (
    is_url_shortener, dns_ttl, google_safe_browsing,
)

log = logging.getLogger(__name__)


def _fetch_html(url: str) -> tuple[Optional[BeautifulSoup], Optional[object]]:
    """
    Fetch the URL and return (BeautifulSoup, Response) or (None, None).
    This single fetch is shared across all HTML feature functions so the
    server is only hit once per URL regardless of how many HTML features exist.
    SSL verification is intentionally disabled (verify=False) because phishing
    pages often have broken certificates — we still want their HTML content.
    """
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            verify=False,
        )
        return BeautifulSoup(resp.text, "html.parser"), resp
    except Exception as e:
        log.debug(f"HTML fetch failed for {url}: {e}")
        return None, None


_HTML_FEATURES = {
    "form_count", "password_field_count", "hidden_field_count", "external_resource_ratio",
    "html_similarity_score", "https_form_mismatch", "favicon_external",
}


def _registry(url: str, soup) -> dict:
    """feature name -> zero-arg callable. Nothing runs until it is called, so asking for a
    subset (only=...) never triggers the network calls of features you did not request."""
    return {
        # A. URL structure — pure string functions.   Bug → features/url_features.py
        "url_length": lambda: url_length(url),
        "dot_count": lambda: dot_count(url),
        "digit_ratio": lambda: digit_ratio(url),
        "special_char_count": lambda: special_char_count(url),
        "subdomain_depth": lambda: subdomain_depth(url),
        "has_ip_address": lambda: has_ip_address(url),
        "has_at_symbol": lambda: has_at_symbol(url),
        "url_entropy": lambda: url_entropy(url),
        "path_depth": lambda: path_depth(url),
        "has_double_slash_in_path": lambda: has_double_slash_in_path(url),
        "has_non_standard_port": lambda: has_non_standard_port(url),
        "sensitive_query_params": lambda: sensitive_query_params(url),
        "phish_keyword_count": lambda: phish_keyword_count(url),
        # B. Domain.   Bug → features/domain_features.py
        "domain_age_days": lambda: get_domain_age_days(url),          # WHOIS API
        "suspicious_tld": lambda: suspicious_tld(url),
        "brand_in_subdomain": lambda: brand_in_subdomain(url),
        "brand_in_path": lambda: brand_in_path(url),
        "brand_in_hostname": lambda: brand_in_hostname(url),
        "min_brand_edit_distance": lambda: min_brand_edit_distance(url),
        "has_homograph_chars": lambda: has_homograph_chars(url),
        "is_punycode_domain": lambda: is_punycode_domain(url),
        # C. SSL/TLS.   Bug → features/ssl_features.py
        "has_https": lambda: has_https(url),                           # scheme only, no network
        "cert_age_days": lambda: cert_age_days(url),                   # live TLS handshake
        "is_self_signed": lambda: is_self_signed(url),
        "trusted_ca": lambda: trusted_ca(url),
        # D. HTML (needs the page).   Bug → features/html_features.py
        "form_count": lambda: form_count(soup),
        "password_field_count": lambda: password_field_count(soup),
        "hidden_field_count": lambda: hidden_field_count(soup),
        "external_resource_ratio": lambda: external_resource_ratio(soup, url),
        "html_similarity_score": lambda: html_similarity_score(soup),
        "https_form_mismatch": lambda: https_form_mismatch(soup, url),
        "favicon_external": lambda: favicon_external(soup, url),
        # E. Network (live).   Bug → features/network_features.py
        "redirect_count": lambda: redirect_count(url),
        "hosting_country_suspicious": lambda: hosting_country_suspicious(url),
        "asn_is_suspicious": lambda: asn_is_suspicious(url),
        "has_mx_record": lambda: has_mx_record(url),
        # F. OSINT.   Bug → features/osint_features.py
        "is_url_shortener": lambda: is_url_shortener(url),             # string match, no network
        "dns_ttl": lambda: dns_ttl(url),
        "google_safe_browsing": lambda: google_safe_browsing(url),
    }


def extract_features(url: str, fetch_html_content: bool = True, only=None) -> dict:
    """
    Extract features for one URL.

    Args:
        url:                The URL to analyse.
        fetch_html_content: Fetch the page for the HTML-group features. Only happens if at
                            least one requested feature needs it.
        only:               Iterable of feature names to compute (default: all of
                            config.FEATURE_COLUMNS). Pass config.LEXICAL_FEATURES for an
                            instant, network-free extraction.

    Returns: dict name -> value. -1 means "unknown / API not configured".
    """
    log.debug(f"Extracting features for: {url}")
    registry = _registry(url, None)
    if only is None:
        names = list(FEATURE_COLUMNS)
    else:
        names = list(only)
        unknown = [n for n in names if n not in registry]
        if unknown:
            raise ValueError(f"Unknown feature name(s): {unknown}")

    if fetch_html_content and any(n in _HTML_FEATURES for n in names):
        soup, _ = _fetch_html(url)
        registry = _registry(url, soup)

    # a column listed in config but not coded yet is zero-filled (only when only=None)
    return {n: (registry[n]() if n in registry else 0) for n in names}


def extract_features_batch(
    urls: list[str],
    fetch_html_content: bool = True,
    delay: float = 0.5,
    only=None,
) -> list[dict]:
    """
    Extract features for a list of URLs with polite rate limiting.

    Args:
        urls:               List of URLs to process.
        fetch_html_content: Whether to make live HTTP requests for HTML features.
        delay:              Seconds to sleep between requests — don't hammer servers.

    Returns:
        List of feature dicts, one per URL, in the same order as the input list.
        Failed URLs return a dict of zeros rather than crashing the whole batch.
    """
    results = []
    for i, url in enumerate(urls):
        log.info(f"  [{i+1}/{len(urls)}] {url[:80]}")
        try:
            feats       = extract_features(url, fetch_html_content=fetch_html_content, only=only)
            feats["url"] = url
            results.append(feats)
        except Exception as e:
            log.warning(f"  Feature extraction failed for {url}: {e}")
            results.append({"url": url, **{col: 0 for col in (only or FEATURE_COLUMNS)}})
        if fetch_html_content and (only is None or any(n in _HTML_FEATURES for n in only)):
            time.sleep(delay)
    return results


if __name__ == "__main__":
    test_url = "http://phonepe-upi-verify.xyz/login?otp=123"
    print(f"\nExtracting features for: {test_url}\n")
    feats = extract_features(test_url, fetch_html_content=False)
    for k, v in feats.items():
        print(f"  {k:<35} {v}")
    print(f"\nTotal features: {len(feats)}")
