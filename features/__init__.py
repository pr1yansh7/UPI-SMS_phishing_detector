# features/__init__.py
#
# Makes features/ a Python package and re-exports every feature function
# so that existing code using:
#
#     from feature_extractor import url_length
#
# continues to work without changes. If you add a new feature module,
# import and expose it here.

from features.url_features import (
    url_length,
    dot_count,
    digit_ratio,
    special_char_count,
    subdomain_depth,
    has_ip_address,
    has_at_symbol,
    url_entropy,
    path_depth,
    has_double_slash_in_path,
    has_non_standard_port,
    sensitive_query_params,
    phish_keyword_count,
)

from features.domain_features import (
    suspicious_tld,
    brand_in_subdomain,
    brand_in_path,
    brand_in_hostname,
    get_domain_age_days,
    min_brand_edit_distance,
    has_homograph_chars,
    is_punycode_domain,
)

from features.ssl_features import (
    has_https,
    cert_age_days,
    is_self_signed,
    trusted_ca,
)

from features.html_features import (
    form_count,
    password_field_count,
    hidden_field_count,
    external_resource_ratio,
    html_similarity_score,
    https_form_mismatch,
    favicon_external,
)

from features.network_features import (
    redirect_count,
    hosting_country_suspicious,
    asn_is_suspicious,
    has_mx_record,
)

from features.osint_features import (
    is_url_shortener,
    dns_ttl,
    google_safe_browsing,
)

__all__ = [
    # A. URL Structure
    "url_length", "dot_count", "digit_ratio", "special_char_count",
    "subdomain_depth", "has_ip_address", "has_at_symbol", "url_entropy",
    "path_depth", "has_double_slash_in_path", "has_non_standard_port",
    "sensitive_query_params", "phish_keyword_count",
    # B. Domain
    "suspicious_tld", "brand_in_subdomain", "brand_in_path", "brand_in_hostname",
    "get_domain_age_days", "min_brand_edit_distance",
    "has_homograph_chars", "is_punycode_domain",
    # C. SSL
    "has_https", "cert_age_days", "is_self_signed", "trusted_ca",
    # D. HTML
    "form_count", "password_field_count", "hidden_field_count",
    "external_resource_ratio", "html_similarity_score",
    "https_form_mismatch", "favicon_external",
    # E. Network
    "redirect_count", "hosting_country_suspicious",
    "asn_is_suspicious", "has_mx_record",
    # F. OSINT
    "is_url_shortener", "dns_ttl", "google_safe_browsing",
]

# ── New feature modules (imported directly, not re-exported here) ─────────────
# Import these directly from their modules:
#   from features.sms_features import analyse_sms
#   from features.qr_features import analyse_qr
#   from features.virustotal_features import virustotal_score
#   from features.visual_features import visual_similarity_score
#   from features.advanced_domain_features import is_ipfs_hosted, phonetic_brand_similarity
