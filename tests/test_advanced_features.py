"""
tests/test_advanced_features.py — Tests for advanced feature modules.

Covers:
  - features/advanced_domain_features.py (phonetic, IPFS, redirect, Tranco, CT)
  - features/qr_features.py
  - features/virustotal_features.py
  - features/visual_features.py (graceful degradation only)

Run:
    python -m pytest tests/test_advanced_features.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest


# ══════════════════════════════════════════════════════════════════════════════
# advanced_domain_features.py
# ══════════════════════════════════════════════════════════════════════════════

class TestPhoneticSimilarity:
    @pytest.mark.parametrize("url", [
        "http://fhonepe.xyz/login", "http://phonpe.com/", "http://paytem.in/", "http://fhonepe-kyc.xyz/",
        "http://adhar-update.xyz/", "http://login.fhonepe.com/",
    ])
    def test_sounds_like_a_brand(self, url):
        from features.advanced_domain_features import phonetic_brand_similarity
        assert phonetic_brand_similarity(url) == 1

    @pytest.mark.parametrize("url", [
        "https://phonepe.com/", "https://paytm.com/", "https://google.com/",
        "http://unrelated-site.com/", "https://www.amazon.in/", "",
    ])
    def test_exact_brands_and_unrelated_domains_are_not_flagged(self, url):
        from features.advanced_domain_features import phonetic_brand_similarity
        assert phonetic_brand_similarity(url) == 0

    def test_key_examples(self):
        from features.advanced_domain_features import phonetic_key
        assert phonetic_key("phonepe") == phonetic_key("fhonepe") == phonetic_key("phonpe") == "fnp"
        assert phonetic_key("paytm") == phonetic_key("paytem") == "ptm"
        assert phonetic_key("") == "" and phonetic_key("123") == ""

    def test_is_deterministic_across_many_calls(self):
        from features.advanced_domain_features import phonetic_brand_similarity
        assert len({phonetic_brand_similarity("https://google.com/") for _ in range(200)}) == 1


class TestIPFSDetection:
    def test_ipfs_gateway_detected(self):
        from features.advanced_domain_features import is_ipfs_hosted
        assert is_ipfs_hosted("https://ipfs.io/ipfs/QmXXX") == 1
        assert is_ipfs_hosted("https://cloudflare-ipfs.com/ipfs/QmXXX") == 1

    def test_normal_url_not_ipfs(self):
        from features.advanced_domain_features import is_ipfs_hosted
        assert is_ipfs_hosted("https://www.phonepe.com/") == 0
        assert is_ipfs_hosted("http://evil.xyz/login") == 0

    def test_ipfs_hash_in_url(self):
        from features.advanced_domain_features import is_ipfs_hosted
        result = is_ipfs_hosted("https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.dweb.link/")
        assert result == 1


class TestRedirectChain:
    def test_returns_dict_with_required_keys(self):
        from features.advanced_domain_features import redirect_chain
        result = redirect_chain("https://www.phonepe.com/")
        required = {"chain", "chain_length", "crosses_domain", "final_url", "has_suspicious_hop"}
        assert required.issubset(result.keys())

    def test_chain_length_non_negative(self):
        from features.advanced_domain_features import redirect_chain
        result = redirect_chain("https://www.phonepe.com/")
        assert result["chain_length"] >= 0

    def test_redirect_crosses_domain_binary(self):
        from features.advanced_domain_features import redirect_crosses_domain
        result = redirect_crosses_domain("https://www.phonepe.com/")
        assert result in (0, 1)

    def test_redirect_has_suspicious_hop_binary(self):
        from features.advanced_domain_features import redirect_has_suspicious_hop
        result = redirect_has_suspicious_hop("https://www.phonepe.com/")
        assert result in (0, 1)


class TestWhoisPrivacy:
    def test_returns_valid_value_without_key(self):
        from features.advanced_domain_features import whois_privacy_protected
        result = whois_privacy_protected("http://evil.xyz/")
        assert result in (-1, 0, 1)

    def test_returns_minus_one_without_api_key(self):
        from config import WHOIS_API_KEY
        from features.advanced_domain_features import whois_privacy_protected
        if WHOIS_API_KEY == "YOUR_WHOIS_API_KEY":
            assert whois_privacy_protected("http://evil.xyz/") == -1


class TestTrancoRank:
    def test_returns_int_or_minus_one(self):
        from features.advanced_domain_features import tranco_rank
        result = tranco_rank("https://www.google.com/")
        assert isinstance(result, int)
        assert result >= -1

    def test_unknown_domain_returns_zero_or_minus_one(self):
        from features.advanced_domain_features import tranco_rank
        result = tranco_rank("http://thisdoesnotexistxyz123.tk/")
        assert result in (-1, 0)

    def test_is_low_popularity_binary(self):
        from features.advanced_domain_features import is_low_popularity_domain
        result = is_low_popularity_domain("http://evil.xyz/")
        assert result in (-1, 0, 1)


class TestCertificateTransparency:
    def test_returns_int_or_minus_one(self):
        from features.advanced_domain_features import crt_sh_new_cert_count
        result = crt_sh_new_cert_count("https://www.phonepe.com/")
        assert isinstance(result, int)
        assert result >= -1

    def test_has_recent_cert_binary(self):
        from features.advanced_domain_features import has_recent_certificate
        result = has_recent_certificate("https://www.phonepe.com/")
        assert result in (-1, 0, 1)

    def test_nonexistent_domain_returns_zero_or_minus_one(self):
        from features.advanced_domain_features import crt_sh_new_cert_count
        result = crt_sh_new_cert_count("http://thisdoesnotexist99999.xyz/")
        assert result in (-1, 0)


# ══════════════════════════════════════════════════════════════════════════════
# qr_features.py
# ══════════════════════════════════════════════════════════════════════════════

class TestQRFeatures:
    def test_extract_url_nonexistent_file(self):
        from features.qr_features import extract_url_from_qr
        result = extract_url_from_qr("/nonexistent/path.png")
        assert result is None

    def test_is_upi_qr_missing_file(self):
        from features.qr_features import is_upi_qr
        assert is_upi_qr("/nonexistent/path.png") == 0

    def test_qr_url_is_http_missing_file(self):
        from features.qr_features import qr_url_is_http
        assert qr_url_is_http("/nonexistent/path.png") == 0

    def test_analyse_qr_missing_file(self):
        from features.qr_features import analyse_qr
        result = analyse_qr("/nonexistent/path.png")
        assert "error" in result
        assert result["decoded_url"] is None

    def test_analyse_qr_returns_required_keys(self):
        from features.qr_features import analyse_qr
        result = analyse_qr("/nonexistent/path.png")
        required = {"image_path", "decoded_url", "is_upi_qr",
                    "qr_url_is_http", "suspicious_domain", "ml_result", "error"}
        assert required.issubset(result.keys())


# ══════════════════════════════════════════════════════════════════════════════
# virustotal_features.py
# ══════════════════════════════════════════════════════════════════════════════

class TestVirusTotalFeatures:
    def test_returns_minus_one_without_key(self):
        from features.virustotal_features import virustotal_score
        result = virustotal_score("http://evil.xyz/")
        assert result == -1.0

    def test_lookup_returns_valid_dict_without_key(self):
        from features.virustotal_features import virustotal_lookup
        result = virustotal_lookup("http://evil.xyz/")
        required = {"vt_malicious", "vt_suspicious", "vt_clean",
                    "vt_undetected", "vt_total", "vt_score", "vt_status"}
        assert required.issubset(result.keys())

    def test_status_not_configured_without_key(self):
        from features.virustotal_features import virustotal_lookup
        result = virustotal_lookup("http://evil.xyz/")
        assert result["vt_status"] == "not_configured"

    def test_is_malicious_minus_one_without_key(self):
        from features.virustotal_features import virustotal_is_malicious
        result = virustotal_is_malicious("http://evil.xyz/")
        assert result == -1

    def test_url_id_generation(self):
        from features.virustotal_features import _url_to_vt_id
        import base64
        url    = "http://evil.xyz/"
        vt_id  = _url_to_vt_id(url)
        decoded = base64.urlsafe_b64decode(vt_id + "==").decode()
        assert decoded == url


# ══════════════════════════════════════════════════════════════════════════════
# visual_features.py — graceful degradation tests only
# ══════════════════════════════════════════════════════════════════════════════

class TestVisualFeatures:
    def test_screenshot_returns_none_or_bytes(self):
        from features.visual_features import screenshot_url
        result = screenshot_url("https://www.phonepe.com/", timeout=5)
        assert result is None or isinstance(result, bytes)

    def test_visual_similarity_returns_float_or_minus_one(self):
        from features.visual_features import visual_similarity_score
        result = visual_similarity_score("https://www.phonepe.com/", timeout=5)
        assert result == -1.0 or 0.0 <= result <= 1.0

    def test_visual_clone_returns_valid_value(self):
        from features.visual_features import visual_clone_detected
        result = visual_clone_detected("https://www.phonepe.com/")
        assert result in (-1, 0, 1)

    def test_compute_phash_none_without_pil(self):
        from features.visual_features import PIL_AVAILABLE, compute_phash
        if not PIL_AVAILABLE:
            assert compute_phash(b"fake") is None

    def test_load_reference_hashes_returns_dict(self):
        from features.visual_features import load_reference_hashes
        result = load_reference_hashes()
        assert isinstance(result, dict)


# ══════════════════════════════════════════════════════════════════════════════
# retrain_pipeline.py
# ══════════════════════════════════════════════════════════════════════════════

class TestRetrainPipeline:
    def test_load_model_f1_missing_file(self):
        from retrain_pipeline import _load_model_f1
        result = _load_model_f1("/nonexistent/model.pkl")
        assert result == 0.0

    def test_save_and_load_f1(self):
        import tempfile, os
        from retrain_pipeline import _load_model_f1, _save_model_f1
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            path = f.name
        try:
            _save_model_f1(path, 0.9712)
            loaded = _load_model_f1(path)
            assert abs(loaded - 0.9712) < 0.0001
        finally:
            os.unlink(path)
            meta = path.replace(".pkl", "_meta.txt")
            if os.path.exists(meta):
                os.unlink(meta)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
