"""
tests/test_api.py — Unit tests for api.py Flask endpoints ONLY.

Scope: tests all REST endpoints (/predict, /health, /history, /features)
using Flask's test client — no real HTTP server is started, no real model
is required (a tiny dummy model is trained inline).

If a test in THIS file fails, the bug is in api.py — check:
  - Route handlers: /predict, /health, /history, /features
  - Request parsing (JSON body, missing fields)
  - Response structure (required keys in JSON response)
  - History storage and clearing

Run:
    python -m pytest tests/test_api.py -v
"""

import os
import sys
import pickle
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import FEATURE_COLUMNS, MODEL_DIR


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_tiny_model() -> Pipeline:
    """Train a minimal Random Forest on random data — just enough to predict."""
    rng = np.random.default_rng(42)
    X   = rng.random((40, len(FEATURE_COLUMNS)))
    y   = np.array([1] * 20 + [0] * 20)
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(n_estimators=5, random_state=42)),
    ])
    model.fit(X, y)
    return model


@pytest.fixture(scope="module")
def app_client():
    """
    Create a Flask test client with a dummy model pre-loaded.
    Uses a temp directory so no real model file is required on disk.
    """
    import api  # import the module to patch its globals

    # Inject a tiny trained model so /predict doesn't 503
    api.model = _make_tiny_model()
    api._history.clear()

    api.app.config["TESTING"] = True
    with api.app.test_client() as client:
        yield client

    # Clean up history between test runs
    api._history.clear()


# ══════════════════════════════════════════════════════════════════════════════
# GET /health
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthEndpoint:

    def test_returns_200(self, app_client):
        resp = app_client.get("/health")
        assert resp.status_code == 200

    def test_response_has_status_ok(self, app_client):
        data = app_client.get("/health").get_json()
        assert data["status"] == "ok"

    def test_response_has_model_key(self, app_client):
        data = app_client.get("/health").get_json()
        assert "model" in data

    def test_response_has_history_count(self, app_client):
        data = app_client.get("/health").get_json()
        assert "history_count" in data
        assert isinstance(data["history_count"], int)


# ══════════════════════════════════════════════════════════════════════════════
# POST /predict
# ══════════════════════════════════════════════════════════════════════════════

class TestPredictEndpoint:

    def test_returns_200_for_valid_url(self, app_client):
        resp = app_client.post("/predict", json={"url": "http://evil.xyz/login"})
        assert resp.status_code == 200

    def test_response_has_required_keys(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "http://evil.xyz/login"}
        ).get_json()
        required = {"url", "label", "is_phishing", "probability", "confidence",
                    "features", "suspicious_flags", "source"}
        assert required.issubset(data.keys())

    def test_label_is_phishing_or_legitimate(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "https://www.phonepe.com/"}
        ).get_json()
        assert data["label"] in ("PHISHING", "LEGITIMATE")

    def test_probability_is_valid(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "http://evil.xyz/"}
        ).get_json()
        assert 0.0 <= data["probability"] <= 1.0

    def test_is_phishing_matches_label(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "http://evil.xyz/"}
        ).get_json()
        if data["is_phishing"]:
            assert data["label"] == "PHISHING"
        else:
            assert data["label"] == "LEGITIMATE"

    def test_features_dict_has_all_columns(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "http://evil.xyz/"}
        ).get_json()
        for col in FEATURE_COLUMNS:
            assert col in data["features"], f"Missing feature: {col}"

    def test_suspicious_flags_is_list(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "http://evil.xyz/"}
        ).get_json()
        assert isinstance(data["suspicious_flags"], list)

    def test_source_is_ml_model(self, app_client):
        data = app_client.post(
            "/predict", json={"url": "http://evil.xyz/"}
        ).get_json()
        assert data["source"] == "ml_model"

    def test_missing_url_returns_400(self, app_client):
        resp = app_client.post("/predict", json={})
        assert resp.status_code == 400

    def test_empty_url_returns_400(self, app_client):
        resp = app_client.post("/predict", json={"url": ""})
        assert resp.status_code == 400

    def test_phishing_url_signals_detected(self, app_client):
        """A clear phishing URL should flag at least some suspicious signals."""
        data = app_client.post(
            "/predict",
            json={"url": "http://phonepe-upi-kyc.xyz/login?otp=1234",
                  "fetch_html": False}
        ).get_json()
        # At minimum: suspicious_tld=1, has_https=0 should be flagged
        assert len(data["suspicious_flags"]) > 0

    def test_each_predict_added_to_history(self, app_client):
        import api
        before = len(api._history)
        app_client.post("/predict", json={"url": "http://test-history.xyz/"})
        assert len(api._history) == before + 1


# ══════════════════════════════════════════════════════════════════════════════
# GET /history
# ══════════════════════════════════════════════════════════════════════════════

class TestHistoryEndpoint:

    def test_returns_200(self, app_client):
        resp = app_client.get("/history")
        assert resp.status_code == 200

    def test_returns_list(self, app_client):
        data = app_client.get("/history").get_json()
        assert isinstance(data, list)

    def test_history_grows_after_predict(self, app_client):
        import api
        api._history.clear()
        app_client.post("/predict", json={"url": "http://history-test.xyz/"})
        data = app_client.get("/history").get_json()
        assert len(data) >= 1

    def test_history_entry_has_url(self, app_client):
        import api
        api._history.clear()
        app_client.post("/predict", json={"url": "http://entry-url-check.xyz/"})
        data = app_client.get("/history").get_json()
        assert data[0]["url"] == "http://entry-url-check.xyz/"


# ══════════════════════════════════════════════════════════════════════════════
# DELETE /history
# ══════════════════════════════════════════════════════════════════════════════

class TestClearHistoryEndpoint:

    def test_returns_200(self, app_client):
        resp = app_client.delete("/history")
        assert resp.status_code == 200

    def test_history_empty_after_clear(self, app_client):
        app_client.post("/predict", json={"url": "http://pre-clear.xyz/"})
        app_client.delete("/history")
        data = app_client.get("/history").get_json()
        assert data == []

    def test_response_has_cleared_key(self, app_client):
        data = app_client.delete("/history").get_json()
        assert data.get("cleared") is True


# ══════════════════════════════════════════════════════════════════════════════
# POST /features
# ══════════════════════════════════════════════════════════════════════════════

class TestFeaturesEndpoint:

    def test_returns_200(self, app_client):
        resp = app_client.post("/features", json={"url": "http://evil.xyz/"})
        assert resp.status_code == 200

    def test_response_has_url_and_features(self, app_client):
        data = app_client.post(
            "/features", json={"url": "http://evil.xyz/"}
        ).get_json()
        assert "url"      in data
        assert "features" in data

    def test_features_dict_complete(self, app_client):
        data = app_client.post(
            "/features", json={"url": "http://evil.xyz/"}
        ).get_json()
        for col in FEATURE_COLUMNS:
            assert col in data["features"], f"Missing: {col}"

    def test_missing_url_returns_400(self, app_client):
        resp = app_client.post("/features", json={})
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# WhatsApp / UPI-link / report-info endpoints + allowlist in /predict
# ══════════════════════════════════════════════════════════════════════════════

class TestMessageEndpoints:

    def test_whatsapp_flags_scam(self, app_client):
        r = app_client.post("/analyse-whatsapp", json={"text": "RTO challan pending. Download http://rto-echallan.top/challan.apk"})
        d = r.get_json()
        assert r.status_code == 200 and d["is_phishing"] is True and d["flags"]

    def test_whatsapp_requires_text(self, app_client):
        assert app_client.post("/analyse-whatsapp", json={}).status_code == 400

    def test_upi_link_by_uri(self, app_client):
        d = app_client.post("/analyse-upi-link", json={"uri": "upi://pay?pa=phonepe.refund@ybl&pn=PhonePe%20Refund&am=15000"}).get_json()
        assert d["is_suspicious_link"] is True and d["risk_level"] == "high"

    def test_upi_link_extracted_from_text(self, app_client):
        d = app_client.post("/analyse-upi-link", json={"text": "pay here upi://pay?pa=shop@okaxis&am=100 ok"}).get_json()
        assert d["payee_vpa"] == "shop@okaxis"

    def test_upi_link_requires_input(self, app_client):
        assert app_client.post("/analyse-upi-link", json={"text": "no link"}).status_code == 400

    def test_sms_result_now_has_flags(self, app_client):
        d = app_client.post("/analyse-sms", json={"text": "Share your OTP now"}).get_json()
        assert d["is_phishing"] is True and d["flags"]

    def test_report_info_lists_1930(self, app_client):
        d = app_client.get("/report-info").get_json()
        assert any(c["contact"] == "1930" for c in d) and all("when" in c for c in d)

    def test_predict_includes_official_domain_flag(self, app_client):
        assert app_client.post("/predict", json={"url": "http://evil.xyz/"}).get_json()["official_domain"] is False
        assert app_client.post("/predict", json={"url": "https://uidai.gov.in/"}).get_json()["official_domain"] is True

    def test_official_domain_is_never_returned_as_phishing(self, app_client):
        d = app_client.post("/predict", json={"url": "https://resident.uidai.gov.in/"}).get_json()
        assert d["is_phishing"] is False


class TestLexicalModelServing:
    """A model trained on the 22 lexical features must be served with exactly those columns."""

    def test_predict_returns_only_lexical_features_and_health_reports_it(self, app_client):
        import api
        from config import LEXICAL_FEATURES
        old = api.model
        try:
            rng = np.random.default_rng(3)
            m = Pipeline([("scaler", StandardScaler()), ("clf", RandomForestClassifier(n_estimators=5, random_state=0))])
            m.fit(rng.random((30, len(LEXICAL_FEATURES))), [0, 1] * 15)
            m.feature_columns_, m.feature_set_ = list(LEXICAL_FEATURES), "lexical"
            api.model = m
            d = app_client.post("/predict", json={"url": "http://uidai-update-kyc.xyz/verify"}).get_json()
            assert set(d["features"]) == set(LEXICAL_FEATURES)
            h = app_client.get("/health").get_json()
            assert h["feature_set"] == "lexical" and h["n_features"] == len(LEXICAL_FEATURES)
        finally:
            api.model = old


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
