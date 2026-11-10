"""tests/test_feature_registry.py — feature_extractor.py (assembler) + model_io.py ONLY."""
import json, os, pickle, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

import feature_extractor as fe
from config import FEATURE_COLUMNS, LEXICAL_FEATURES
from model_io import columns_for, load_model_bundle, meta_path, save_meta, vectorize

URL = "http://uidai-update-kyc.xyz/verify?otp=1"


def test_lexical_is_a_subset_of_all_features():
    assert set(LEXICAL_FEATURES) <= set(FEATURE_COLUMNS) and len(LEXICAL_FEATURES) == len(set(LEXICAL_FEATURES))


def test_registry_covers_every_configured_feature():
    assert set(FEATURE_COLUMNS) <= set(fe._registry("", None))


def test_only_returns_just_the_requested_subset():
    out = fe.extract_features(URL, fetch_html_content=False, only=["url_length", "suspicious_tld"])
    assert list(out) == ["url_length", "suspicious_tld"] and out["suspicious_tld"] == 1


def test_unknown_feature_name_is_rejected():
    with pytest.raises(ValueError):
        fe.extract_features(URL, only=["definitely_not_a_feature"])


def test_lexical_extraction_touches_no_network(monkeypatch):
    """The whole point of the lexical set: zero network, so it works on dead phishing URLs."""
    def boom(*a, **k):
        raise AssertionError("network used by a lexical feature!")
    monkeypatch.setattr("socket.create_connection", boom)
    monkeypatch.setattr("socket.gethostbyname", boom)
    monkeypatch.setattr("requests.get", boom)
    monkeypatch.setattr("requests.post", boom)
    out = fe.extract_features(URL, fetch_html_content=True, only=LEXICAL_FEATURES)
    assert list(out) == LEXICAL_FEATURES


def test_html_is_only_fetched_when_an_html_feature_is_requested(monkeypatch):
    calls = []
    monkeypatch.setattr(fe, "_fetch_html", lambda u: calls.append(u) or (None, None))
    fe.extract_features(URL, fetch_html_content=True, only=["url_length"])
    assert calls == []
    fe.extract_features(URL, fetch_html_content=True, only=["form_count"])
    assert calls == [URL]


def test_default_still_returns_every_column():
    assert set(fe.extract_features(URL, fetch_html_content=False)) == set(FEATURE_COLUMNS)


def test_batch_passes_only_through():
    rows = fe.extract_features_batch([URL, "https://paytm.com/"], fetch_html_content=False, only=["url_length"])
    assert [set(r) for r in rows] == [{"url_length", "url"}] * 2


# ── model_io ────────────────────────────────────────────────────────────────

def _fit(n_features):
    rng = np.random.default_rng(0)
    m = RandomForestClassifier(n_estimators=3, random_state=0)
    m.fit(rng.random((20, n_features)), [0, 1] * 10)
    return m


def test_columns_for():
    assert columns_for("lexical") == LEXICAL_FEATURES and columns_for("full") == FEATURE_COLUMNS
    with pytest.raises(ValueError):
        columns_for("nope")


def test_bundle_round_trip_with_meta(tmp_path):
    p = str(tmp_path / "m.pkl")
    pickle.dump(_fit(len(LEXICAL_FEATURES)), open(p, "wb"))
    save_meta(p, {"feature_set": "lexical", "columns": LEXICAL_FEATURES})
    assert meta_path(p).endswith("m.json")
    model, cols, meta = load_model_bundle(p)
    assert cols == LEXICAL_FEATURES and model.feature_columns_ == cols and model.feature_set_ == "lexical"


def test_legacy_model_without_meta_is_treated_as_full(tmp_path):
    p = str(tmp_path / "old.pkl")
    pickle.dump(_fit(len(FEATURE_COLUMNS)), open(p, "wb"))
    _, cols, meta = load_model_bundle(p)
    assert cols == FEATURE_COLUMNS and meta["legacy"] is True


def test_mismatched_model_and_columns_fail_loudly(tmp_path):
    p = str(tmp_path / "bad.pkl")
    pickle.dump(_fit(5), open(p, "wb"))
    save_meta(p, {"feature_set": "full", "columns": FEATURE_COLUMNS})
    with pytest.raises(ValueError, match="Retrain"):
        load_model_bundle(p)


def test_vectorize_orders_and_zero_fills():
    v = vectorize({"b": 2, "a": 1}, ["a", "b", "c"])
    assert v.shape == (1, 3) and v.tolist() == [[1.0, 2.0, 0.0]]
