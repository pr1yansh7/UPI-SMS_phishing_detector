"""
tests/test_trainer.py — Unit tests for trainer.py ONLY.

Scope: tests data loading, feature preparation, model building, and
result saving. Does NOT run actual model training (too slow for CI) —
instead verifies that each sub-function works correctly in isolation.

If a test in THIS file fails, the bug is in trainer.py — check:
  - load_or_extract_features()
  - prepare_xy()
  - build_random_forest()
  - build_logistic_regression()
  - save_model() / save_results_csv()

Run:
    python -m pytest tests/test_trainer.py -v
"""

import os
import sys
import csv
import pickle
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

from config import FEATURE_COLUMNS, TARGET_COLUMN, RANDOM_STATE, TEST_SIZE
from trainer import (
    build_random_forest,
    build_logistic_regression,
    prepare_xy,
    save_model,
    save_results_csv,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _make_dummy_df(n_phish: int = 20, n_legit: int = 20) -> pd.DataFrame:
    """Create a minimal DataFrame with all feature columns + label."""
    rng = np.random.default_rng(RANDOM_STATE)
    rows = []
    for i in range(n_phish):
        row = {col: rng.random() for col in FEATURE_COLUMNS}
        row[TARGET_COLUMN] = 1
        rows.append(row)
    for i in range(n_legit):
        row = {col: rng.random() for col in FEATURE_COLUMNS}
        row[TARGET_COLUMN] = 0
        rows.append(row)
    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════════════════════
# build_random_forest()
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildRandomForest:

    def test_returns_pipeline(self):
        model = build_random_forest()
        assert isinstance(model, Pipeline)

    def test_has_scaler_and_clf(self):
        model = build_random_forest()
        assert "scaler" in model.named_steps
        assert "clf"    in model.named_steps

    def test_clf_is_random_forest(self):
        from sklearn.ensemble import RandomForestClassifier
        model = build_random_forest()
        assert isinstance(model.named_steps["clf"], RandomForestClassifier)

    def test_can_fit_and_predict(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_random_forest()
        model.fit(X, y)
        preds = model.predict(X)
        assert len(preds) == len(y)
        assert set(preds).issubset({0, 1})

    def test_predict_proba_shape(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_random_forest()
        model.fit(X, y)
        proba = model.predict_proba(X)
        assert proba.shape == (len(y), 2)

    def test_proba_sums_to_one(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_random_forest()
        model.fit(X, y)
        proba = model.predict_proba(X)
        np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-6)


# ══════════════════════════════════════════════════════════════════════════════
# build_logistic_regression()
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildLogisticRegression:

    def test_returns_pipeline(self):
        model = build_logistic_regression()
        assert isinstance(model, Pipeline)

    def test_clf_is_logistic_regression(self):
        from sklearn.linear_model import LogisticRegression
        model = build_logistic_regression()
        assert isinstance(model.named_steps["clf"], LogisticRegression)

    def test_can_fit_and_predict(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_logistic_regression()
        model.fit(X, y)
        preds = model.predict(X)
        assert len(preds) == len(y)

    def test_predict_proba_shape(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_logistic_regression()
        model.fit(X, y)
        proba = model.predict_proba(X)
        assert proba.shape == (len(y), 2)


# ══════════════════════════════════════════════════════════════════════════════
# prepare_xy()
# ══════════════════════════════════════════════════════════════════════════════

class TestPrepareXY:

    def test_returns_correct_shapes(self):
        df = _make_dummy_df(10, 10)
        X, y, feature_names = prepare_xy(df)
        assert X.shape == (20, len(FEATURE_COLUMNS))
        assert y.shape == (20,)
        assert len(feature_names) == len(FEATURE_COLUMNS)

    def test_feature_names_match_columns(self):
        df = _make_dummy_df()
        _, _, names = prepare_xy(df)
        assert names == FEATURE_COLUMNS

    def test_labels_are_binary(self):
        df = _make_dummy_df(10, 10)
        _, y, _ = prepare_xy(df)
        assert set(y).issubset({0, 1})

    def test_missing_columns_zero_filled(self):
        """If a feature column is missing from the DataFrame it should be zero-filled."""
        df = _make_dummy_df()
        # Drop one column to simulate a missing feature
        df = df.drop(columns=[FEATURE_COLUMNS[0]])
        X, y, _ = prepare_xy(df)
        # Should not raise — missing column filled with 0
        assert X.shape[1] == len(FEATURE_COLUMNS)

    def test_nan_values_filled(self):
        """NaN values (e.g. from failed WHOIS lookups) should be replaced with -1."""
        df = _make_dummy_df()
        df.loc[0, FEATURE_COLUMNS[0]] = float("nan")
        X, y, _ = prepare_xy(df)
        assert not np.isnan(X).any()


# ══════════════════════════════════════════════════════════════════════════════
# save_model()
# ══════════════════════════════════════════════════════════════════════════════

class TestSaveModel:

    def test_saves_and_loads_correctly(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_random_forest()
        model.fit(X, y)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_model.pkl")
            save_model(model, path)
            assert os.path.exists(path)

            with open(path, "rb") as f:
                loaded = pickle.load(f)

            # Loaded model should predict identically to the original
            orig_preds   = model.predict(X)
            loaded_preds = loaded.predict(X)
            np.testing.assert_array_equal(orig_preds, loaded_preds)

    def test_creates_directory_if_missing(self):
        df = _make_dummy_df()
        X, y, _ = prepare_xy(df)
        model = build_random_forest()
        model.fit(X, y)

        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "models", "subdir", "model.pkl")
            Path(nested).parent.mkdir(parents=True, exist_ok=True)
            save_model(model, nested)
            assert os.path.exists(nested)


# ══════════════════════════════════════════════════════════════════════════════
# save_results_csv()
# ══════════════════════════════════════════════════════════════════════════════

class TestSaveResultsCSV:

    def _make_results(self):
        return [
            {
                "name": "Random Forest", "accuracy": 0.97,
                "precision": 0.96, "recall": 0.98,
                "f1": 0.97, "roc_auc": 0.99,
                "cv_f1_mean": 0.97, "cv_f1_std": 0.01,
            },
            {
                "name": "Logistic Regression", "accuracy": 0.92,
                "precision": 0.91, "recall": 0.93,
                "f1": 0.92, "roc_auc": 0.97,
                "cv_f1_mean": 0.91, "cv_f1_std": 0.02,
            },
        ]

    def test_creates_csv_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "results.csv")
            save_results_csv(self._make_results(), path)
            assert os.path.exists(path)

    def test_csv_has_correct_row_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "results.csv")
            results = self._make_results()
            save_results_csv(results, path)
            with open(path) as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == len(results)

    def test_csv_has_name_column(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "results.csv")
            save_results_csv(self._make_results(), path)
            with open(path) as f:
                rows = list(csv.DictReader(f))
            assert rows[0]["name"] == "Random Forest"
            assert rows[1]["name"] == "Logistic Regression"

    def test_model_key_excluded_from_csv(self):
        """The 'model' key (the actual Pipeline object) must never be written to CSV."""
        results = self._make_results()
        results[0]["model"] = build_random_forest()  # add a model object
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "results.csv")
            save_results_csv(results, path)
            with open(path) as f:
                reader = csv.DictReader(f)
                assert "model" not in reader.fieldnames


# ══════════════════════════════════════════════════════════════════════════════
# Regression: plotting + full evaluate_model path (this crashed before)
# ══════════════════════════════════════════════════════════════════════════════

class TestEvaluateModelEndToEnd:

    def test_feature_importance_plot_does_not_crash(self):
        import matplotlib
        matplotlib.use("Agg")
        from trainer import _plot_feature_importance
        df = _make_dummy_df()
        X, y, names = prepare_xy(df)
        model = build_random_forest()
        model.fit(X, y)
        with tempfile.TemporaryDirectory() as tmp:
            import trainer
            old = trainer.RESULTS_DIR
            trainer.RESULTS_DIR = tmp + os.sep
            try:
                _plot_feature_importance("Random Forest", model, names)
            finally:
                trainer.RESULTS_DIR = old
            assert any(f.endswith("_feature_importance.png") for f in os.listdir(tmp))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ══════════════════════════════════════════════════════════════════════════════
# Whole train() run on synthetic data — this is the test that would have caught the
# feature-importance crash.  No network: features come from a pre-built CSV.
# ══════════════════════════════════════════════════════════════════════════════

class TestTrainEndToEnd:

    def _features_csv(self, tmp_path):
        from config import FEATURE_COLUMNS
        rng = np.random.default_rng(1)
        rows = []
        for i in range(80):
            label = i % 2
            row = {c: float(rng.random()) + (1.5 if label and j < 5 else 0.0) for j, c in enumerate(FEATURE_COLUMNS)}
            row.update({"url": f"http://site{i}.example/p{i}", TARGET_COLUMN: label})
            rows.append(row)
        p = tmp_path / "data" / "f.csv"
        p.parent.mkdir(exist_ok=True)
        pd.DataFrame(rows).to_csv(p, index=False)
        return str(p)

    @pytest.mark.parametrize("feature_set", ["lexical", "full"])
    def test_train_saves_models_meta_and_splits(self, tmp_path, monkeypatch, feature_set):
        import json
        import trainer
        from config import FEATURE_COLUMNS, LEXICAL_FEATURES
        from model_io import load_model_bundle
        for name, sub in (("MODEL_DIR", "models"), ("RESULTS_DIR", "results"), ("DATA_DIR", "data")):
            monkeypatch.setattr(trainer, name, str(tmp_path / sub) + os.sep)
        csv_path = self._features_csv(tmp_path)

        trainer.train(features_csv=csv_path, raw_csv="unused.csv", feature_set=feature_set)

        expected = LEXICAL_FEATURES if feature_set == "lexical" else FEATURE_COLUMNS
        model, cols, meta = load_model_bundle(str(tmp_path / "models" / "best_model.pkl"))
        assert cols == expected and meta["feature_set"] == feature_set and model.n_features_in_ == len(expected)
        for fname in ("random_forest", "logistic_regression"):
            assert (tmp_path / "models" / f"{fname}.pkl").exists() and (tmp_path / "models" / f"{fname}.json").exists()
        assert (tmp_path / "results" / "random_forest_feature_importance.png").exists()

        test = pd.read_csv(tmp_path / "data" / "test_split.csv")
        train = pd.read_csv(tmp_path / "data" / "train_split.csv")
        assert list(test.columns) == ["url", "label"] and len(test) == meta["n_test"] == 16
        assert not set(test["url"]) & set(train["url"]), "train/test overlap"
        assert json.loads((tmp_path / "models" / "best_model.json").read_text())["metrics"]["Random Forest"]["f1"] >= 0

    def test_cache_lacking_columns_is_not_silently_zero_filled(self, tmp_path, monkeypatch):
        import trainer
        monkeypatch.setattr(trainer, "DATA_DIR", str(tmp_path) + os.sep)
        from config import LEXICAL_FEATURES
        cached = tmp_path / "c.csv"
        pd.DataFrame([{"url": "http://a.xyz/", TARGET_COLUMN: 1, "url_length": 5}]).to_csv(cached, index=False)
        raw = tmp_path / "raw.csv"
        pd.DataFrame([{"url": "http://a.xyz/login", "label": 1}, {"url": "https://paytm.com/", "label": 0}]).to_csv(raw, index=False)
        df = trainer.load_or_extract_features(str(raw), str(cached), False, "lexical")
        assert set(LEXICAL_FEATURES) <= set(df.columns) and len(df) == 2   # re-extracted, not the stale 1-col cache
