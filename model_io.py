"""
model_io.py — save/load a trained model TOGETHER with the exact feature columns it expects.

Edit THIS file if loading a model fails with a column/feature mismatch.

A model trained with `--feature-set lexical` needs 22 inputs, a full one needs 39. The
training run writes `<model>.json` next to `<model>.pkl` listing the columns; every consumer
(predictor, API, dashboard, evaluate) loads both through here so they can never disagree.
Old models without a .json are treated as the full 39-feature set.
"""

import json
import pickle
from pathlib import Path

import numpy as np

from config import FEATURE_COLUMNS, LEXICAL_FEATURES


def columns_for(feature_set: str) -> list:
    if feature_set == "lexical":
        return list(LEXICAL_FEATURES)
    if feature_set == "full":
        return list(FEATURE_COLUMNS)
    raise ValueError(f"feature_set must be 'lexical' or 'full', got {feature_set!r}")


def meta_path(model_path: str) -> str:
    return str(model_path)[: -len(".pkl")] + ".json" if str(model_path).endswith(".pkl") else str(model_path) + ".json"


def save_meta(model_path: str, meta: dict) -> None:
    Path(meta_path(model_path)).write_text(json.dumps(meta, indent=2), encoding="utf-8")


def load_model_bundle(model_path: str):
    """Returns (model, columns, meta). The model also gets `.feature_columns_` / `.feature_set_`."""
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    mp = Path(meta_path(model_path))
    if mp.exists():
        meta = json.loads(mp.read_text(encoding="utf-8"))
        columns = list(meta["columns"])
    else:
        meta = {"feature_set": "full", "legacy": True}
        columns = list(FEATURE_COLUMNS)

    expected = getattr(model, "n_features_in_", None)
    if expected is not None and expected != len(columns):
        raise ValueError(
            f"{model_path} expects {expected} features but its column list has {len(columns)} "
            f"({meta.get('feature_set')}). Retrain with `python trainer.py` to regenerate both files.")

    model.feature_columns_ = columns
    model.feature_set_ = meta.get("feature_set", "full")
    return model, columns, meta


def vectorize(features: dict, columns) -> np.ndarray:
    """One-row matrix in column order (missing -> 0)."""
    return np.array([[features.get(c, 0) for c in columns]], dtype=float)
