"""
trainer.py — Train, evaluate, and save phishing detection models.

Models:
  1. Random Forest       — handles non-linear feature interactions well
  2. Logistic Regression — interpretable baseline, good for research write-up

Pipeline:
  1. Load raw_urls.csv + extract features (or load precomputed features.csv)
  2. Split train/test
  3. Train both models with cross-validation
  4. Generate evaluation plots: confusion matrix, ROC curve, feature importance
  5. Save best model to models/best_model.pkl

Usage:
    python trainer.py
    python trainer.py --input data/features.csv   # skip feature extraction
"""

import argparse
import csv
import logging
import pickle
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for servers
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    RocCurveDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import (
    CV_FOLDS,
    DATA_DIR,
    FEATURE_COLUMNS,
    MODEL_DIR,
    RANDOM_STATE,
    RESULTS_DIR,
    TARGET_COLUMN,
    TEST_SIZE,
)
from datetime import datetime, timezone

from feature_extractor import extract_features_batch
from model_io import columns_for, save_meta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ─── Data Loading ─────────────────────────────────────────────────────────────

def load_or_extract_features(
    raw_csv: str = f"{DATA_DIR}raw_urls.csv",
    features_csv: str = f"{DATA_DIR}features.csv",
    force_extract: bool = False,
    feature_set: str = "full",
) -> pd.DataFrame:
    """
    Load precomputed features if the cache has every column the feature set needs,
    otherwise extract them.  "lexical" extraction is instant and needs no network;
    "full" fetches pages / does TLS+DNS lookups (10–30 min on large datasets — cache it).
    """
    columns = columns_for(feature_set)
    features_path = Path(features_csv)

    if features_path.exists() and not force_extract:
        cached = pd.read_csv(features_csv)
        if set(columns) <= set(cached.columns):
            log.info(f"Loading precomputed features from {features_csv}")
            return cached
        log.info(f"Cache {features_csv} lacks columns for the {feature_set!r} set — re-extracting")

    lexical = feature_set == "lexical"
    raw_df = pd.read_csv(raw_csv)
    log.info(f"Extracting {feature_set} features from {raw_csv}" + ("" if lexical else " — this may take a while…"))

    records = extract_features_batch(
        urls=raw_df["url"].tolist(),
        fetch_html_content=not lexical,
        delay=0.0 if lexical else 0.5,
        only=columns if lexical else None,
    )
    df = pd.DataFrame(records)

    # Merge labels from raw dataset
    label_map = dict(zip(raw_df["url"], raw_df["label"]))
    df[TARGET_COLUMN] = df["url"].map(label_map).fillna(0).astype(int)

    Path(DATA_DIR).mkdir(exist_ok=True)
    df.to_csv(features_csv, index=False)
    log.info(f"Features saved → {features_csv}")
    return df


def prepare_xy(df: pd.DataFrame, columns=None):
    """Split DataFrame into feature matrix X and target vector y (columns default: all 39)."""
    columns = list(columns) if columns else list(FEATURE_COLUMNS)
    missing = [c for c in columns if c not in df.columns]
    if missing:
        log.warning(f"Missing feature columns (will be zero-filled): {set(missing)}")
        for col in missing:
            df[col] = 0

    X = df[columns].fillna(-1).values
    y = df[TARGET_COLUMN].values
    return X, y, columns


# ─── Model Definitions ────────────────────────────────────────────────────────

def build_random_forest() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight="balanced",   # handles class imbalance
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])


def build_logistic_regression() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            solver="lbfgs",
        )),
    ])


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_model(
    name: str,
    model: Pipeline,
    X_train, y_train,
    X_test, y_test,
    feature_names: list[str],
) -> dict:
    """Train, cross-validate, and evaluate a model. Returns metrics dict."""
    log.info(f"\n{'='*50}")
    log.info(f"Evaluating: {name}")
    log.info(f"{'='*50}")

    # Cross-validation on training set
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
    log.info(f"CV F1 scores: {cv_scores.round(4)}")
    log.info(f"Mean CV F1:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Fit on full training set
    model.fit(X_train, y_train)

    # Test set evaluation
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_prob)

    log.info(f"\nTest Set Results:")
    log.info(f"  Accuracy:  {acc:.4f}")
    log.info(f"  Precision: {prec:.4f}")
    log.info(f"  Recall:    {rec:.4f}")
    log.info(f"  F1 Score:  {f1:.4f}")
    log.info(f"  ROC AUC:   {auc:.4f}")
    log.info(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])}")

    # Save plots
    Path(RESULTS_DIR).mkdir(exist_ok=True)
    _plot_confusion_matrix(name, y_test, y_pred)
    _plot_roc_curve(name, model, X_test, y_test)
    if hasattr(model.named_steps["clf"], "feature_importances_"):
        _plot_feature_importance(name, model, feature_names)

    return {
        "name": name,
        "model": model,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "cv_f1_mean": cv_scores.mean(),
        "cv_f1_std": cv_scores.std(),
    }


# ─── Plotting ────────────────────────────────────────────────────────────────

def _plot_confusion_matrix(name: str, y_true, y_pred) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title(f"Confusion Matrix — {name}")
    plt.tight_layout()
    safe_name = name.lower().replace(" ", "_")
    path = f"{RESULTS_DIR}{safe_name}_confusion_matrix.png"
    plt.savefig(path, dpi=150)
    plt.close()
    log.info(f"Saved confusion matrix → {path}")


def _plot_roc_curve(name: str, model, X_test, y_test) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    RocCurveDisplay.from_estimator(model, X_test, y_test, ax=ax, name=name)
    ax.plot([0, 1], [0, 1], "k--", label="Random classifier")
    ax.set_title(f"ROC Curve — {name}")
    ax.legend()
    plt.tight_layout()
    safe_name = name.lower().replace(" ", "_")
    path = f"{RESULTS_DIR}{safe_name}_roc_curve.png"
    plt.savefig(path, dpi=150)
    plt.close()
    log.info(f"Saved ROC curve → {path}")


def _plot_feature_importance(name: str, model: Pipeline, feature_names: list[str]) -> None:
    clf = model.named_steps["clf"]
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1][:15]  # top 15 features

    fig, ax = plt.subplots(figsize=(8, 6))
    order = indices[::-1]          # reversed order so the biggest bar is on top
    ax.barh(
        [feature_names[i] for i in order],
        importances[order],
        color="#e63946",
    )
    ax.set_title(f"Top 15 Feature Importances — {name}")
    ax.set_xlabel("Importance Score")
    plt.tight_layout()
    safe_name = name.lower().replace(" ", "_")
    path = f"{RESULTS_DIR}{safe_name}_feature_importance.png"
    plt.savefig(path, dpi=150)
    plt.close()
    log.info(f"Saved feature importance → {path}")


def _plot_model_comparison(results: list[dict]) -> None:
    """Side-by-side bar chart comparing all models."""
    metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    x = np.arange(len(metrics))
    width = 0.35
    colors = ["#2196F3", "#FF5722"]

    fig, ax = plt.subplots(figsize=(10, 6))
    for i, result in enumerate(results):
        values = [result[m] for m in metrics]
        bars = ax.bar(x + i * width, values, width, label=result["name"], color=colors[i])
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.005,
                f"{val:.3f}",
                ha="center", va="bottom", fontsize=8,
            )

    ax.set_xlabel("Metric")
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison — UPI Phishing Detection")
    ax.set_xticks(x + width / 2)
    ax.set_xticklabels([m.replace("_", " ").title() for m in metrics])
    ax.set_ylim(0, 1.08)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    path = f"{RESULTS_DIR}model_comparison.png"
    plt.savefig(path, dpi=150)
    plt.close()
    log.info(f"Saved model comparison → {path}")


# ─── Save / Load ─────────────────────────────────────────────────────────────

def save_model(model: Pipeline, path: str) -> None:
    Path(MODEL_DIR).mkdir(exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(model, f)
    log.info(f"Model saved → {path}")


def save_results_csv(results: list[dict], path: str) -> None:
    Path(RESULTS_DIR).mkdir(exist_ok=True)
    rows = [
        {k: v for k, v in r.items() if k != "model"}
        for r in results
    ]
    keys = rows[0].keys()
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
    log.info(f"Results saved → {path}")


# ─── Main Training Pipeline ───────────────────────────────────────────────────

def train(
    features_csv: str = f"{DATA_DIR}features.csv",
    raw_csv: str = f"{DATA_DIR}raw_urls.csv",
    force_extract: bool = False,
    feature_set: str = "lexical",
) -> None:
    """
    Train + compare the models and save them WITH their column list (model_io.save_meta).

    feature_set="lexical" (default): 22 URL-string features, instant, no network, no
        dependence on whether a phishing site is still alive.
    feature_set="full": all 39 features (live TLS/DNS/HTML) — beware: unreachable pages
        leak the label when phishing URLs come from feeds (see PAPER.md §7).
    Also writes data/train_split.csv and data/test_split.csv so evaluate.py can score
    competing detectors on URLs the model never saw.
    """
    log.info(f"UPI Phishing Detector — Training Pipeline ({feature_set} features)")
    if feature_set == "lexical" and features_csv == f"{DATA_DIR}features.csv":
        features_csv = f"{DATA_DIR}features_lexical.csv"

    # 1. Load data
    df = load_or_extract_features(raw_csv, features_csv, force_extract, feature_set)
    log.info(f"Dataset shape: {df.shape}")
    counts = df[TARGET_COLUMN].value_counts()
    log.info(f"Class distribution:\n{counts}")
    if counts.min() / counts.sum() < 0.25:
        log.warning("Strong class imbalance — accuracy will look better than it is. Add legitimate URLs "
                    "(python collector.py --tranco-legit 500) and judge by precision/recall, not accuracy.")

    X, y, feature_names = prepare_xy(df, columns_for(feature_set))

    # 2. Train/test split (stratified); keep the row indices so the test URLs can be saved
    idx = np.arange(len(y))
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, idx,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    log.info(f"Train: {len(y_train)} samples | Test: {len(y_test)} samples")
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    for split_name, ix in (("train_split", idx_train), ("test_split", idx_test)):
        out = df.iloc[ix][["url", TARGET_COLUMN]].rename(columns={TARGET_COLUMN: "label"})
        out.to_csv(f"{DATA_DIR}{split_name}.csv", index=False)

    # 3. Train and evaluate models
    models_to_train = [
        ("Random Forest",        build_random_forest()),
        ("Logistic Regression",  build_logistic_regression()),
    ]

    results = []
    for name, model in models_to_train:
        result = evaluate_model(
            name, model,
            X_train, y_train,
            X_test, y_test,
            feature_names,
        )
        results.append(result)

    # 4. Save comparison plot + CSV
    _plot_model_comparison(results)
    save_results_csv(results, f"{RESULTS_DIR}model_results.csv")

    # 5. Save the best model (by F1 score) + metadata describing exactly what it expects
    best = max(results, key=lambda r: r["f1"])
    log.info(f"\nBest model: {best['name']} (F1={best['f1']:.4f})")
    metric_keys = ("accuracy", "precision", "recall", "f1", "roc_auc", "cv_f1_mean", "cv_f1_std")
    meta = {
        "feature_set": feature_set,
        "columns": feature_names,
        "best_model": best["name"],
        "n_rows": int(len(df)), "n_train": int(len(y_train)), "n_test": int(len(y_test)),
        "class_counts": {str(k): int(v) for k, v in counts.items()},
        "test_split_csv": f"{DATA_DIR}test_split.csv",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "metrics": {r["name"]: {k: round(float(r[k]), 4) for k in metric_keys} for r in results},
    }
    best_path = f"{MODEL_DIR}best_model.pkl"
    save_model(best["model"], best_path)
    save_meta(best_path, meta)

    # Also save both individually
    for result in results:
        safe_name = result["name"].lower().replace(" ", "_")
        path = f"{MODEL_DIR}{safe_name}.pkl"
        save_model(result["model"], path)
        save_meta(path, meta)

    log.info("\nTraining complete!")
    log.info(f"  Models   → {MODEL_DIR}")
    log.info(f"  Results  → {RESULTS_DIR}")
    log.info(f"  Test set → {DATA_DIR}test_split.csv  (use with: python evaluate.py)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train UPI phishing detection models")
    parser.add_argument("--input", default=f"{DATA_DIR}features.csv", help="Precomputed features CSV")
    parser.add_argument("--raw", default=f"{DATA_DIR}raw_urls.csv", help="Raw URLs CSV")
    parser.add_argument("--force-extract", action="store_true", help="Re-extract features even if cached")
    parser.add_argument("--feature-set", choices=["lexical", "full"], default="lexical",
                        help="lexical = 22 URL-string features, instant (default); full = all 39, needs network")
    args = parser.parse_args()

    train(
        features_csv=args.input,
        raw_csv=args.raw,
        force_extract=args.force_extract,
        feature_set=args.feature_set,
    )
