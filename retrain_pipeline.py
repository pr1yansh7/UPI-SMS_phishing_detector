"""
retrain_pipeline.py — Automated nightly model retraining pipeline.

Runs as a background process. Every night at 02:00 it:
  1. Fetches fresh phishing URLs from OpenPhish + PhishTank
  2. Extracts features for new URLs
  3. Trains a new model on the combined dataset
  4. Compares new model F1 to current production model
  5. Replaces production model ONLY if new model is better
  6. Logs everything to logs/retrain.log

This keeps your model fresh — phishing patterns evolve daily and a
model trained once on static data degrades over time.

Edit THIS file if:
  - Retraining schedule needs to change (daily → weekly etc.)
  - Promotion threshold needs adjusting (currently F1 must improve by 0.005)
  - Log rotation or alerting logic needs changing

Usage:
    python retrain_pipeline.py          # run scheduler (keeps running)
    python retrain_pipeline.py --now    # trigger one retrain immediately
    python retrain_pipeline.py --dry-run # show what would happen, no changes
"""

import argparse
import json
import logging
import os
import pickle
import shutil
from datetime import datetime, timezone
from pathlib import Path

import schedule
import time

from config import DATA_DIR, MODEL_DIR, RESULTS_DIR
from model_io import columns_for, meta_path, save_meta

# ── Logging setup ─────────────────────────────────────────────────────────────

Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/retrain.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_model_f1(model_path: str) -> float:
    """Load the F1 score stored alongside a model. Returns 0.0 if not found."""
    meta_path = model_path.replace(".pkl", "_meta.txt")
    if not Path(meta_path).exists():
        return 0.0
    try:
        with open(meta_path) as f:
            for line in f:
                if line.startswith("f1="):
                    return float(line.strip().split("=")[1])
    except Exception:
        pass
    return 0.0


def _production_feature_set() -> str:
    """Feature set of the model currently in production (so a retrain never swaps column layouts)."""
    mp = Path(meta_path(f"{MODEL_DIR}best_model.pkl"))
    if mp.exists():
        try:
            return json.loads(mp.read_text(encoding="utf-8")).get("feature_set", "full")
        except Exception:
            pass
    return "lexical" if not Path(f"{MODEL_DIR}best_model.pkl").exists() else "full"


def _save_model_f1(model_path: str, f1: float) -> None:
    """Save F1 score alongside the model for comparison in future runs."""
    meta_path = model_path.replace(".pkl", "_meta.txt")
    with open(meta_path, "w") as f:
        f.write(f"f1={f1:.6f}\n")
        f.write(f"trained_at={datetime.now(timezone.utc).isoformat()}\n")


# ── Core retrain logic ────────────────────────────────────────────────────────

def retrain(dry_run: bool = False) -> dict:
    """
    Run a full retrain cycle.

    Steps:
      1. Collect fresh phishing URLs
      2. Re-extract features (force=True to pick up new URLs)
      3. Train new model
      4. Compare F1 to current production model
      5. Promote if better (or dry_run)

    Returns:
        dict with keys: success, new_f1, old_f1, promoted, message
    """
    log.info("=" * 60)
    log.info(f"Retrain cycle started — dry_run={dry_run}")
    log.info("=" * 60)

    result = {
        "success":   False,
        "new_f1":    0.0,
        "old_f1":    0.0,
        "promoted":  False,
        "message":   "",
    }

    # ── Step 1: Collect fresh data ────────────────────────────────────────
    log.info("[1/5] Collecting fresh phishing URLs…")
    try:
        from collector import collect
        records = collect(output_path=f"{DATA_DIR}raw_urls.csv")
        log.info(f"  Collected {len(records)} URLs")
        if len(records) < 50:
            result["message"] = f"Too few URLs collected ({len(records)}) — skipping retrain"
            log.warning(result["message"])
            return result
    except Exception as e:
        result["message"] = f"Collection failed: {e}"
        log.error(result["message"])
        return result

    # ── Step 2: Extract features ──────────────────────────────────────────
    log.info("[2/5] Extracting features (force=True)…")
    candidate_features = f"{DATA_DIR}features_candidate.csv"
    try:
        from trainer import load_or_extract_features
        feature_set = _production_feature_set()
        df = load_or_extract_features(
            raw_csv=f"{DATA_DIR}raw_urls.csv",
            features_csv=candidate_features,
            force_extract=True,
            feature_set=feature_set,
        )
        log.info(f"  Features extracted: {df.shape}")
    except Exception as e:
        result["message"] = f"Feature extraction failed: {e}"
        log.error(result["message"])
        return result

    # ── Step 3: Train candidate model ─────────────────────────────────────
    log.info("[3/5] Training candidate model…")
    candidate_model_path = f"{MODEL_DIR}candidate_model.pkl"
    try:
        from trainer import (
            prepare_xy, build_random_forest, evaluate_model, save_model
        )
        from sklearn.model_selection import train_test_split
        from config import RANDOM_STATE, TEST_SIZE

        X, y, feature_names = prepare_xy(df, columns_for(feature_set))
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
        )

        model  = build_random_forest()
        result_dict = evaluate_model(
            "Candidate Random Forest", model,
            X_train, y_train, X_test, y_test, feature_names,
        )
        new_f1 = result_dict["f1"]
        log.info(f"  Candidate model F1: {new_f1:.4f}")

        if not dry_run:
            save_model(model, candidate_model_path)
            _save_model_f1(candidate_model_path, new_f1)
            save_meta(candidate_model_path, {"feature_set": feature_set, "columns": feature_names})
    except Exception as e:
        result["message"] = f"Training failed: {e}"
        log.error(result["message"])
        return result

    # ── Step 4: Compare to production model ───────────────────────────────
    log.info("[4/5] Comparing to production model…")
    production_path = f"{MODEL_DIR}best_model.pkl"
    old_f1 = _load_model_f1(production_path)
    log.info(f"  Production F1: {old_f1:.4f}  |  Candidate F1: {new_f1:.4f}")

    PROMOTION_THRESHOLD = 0.005   # candidate must be at least 0.5% better

    result["new_f1"] = new_f1
    result["old_f1"] = old_f1

    # ── Step 5: Promote if better ─────────────────────────────────────────
    if new_f1 >= old_f1 + PROMOTION_THRESHOLD:
        log.info("[5/5] Candidate is better — promoting to production…")
        if not dry_run:
            # Back up old model
            backup_path = production_path.replace(".pkl", f"_backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pkl")
            if Path(production_path).exists():
                shutil.copy(production_path, backup_path)
                log.info(f"  Old model backed up → {backup_path}")
            shutil.copy(candidate_model_path, production_path)
            shutil.copy(meta_path(candidate_model_path), meta_path(production_path))
            _save_model_f1(production_path, new_f1)
            log.info(f"  New model deployed → {production_path}")

        result.update({
            "success":  True,
            "promoted": True,
            "message":  f"Promoted: F1 improved {old_f1:.4f} → {new_f1:.4f}",
        })
    else:
        log.info(f"[5/5] Candidate not better enough (Δ={new_f1-old_f1:+.4f}) — keeping production model.")
        result.update({
            "success":  True,
            "promoted": False,
            "message":  f"Not promoted: Δ={new_f1-old_f1:+.4f} < threshold {PROMOTION_THRESHOLD}",
        })

    log.info(f"Retrain cycle complete — {result['message']}")
    return result


# ── Scheduler ─────────────────────────────────────────────────────────────────

def start_scheduler(retrain_time: str = "02:00") -> None:
    """
    Start the nightly retrain scheduler.
    Runs retrain() every day at retrain_time (default 02:00 local time).
    Runs indefinitely until interrupted with Ctrl+C.

    Args:
        retrain_time: HH:MM format time string for daily retrain.
    """
    log.info(f"Retrain scheduler started — daily at {retrain_time}")
    log.info("Press Ctrl+C to stop.")

    schedule.every().day.at(retrain_time).do(retrain)

    # Also run once on startup if no model exists
    if not Path(f"{MODEL_DIR}best_model.pkl").exists():
        log.info("No production model found — running initial training now.")
        retrain()

    while True:
        schedule.run_pending()
        time.sleep(30)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="UPI Phishing Detector — Automated Retraining Pipeline",
    )
    parser.add_argument(
        "--now", action="store_true",
        help="Trigger one retrain immediately, then exit.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would happen without making any changes.",
    )
    parser.add_argument(
        "--time", default="02:00",
        help="Time to run daily retrain (HH:MM, default: 02:00).",
    )
    args = parser.parse_args()

    Path(MODEL_DIR).mkdir(exist_ok=True)
    Path(DATA_DIR).mkdir(exist_ok=True)
    Path(RESULTS_DIR).mkdir(exist_ok=True)

    if args.now or args.dry_run:
        result = retrain(dry_run=args.dry_run)
        print(f"\nResult: {result['message']}")
        print(f"  New F1: {result['new_f1']:.4f}")
        print(f"  Old F1: {result['old_f1']:.4f}")
        print(f"  Promoted: {result['promoted']}")
    else:
        start_scheduler(retrain_time=args.time)


if __name__ == "__main__":
    main()
