"""
evaluate.py — score this project's detector against Google Safe Browsing and VirusTotal
on URLs the model has NEVER seen, and report the result honestly.

    python trainer.py --raw data/raw_urls.csv      # writes data/test_split.csv (held-out URLs)
    python evaluate.py                              # uses models/best_model.pkl + that split
    python evaluate.py --no-vt --limit 300          # skip VirusTotal (free tier = 4 requests/min)

Needs API keys in .env for the external detectors (GOOGLE_SAFE_BROWSING_API_KEY,
VIRUSTOTAL_API_KEY). Detectors without a key are skipped, not faked.

Edit THIS file for: metrics, the report, how detectors are wrapped.
Outputs: results/comparison.csv (per-URL answers) and results/comparison.md (summary table).

Read the caveats the report prints: URLs from phishing feeds are, by construction, ones other
blocklists often already know, so "they catch more than my model" is the EXPECTED result — the
interesting numbers are the false-alarm rates and what each side misses.
"""

import argparse
import csv
import logging
import math
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from config import (
    DATA_DIR, GOOGLE_SAFE_BROWSING_API_KEY, MODEL_DIR, PHISH_PROBABILITY_THRESHOLD,
    RESULTS_DIR, VIRUSTOTAL_API_KEY,
)

log = logging.getLogger("evaluate")

OURS = "this project"


# ── metrics (pure functions — unit tested) ────────────────────────────────────

def wilson_interval(k: int, n: int, z: float = 1.96):
    """95% Wilson score interval for a proportion k/n. (None, None) if n == 0."""
    if n == 0:
        return (None, None)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def confusion_metrics(y_true, y_pred) -> dict:
    """Metrics over the items where y_pred is not None (the detector answered)."""
    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if p is None:
            continue
        if t == 1 and p == 1: tp += 1
        elif t == 0 and p == 1: fp += 1
        elif t == 1 and p == 0: fn += 1
        else: tn += 1
    n = tp + fp + fn + tn
    div = lambda a, b: (a / b) if b else None
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    f1 = div(2 * precision * recall, precision + recall) if precision is not None and recall is not None and (precision + recall) else None
    return {
        "answered": n, "total": len(y_true), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_alarm_rate": div(fp, fp + tn), "accuracy": div(tp + tn, n),
        "recall_ci": wilson_interval(tp, tp + fn), "false_alarm_ci": wilson_interval(fp, fp + tn),
    }


def overlap(y_true, ours, other) -> dict:
    """Who catches what, on the URLs BOTH detectors answered."""
    out = dict(common=0, both_caught=0, ours_only_caught=0, other_only_caught=0, both_missed=0,
               ours_only_false_alarms=0, other_only_false_alarms=0)
    for t, a, b in zip(y_true, ours, other):
        if a is None or b is None:
            continue
        out["common"] += 1
        if t == 1:
            if a and b: out["both_caught"] += 1
            elif a: out["ours_only_caught"] += 1
            elif b: out["other_only_caught"] += 1
            else: out["both_missed"] += 1
        else:
            if a and not b: out["ours_only_false_alarms"] += 1
            if b and not a: out["other_only_false_alarms"] += 1
    return out


def build_report(urls, y_true, preds: dict) -> dict:
    report = {"n": len(urls), "n_phishing": sum(y_true), "n_legit": len(y_true) - sum(y_true),
              "detectors": {name: confusion_metrics(y_true, p) for name, p in preds.items()}, "overlap": {}}
    if OURS in preds:
        for name, p in preds.items():
            if name != OURS:
                report["overlap"][name] = overlap(y_true, preds[OURS], p)
    return report


def _pct(x):
    return "n/a" if x is None else f"{x:.0%}"


def _with_ci(v, ci):
    return "n/a" if v is None else f"{v:.0%} ({_pct(ci[0])}–{_pct(ci[1])})"


def render_markdown(report: dict, notes: list) -> str:
    lines = [f"# Detector comparison — {report['n']} held-out URLs "
             f"({report['n_phishing']} phishing / {report['n_legit']} legitimate)\n",
             "| Detector | Answered | Precision | Recall (95% CI) | False-alarm rate (95% CI) | F1 |",
             "|---|---|---|---|---|---|"]
    for name, m in report["detectors"].items():
        lines.append(f"| {name} | {m['answered']}/{m['total']} | {_pct(m['precision'])} | "
                     f"{_with_ci(m['recall'], m['recall_ci'])} | {_with_ci(m['false_alarm_rate'], m['false_alarm_ci'])} | "
                     f"{'n/a' if m['f1'] is None else format(m['f1'], '.2f')} |")
    for name, o in report["overlap"].items():
        lines += [f"\n## {OURS} vs {name} (on the {o['common']} URLs both answered)\n",
                  "| Phishing caught by both | only by this project | only by " + name + " | missed by both |", "|---|---|---|---|",
                  f"| {o['both_caught']} | {o['ours_only_caught']} | {o['other_only_caught']} | {o['both_missed']} |",
                  f"\nFalse alarms on legitimate URLs — only this project: {o['ours_only_false_alarms']}, only {name}: {o['other_only_false_alarms']}"]
    lines += ["\n## Read before quoting these numbers\n"] + [f"- {n}" for n in notes]
    return "\n".join(lines) + "\n"


# ── detectors (each: url -> 1 phishing | 0 clean | None unknown) ─────────────

def our_detector(model_path: str) -> Callable[[str], Optional[int]]:
    from allowlist import apply_allowlist
    from feature_extractor import extract_features
    from model_io import load_model_bundle, vectorize
    model, columns, meta = load_model_bundle(model_path)

    def detect(url: str):
        feats = extract_features(url, fetch_html_content=False, only=columns)
        prob = float(model.predict_proba(vectorize(feats, columns))[0][1])
        res = apply_allowlist({"url": url, "probability": prob, "is_phishing": prob >= PHISH_PROBABILITY_THRESHOLD,
                               "label": "", "confidence": 0.0})
        return int(res["is_phishing"])
    detect.meta = meta
    return detect


def gsb_detector() -> Optional[Callable[[str], Optional[int]]]:
    if GOOGLE_SAFE_BROWSING_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        return None
    from features.osint_features import google_safe_browsing
    return lambda url: {1: 1, 0: 0}.get(google_safe_browsing(url))


def vt_detector(delay: float = 16.0, limit: int = 100) -> Optional[Callable[[str], Optional[int]]]:
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return None
    from features.virustotal_features import virustotal_lookup
    state = {"n": 0}

    def detect(url: str):
        if state["n"] >= limit:
            return None
        if state["n"]:
            time.sleep(delay)             # free tier: 4 requests/minute
        state["n"] += 1
        status = virustotal_lookup(url, submit=False)["vt_status"]
        return 1 if status in ("malicious", "suspicious") else (0 if status == "clean" else None)
    return detect


def run_detectors(urls, detectors: dict) -> dict:
    preds = {}
    for name, fn in detectors.items():
        log.info(f"Running {name} on {len(urls)} URLs…")
        preds[name] = [fn(u) for u in urls]
    return preds


def caveats(n: int, has_external: bool, overlap_with_train: int) -> list:
    notes = []
    if n < 200:
        notes.append(f"Only {n} test URLs — the confidence intervals are wide; differences between detectors are NOT statistically meaningful.")
    notes.append("Phishing URLs from feeds are ones other blocklists often already know, so external detectors are favoured by construction.")
    if has_external:
        notes.append("Safe Browsing / VirusTotal answers depend on WHEN you run this (new phishing is flagged within hours); run soon after collecting and say when you ran it.")
    notes.append("If your legitimate URLs come from the Tranco list they are popular homepages — an easy negative class; false-alarm rates on harder legitimate pages would be higher.")
    notes.append("Same-campaign URLs can appear in both train and test; the split is random, not by time or campaign.")
    if overlap_with_train:
        notes.append(f"WARNING: {overlap_with_train} test URLs also appear in the training split — results are inflated.")
    return notes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test-csv", default=f"{DATA_DIR}test_split.csv")
    ap.add_argument("--model", default=f"{MODEL_DIR}best_model.pkl")
    ap.add_argument("--no-gsb", action="store_true")
    ap.add_argument("--no-vt", action="store_true")
    ap.add_argument("--vt-limit", type=int, default=100, help="max URLs sent to VirusTotal (default 100)")
    ap.add_argument("--vt-delay", type=float, default=16.0, help="seconds between VirusTotal calls")
    ap.add_argument("--limit", type=int, default=0, help="evaluate only the first N test URLs")
    ap.add_argument("--allow-overlap", action="store_true")
    ap.add_argument("--out", default=f"{RESULTS_DIR}comparison")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not Path(args.test_csv).exists() or not Path(args.model).exists():
        print(f"Need {args.test_csv} and {args.model} — run `python trainer.py --raw data/raw_urls.csv` first.")
        return 1
    rows = list(csv.DictReader(open(args.test_csv, encoding="utf-8")))
    if args.limit:
        rows = rows[: args.limit]
    urls, y_true = [r["url"] for r in rows], [int(r["label"]) for r in rows]

    train_csv = Path(args.test_csv).with_name("train_split.csv")
    overlap_n = 0
    if train_csv.exists():
        overlap_n = len(set(urls) & {r["url"] for r in csv.DictReader(open(train_csv, encoding="utf-8"))})
        if overlap_n and not args.allow_overlap:
            print(f"{overlap_n} test URLs are also in the training split — refusing (use --allow-overlap to override).")
            return 1

    detectors = {OURS: our_detector(args.model)}
    if not args.no_gsb:
        g = gsb_detector()
        detectors["Google Safe Browsing"] = g if g else None
        if not g: print("Google Safe Browsing: no API key in .env — skipped.")
    if not args.no_vt:
        v = vt_detector(args.vt_delay, args.vt_limit)
        detectors["VirusTotal"] = v if v else None
        if not v: print("VirusTotal: no API key in .env — skipped.")
    detectors = {k: v for k, v in detectors.items() if v}

    preds = run_detectors(urls, detectors)
    report = build_report(urls, y_true, preds)
    md = render_markdown(report, caveats(len(urls), len(detectors) > 1, overlap_n))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out + ".md").write_text(md, encoding="utf-8")
    with open(args.out + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"] + list(preds))
        for i, u in enumerate(urls):
            w.writerow([u, y_true[i]] + ["" if preds[k][i] is None else preds[k][i] for k in preds])
    print(md)
    print(f"Saved → {args.out}.md and {args.out}.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
