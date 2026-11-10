# How to evaluate this project honestly

The committed `data/sample_urls.csv` (52 URLs) is a smoke test — **its scores mean nothing**. To get numbers worth quoting:

## 1. Keys (optional but needed for the comparison) — `.env`
`GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY` (free tiers; VirusTotal is limited to 4 requests/minute).
Detectors without a key are skipped, never faked.

## 2. Collect balanced data
```bash
python collector.py --tranco-legit 500     # phishing from OpenPhish/PhishTank + 500 legitimate from Tranco
```
You need hundreds of phishing URLs; the collector warns if classes are >3:1 imbalanced.
**Run step 4 soon after step 2** — blocklists flag new phishing within hours, so waiting changes the answer.

## 3. Train (writes the held-out test split)
```bash
python trainer.py --raw data/raw_urls.csv                     # lexical, 22 features (default)
cp models/best_model.pkl models/lexical.pkl; cp models/best_model.json models/lexical.json
python trainer.py --raw data/raw_urls.csv --feature-set full  # optional: 39 features, slow (live requests)
```
`data/test_split.csv` / `data/train_split.csv` are the URLs the model did / did not see.

## 4. Compare
```bash
python evaluate.py --model models/lexical.pkl --out results/comparison_lexical
python evaluate.py --model models/best_model.pkl --out results/comparison_full   # if you trained both
```
Refuses to run if test URLs overlap the training split. Output: `results/comparison*.md` (precision, recall and false-alarm rate with 95% Wilson CIs; who catches what) and `.csv` (per-URL answers).

## 5. Report it straight
Paste the table into `PAPER.md` §5 **with the caveats the report prints** (feeds favour blocklists; Tranco negatives are easy; random split; date you ran it).
The likely true result is "Safe Browsing/VirusTotal catch more; mine has X% false alarms and catches Y that they missed" — that is a fine, honest finding.
