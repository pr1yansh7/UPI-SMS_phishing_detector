# UPI-SMS Phishing Detector 🛡️

!\[Tests](https://github.com/pr1yansh7/UPI-SMS\_phishing\_detector/actions/workflows/tests.yml/badge.svg)
!\[Python](https://img.shields.io/badge/python-3.10%2B-blue)
!\[License](https://img.shields.io/badge/license-MIT-green)
!\[Features](https://img.shields.io/badge/URL%20features-39-orange)
!\[SMS](https://img.shields.io/badge/SMS%20detection-8%20features-purple)

ML-based phishing detector for **UPI payment apps** (PhonePe, GPay, Paytm, BHIM) and **Aadhaar/UIDAI** identity services. Covers URLs, SMS messages, and QR codes.

## What it does

|Check|How|In the trained ML model?|
|-|-|-|
|**URL** (UPI + Aadhaar lookalikes)|Random Forest / Logistic Regression on **22 lexical features** (URL string only — instant, no network; default) or all **39** (adds live SSL/DNS/HTML/hosting; `--feature-set full`)|✅|
|**SMS**|8 rule-based checks: OTP-sharing request, fake sender ID, urgency, account threats, Hindi/Tamil/Telugu/Bengali wording|❌ rules|
|**WhatsApp message**|SMS checks + lottery/KBC, chain-forwards, work-from-home tasks, fake `.apk` (RTO challan / PM-Kisan), utility threats, group-invite pushes, embedded links|❌ rules|
|**UPI deep link** (`upi://pay?…`)|Parses payee ID, name, amount, note; flags refund/KYC bait, imitation names, high amounts, mandates|❌ rules|
|**Official-domain allowlist**|HTTPS + exact official host/subdomain is never flagged (lookalikes like `uidai.gov.in.evil.xyz` are not trusted)|safety net|
|**Report panel**|Shown on every scam verdict: 1930 helpline, cybercrime.gov.in, Sanchar Saathi (Chakshu), your bank|—|

Rule-based checks are heuristics, not trained models. A clean result is **not** a guarantee of safety.
Extra standalone modules (QR decoding, VirusTotal, screenshot clone check, IPFS, phonetic, Tranco, crt.sh) are
not wired into the UI or the trained model yet.

### One click

```bash
./run.sh          # Mac/Linux  — installs, trains (first run), starts backend, opens START.html
run.bat           # Windows    — same (written for Windows, not tested on a Windows machine)
```

Or just double-click `START.html` for browser-only demo mode (no install; URL scoring is heuristic there).

### Editing the web UI

`config.py` is the single source for brand/keyword/pattern lists. **Never hand-edit** `static/upi-config.js` or
`START.html` — they are generated:

```bash
make sync-js     # config.py  → static/upi-config.js
make build       # index.html + static/\* → START.html (also runs sync-js)
```

`tests/test\_js\_parity.py` fails if the browser rules drift from the Python ones.

### Why two feature sets?

SSL, HTML, DNS and hosting features only work when a site is **alive**. Phishing URLs from feeds are often already
taken down, so "unreachable" leaks the label and inflates accuracy without detecting anything. The **lexical** set
(URL string only) is the fair baseline and the default; `full` is there for comparison. Details: `docs/EVALUATION.md`.

### Evaluate honestly (do this before quoting any accuracy)

```bash
python collector.py --tranco-legit 500        # phishing feeds + legitimate negatives
python trainer.py  --raw data/raw\_urls.csv    # trains, saves models/ + data/test\_split.csv (held-out URLs)
python evaluate.py                            # vs Google Safe Browsing / VirusTotal (keys in .env), with 95% CIs
```

### Chrome extension (experimental)

`extension/` — warns before you use a confident phishing page; talks only to your local backend. See `extension/README.md`.

## Project Structure

```
upi-phish-detector/
├── collector.py             # Fetch phishing URLs from OpenPhish / PhishTank + manual seeds
├── feature\_extractor.py     # Extract 38 features: domain age, SSL, HTML similarity, OSINT, etc.
├── trainer.py                # Train Random Forest + Logistic Regression, compare, save model
├── predictor.py               # CLI tool: predict a single URL as phishing or legitimate
├── api.py                     # Flask API bridge — connects index.html to the trained model
├── dashboard.py                # Streamlit dashboard for live analysis (alternative to index.html)
├── index.html                  # Page STRUCTURE ONLY — no inline CSS or JS
├── static/
│   ├── style.css                  # ALL visual styling — colors, fonts, layout
│   ├── upi-config.js               # ALL brand/TLD/keyword lists for browser demo mode
│   ├── scoring.js                   # Heuristic feature scoring logic (demo mode only)
│   └── app.js                        # API calls, rendering, history, DOM events
├── config.py                    # All config: API keys, thresholds, UPI brand keywords
├── requirements.txt              # Python dependencies
├── setup.sh / setup.bat            # One-command bootstrap (Mac/Linux / Windows)
├── .env.example                     # Template for API keys — copy to .env, never commit .env
├── LICENSE                           # MIT License
├── PAPER.md                           # Symposium-ready research write-up
├── README.md                           # This file
├── data/
│   ├── sample\_urls.csv                 # Small committed dataset — repo works out of the box
│   ├── raw\_urls.csv                     # Generated by collector.py (gitignored)
│   └── features.csv                      # Generated by trainer.py (gitignored)
├── models/                                # Saved .pkl model files (gitignored, generated by trainer.py)
├── results/                                # Confusion matrix / ROC / feature importance plots (gitignored)
├── tests/
│   ├── test\_features.py                     # Tests for feature\_extractor.py ONLY
│   ├── test\_predictor.py                     # Tests for predictor.py ONLY
│   └── test\_collector.py                      # Tests for collector.py ONLY
└── .github/workflows/tests.yml                 # CI — runs the full test suite on every push
```

> \*\*Fault isolation:\*\* each file under `tests/` only tests the one Python file with
> the matching name. If `test\_predictor.py` fails, the bug is in `predictor.py` —
> you never need to check `feature\_extractor.py` or `collector.py` to debug it.

## Setup

### Option 0 — one click

`./run.sh` (Mac/Linux) or `run.bat` (Windows) — see **One click** above.

### Option A — setup script

```bash
git clone https://github.com/pr1yansh7/UPI-SMS\_phishing\_detector
cd UPI-SMS\_phishing\_detector

# Mac/Linux
chmod +x setup.sh \&\& ./setup.sh

# Windows
setup.bat
```

This creates a virtual environment, installs dependencies, sets up your `.env` file, and runs the test suite to confirm everything works — all in one step.

### Option B — Manual

```bash
# 1. Clone and install
git clone https://github.com/pr1yansh7/UPI-SMS\_phishing\_detector
cd UPI-SMS\_phishing\_detector
python -m venv venv
source venv/bin/activate        # Windows: venv\\Scripts\\activate
pip install -r requirements.txt

# 2. Configure API keys (optional — project works without these)
cp .env.example .env
# Edit .env and add your PhishTank / WhoisXML / Google Safe Browsing keys

# 3. Try it immediately with the committed sample dataset
python trainer.py --raw data/sample\_urls.csv

# 4. Or collect fresh data from live feeds
python collector.py
python trainer.py

# 5. Predict a URL
python predictor.py --url "http://phonpe-upi-verify.xyz/login"

# 6. Launch a dashboard (pick one)
python api.py \&\& open index.html      # standalone HTML, full ML predictions
streamlit run dashboard.py            # Streamlit alternative
```



## Features Extracted (38)

|Category|Count|Features|
|-|-|-|
|URL Structure|13|Length, dots, digit ratio, special chars, subdomain depth, IP usage, @ symbol, entropy, path depth, double-slash, non-standard port, sensitive query params, phish keyword count|
|Domain|7|Age, TLD type, brand-in-subdomain, brand-in-path, Levenshtein edit distance, homograph chars, punycode|
|SSL/TLS|4|Has HTTPS, cert age, self-signed, trusted CA|
|HTML Content|7|Form count, password fields, hidden fields, external resource ratio, UPI similarity score, HTTPS form mismatch, external favicon|
|Network|4|Redirect count, hosting country, ASN reputation, MX record presence|
|OSINT / Threat Intel|3|URL shortener detection, DNS TTL (fast-flux), Google Safe Browsing|

## Model Performance (measured on the 52-URL sample)

|Model|5-fold CV F1|Held-out test (11 samples)|
|-|-|-|
|Random Forest|0.978 ± 0.044|100% (too small to be meaningful)|
|Logistic Regression|0.938 ± 0.081|100% (too small to be meaningful)|

These come from the committed sample dataset only. Run `python collector.py \&\& python trainer.py`
on real feed data and update this table before quoting accuracy anywhere.

> \*\*Status note:\*\* the 39-feature vector feeds the ML model. SMS, QR, visual-similarity,
> VirusTotal, IPFS, phonetic, Tranco and CT-log modules are standalone analysers (not yet
> part of the trained feature vector).

## Research Write-up

See `PAPER.md` for the symposium-ready research paper.

## CNS Knowledge Applied

* **SSL/TLS**: Certificate validation, chain-of-trust analysis
* **Authentication**: Detecting fake login form harvesting
* **OSINT**: Using open threat intelligence feeds
* **Network Analysis**: IP geolocation, ASN lookup for hosting origin

## Testing

Each test file maps 1-to-1 to the source file it tests — run them individually to isolate a fault:

```bash
python -m pytest tests/test\_features.py -v   # tests feature\_extractor.py only
python -m pytest tests/test\_predictor.py -v  # tests predictor.py only
python -m pytest tests/test\_collector.py -v  # tests collector.py only
python -m pytest tests/test\_sms\_features.py tests/test\_whatsapp.py tests/test\_deeplink.py tests/test\_allowlist.py -v
python -m pytest tests/test\_js\_parity.py -v  # browser rules == Python rules (needs Node)
npm install \&\& python -m pytest tests/test\_ui.py -v   # headless click-through of START.html (optional)

python -m pytest tests/ -v                   # run everything
```

CI runs the full suite automatically on every push via `.github/workflows/tests.yml`.

## License

MIT — see `LICENSE`. Free to use, modify, and submit as part of your own coursework or portfolio.

