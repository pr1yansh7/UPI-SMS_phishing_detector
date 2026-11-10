# Contributing to UPI Phishing Detector

## Where to make each type of change

This project uses strict fault isolation — every concern lives in exactly
one file. Before editing anything, use this map to find the right file.

### Adding a new feature

**Step 1 — Write the function in the right group file**

| Feature type | File to edit |
|---|---|
| URL structure (length, entropy, ports…) | `features/url_features.py` |
| Domain intelligence (TLD, brand, edit distance…) | `features/domain_features.py` |
| SSL / TLS certificate | `features/ssl_features.py` |
| HTML page content | `features/html_features.py` |
| Network (redirects, ASN, MX…) | `features/network_features.py` |
| OSINT / threat intelligence | `features/osint_features.py` |

**Step 2 — Export it from the package**

Open `features/__init__.py` and add the function to both the import block
and the `__all__` list.

**Step 3 — Wire it into the feature dict**

Open `feature_extractor.py` and add one line to the correct group section
in `extract_features()`:
```python
"my_new_feature": my_new_feature(url),
```

**Step 4 — Add the column name to config**

Open `config.py` and add `"my_new_feature"` to `FEATURE_COLUMNS` in the
correct group comment block.

**Step 5 — Define its suspiciousness threshold**

Open `thresholds.py` and:
- Add the name to `SUSPICIOUS_HIGH` (high value = bad) or `SUSPICIOUS_LOW`
  (low value = bad)
- Add a threshold entry to `FEATURE_WARN_THRESHOLDS` if it's numeric

**Step 6 — Add it to the browser demo**

Open `static/upi-config.js` if the feature needs a new lookup list
(e.g. a new brand name or TLD). Open `static/scoring.js` and add the
heuristic computation inside `computeFeatures()`.

**Step 7 — Write a test**

Add a test class to the matching test file:

| Feature file | Test file |
|---|---|
| `features/url_features.py` | `tests/test_features.py` |
| `features/domain_features.py` | `tests/test_features.py` |
| `features/ssl_features.py` | `tests/test_features.py` |
| `features/html_features.py` | `tests/test_features.py` |
| `features/network_features.py` | `tests/test_features.py` |
| `features/osint_features.py` | `tests/test_features.py` |

**Step 8 — Retrain the model**

```bash
python trainer.py --force-extract
```

---

### Changing a suspicious threshold

Open `thresholds.py` only. Change the value in `FEATURE_WARN_THRESHOLDS`.
Do not touch any feature file.

### Changing a brand name or keyword list

Edit `config.py` ONLY, then run `make sync-js` — `static/upi-config.js` is generated from it
(never edit that file by hand). `tests/test_js_parity.py` fails if they drift.

### Changing the dashboard appearance

Open `static/style.css` only. Do not touch `index.html` unless you are
adding or removing a page element.

### Fixing a bug in CLI output

Open `predictor.py` only.

### Fixing a bug in the Flask API

Open `api.py` only.

---

## Running tests before submitting

```bash
# Run all tests
python -m pytest tests/ -v

# Run only the test file relevant to your change
python -m pytest tests/test_features.py -v
python -m pytest tests/test_predictor.py -v
python -m pytest tests/test_collector.py -v
python -m pytest tests/test_trainer.py -v
python -m pytest tests/test_api.py -v
```

All tests must pass before pushing.

---

## Code style

- Python: follow PEP 8. Functions have a one-line docstring minimum.
- JavaScript: use `const`/`let`, no `var`. One responsibility per function.
- Every new feature function must have a docstring explaining:
  - What it measures
  - Why it's a phishing signal
  - What value is suspicious and why
  - What -1 means (if the function can return -1)

### Scam-message rules (SMS / WhatsApp / UPI link)
Python is the reference: `features/sms_features.py`, `whatsapp_features.py`, `deeplink_features.py`.
`static/messages.js` is an exact port — change both, then run `python -m pytest tests/test_js_parity.py`.
