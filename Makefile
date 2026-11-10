# Makefile — shortcut commands for the UPI Phishing Detector.
#
# Usage:
#   make install       install all dependencies
#   make test          run all tests
#   make test-fast     run tests without live HTTP (much faster)
#   make collect       fetch phishing URLs from live feeds
#   make train         train the ML model
#   make predict URL=http://evil.xyz/login
#   make api           start the Flask API server
#   make dashboard     start the Streamlit dashboard
#   make lint          check code style
#   make clean         remove generated files (models, results, data caches)
#   make zip           package the project into a distributable ZIP

PYTHON   = python3
PIP      = pip3
VENV     = venv
MODEL    = models/best_model.pkl
RAW_DATA = data/raw_urls.csv
SAMPLE   = data/sample_urls.csv

# ─── Setup ────────────────────────────────────────────────────────────────────

.PHONY: install
install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env — add your API keys"; fi
	@echo "✅  Setup complete. Activate with: source $(VENV)/bin/activate"

# ─── Testing ──────────────────────────────────────────────────────────────────

.PHONY: test
test:
	$(PYTHON) -m pytest tests/ -v

.PHONY: test-fast
test-fast:
	$(PYTHON) -m pytest tests/test_features.py tests/test_predictor.py \
	          tests/test_collector.py tests/test_trainer.py tests/test_api.py \
	          -v -k "not legit_url_signals and not shortener_url_signals"

.PHONY: test-features
test-features:
	$(PYTHON) -m pytest tests/test_features.py -v

.PHONY: test-predictor
test-predictor:
	$(PYTHON) -m pytest tests/test_predictor.py -v

.PHONY: test-collector
test-collector:
	$(PYTHON) -m pytest tests/test_collector.py -v

.PHONY: test-trainer
test-trainer:
	$(PYTHON) -m pytest tests/test_trainer.py -v

.PHONY: test-api
test-api:
	$(PYTHON) -m pytest tests/test_api.py -v

# ─── Data & Training ──────────────────────────────────────────────────────────

.PHONY: collect
collect:
	$(PYTHON) collector.py

.PHONY: train
train:
	@if [ -f $(RAW_DATA) ]; then \
	  $(PYTHON) trainer.py; \
	else \
	  echo "No live data found — training on sample dataset"; \
	  $(PYTHON) trainer.py --raw $(SAMPLE); \
	fi

.PHONY: train-sample
train-sample:
	$(PYTHON) trainer.py --raw $(SAMPLE)

.PHONY: retrain-features
retrain-features:
	$(PYTHON) trainer.py --force-extract

# ─── Prediction ───────────────────────────────────────────────────────────────

.PHONY: predict
predict:
ifndef URL
	$(error Usage: make predict URL=http://evil.xyz/login)
endif
	$(PYTHON) predictor.py --url "$(URL)"

.PHONY: predict-fast
predict-fast:
ifndef URL
	$(error Usage: make predict-fast URL=http://evil.xyz/login)
endif
	$(PYTHON) predictor.py --url "$(URL)" --no-html

# ─── Servers ──────────────────────────────────────────────────────────────────

.PHONY: api
api:
	$(PYTHON) api.py

.PHONY: dashboard
dashboard:
	streamlit run dashboard.py

# ─── Code quality ─────────────────────────────────────────────────────────────

.PHONY: lint
lint:
	$(PYTHON) -m flake8 *.py features/ tests/ --max-line-length=100 \
	          --ignore=E501,W503 || true

.PHONY: compile-check
compile-check:
	$(PYTHON) -c "\
	import py_compile, glob; \
	files = glob.glob('*.py') + glob.glob('features/*.py') + glob.glob('tests/*.py'); \
	[py_compile.compile(f, doraise=True) for f in sorted(files)]; \
	print('All files compile OK') \
	"

# ─── Cleanup ──────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	rm -rf models/*.pkl
	rm -rf results/*.png results/*.csv
	rm -rf data/features.csv
	rm -rf __pycache__ features/__pycache__ tests/__pycache__
	rm -rf .pytest_cache
	@echo "✅  Cleaned generated files"

.PHONY: clean-all
clean-all: clean
	rm -rf $(VENV)
	rm -rf data/raw_urls.csv
	@echo "✅  Cleaned everything including venv and raw data"

# ─── Packaging ────────────────────────────────────────────────────────────────

.PHONY: zip
zip: clean
	cd .. && zip -r upi-phish-detector.zip upi-phish-detector/ \
	  --exclude "*/\.*" \
	  --exclude "*/__pycache__/*" \
	  --exclude "*/.pytest_cache/*" \
	  --exclude "*/venv/*"
	@echo "✅  Created ../upi-phish-detector.zip"

.PHONY: sms
sms:
ifndef TEXT
	$(error Usage: make sms TEXT="Your Aadhaar will be blocked. Click http://evil.xyz")
endif
	$(PYTHON) sms_predictor.py --text "$(TEXT)"

.PHONY: sms-interactive
sms-interactive:
	$(PYTHON) sms_predictor.py --interactive

.PHONY: retrain
retrain:
	$(PYTHON) retrain_pipeline.py --now

.PHONY: retrain-dry
retrain-dry:
	$(PYTHON) retrain_pipeline.py --dry-run

.PHONY: retrain-scheduler
retrain-scheduler:
	$(PYTHON) retrain_pipeline.py

.PHONY: sync-js build run test-js
sync-js:            ## regenerate static/upi-config.js from config.py
	$(PYTHON) tools/sync_js_config.py

build: sync-js      ## regenerate START.html from index.html + static/*
	$(PYTHON) build_start.py

run:                ## install, train (first run), start backend, open dashboard
	./run.sh

test-js:
	$(PYTHON) -m pytest tests/test_js_parity.py -v

.PHONY: collect-balanced train-full evaluate test-ext
collect-balanced:   ## phishing feeds + 500 legitimate domains from Tranco
	$(PYTHON) collector.py --tranco-legit 500

train-full:         ## all 39 features (slow, live network) — see docs/EVALUATION.md for why lexical is the default
	$(PYTHON) trainer.py --raw $(RAW_DATA) --feature-set full

evaluate:           ## compare against Google Safe Browsing / VirusTotal on held-out URLs
	$(PYTHON) evaluate.py

test-ext:
	$(PYTHON) -m pytest tests/test_extension.py -v
