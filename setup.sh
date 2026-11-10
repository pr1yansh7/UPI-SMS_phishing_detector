#!/usr/bin/env bash
# setup.sh — One-command project bootstrap.
#
# What this does, step by step (fails loudly at any step so you know
# exactly which part broke):
#   1. Check Python version
#   2. Create a virtual environment
#   3. Install dependencies
#   4. Copy .env.example → .env (if missing)
#   5. Run the test suite to confirm everything works
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh

set -e   # exit immediately if any command fails

echo "════════════════════════════════════════════════════════"
echo "  UPI Phishing Detector — Setup"
echo "════════════════════════════════════════════════════════"

# ── 1. Check Python version ──────────────────────────────────
echo ""
echo "[1/5] Checking Python version…"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "      Found Python $PYTHON_VERSION"
REQUIRED="3.10"
if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)"; then
  echo "      ❌ Python 3.10+ required. Please upgrade Python and re-run."
  exit 1
fi
echo "      ✅ Python version OK"

# ── 2. Create virtual environment ────────────────────────────
echo ""
echo "[2/5] Creating virtual environment (venv/)…"
if [ -d "venv" ]; then
  echo "      venv/ already exists — skipping creation"
else
  python3 -m venv venv
  echo "      ✅ Created venv/"
fi

# shellcheck disable=SC1091
source venv/bin/activate
echo "      ✅ Activated venv"

# ── 3. Install dependencies ──────────────────────────────────
echo ""
echo "[3/5] Installing dependencies from requirements.txt…"
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "      ✅ Dependencies installed"

# ── 4. Set up .env file ──────────────────────────────────────
echo ""
echo "[4/5] Setting up .env file…"
if [ -f ".env" ]; then
  echo "      .env already exists — skipping"
else
  cp .env.example .env
  echo "      ✅ Created .env from .env.example"
  echo "      ⚠  Edit .env and add your API keys (optional — project works without them)"
fi

# ── 5. Run test suite ────────────────────────────────────────
echo ""
echo "[5/5] Running test suite to confirm everything works…"
python -m pytest tests/ -q
echo "      ✅ All tests passed"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Setup complete!"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. (Optional) Add API keys to .env for full WHOIS/Safe Browsing features"
echo "  2. Collect data:    python collector.py"
echo "  3. Train model:     python trainer.py --raw data/sample_urls.csv"
echo "  4. Start API:       python api.py"
echo "  5. Open dashboard:  open index.html   (or: streamlit run dashboard.py)"
echo ""
