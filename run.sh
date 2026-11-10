#!/usr/bin/env bash
# run.sh — one command: install → train (first run) → start backend → open the dashboard.
#   chmod +x run.sh && ./run.sh        (Ctrl+C stops the backend)
set -e
cd "$(dirname "$0")"
PY=python3; command -v "$PY" >/dev/null 2>&1 || PY=python

if [ ! -d venv ]; then echo "[1/4] Creating virtual environment…"; "$PY" -m venv venv; fi
# shellcheck disable=SC1091
source venv/bin/activate

echo "[2/4] Installing dependencies (first run takes a few minutes)…"
pip install -q --upgrade pip
pip install -q -r requirements-core.txt
[ -f .env ] || cp .env.example .env

if [ ! -f models/best_model.pkl ]; then
  echo "[3/4] Training on data/sample_urls.csv (a few seconds, no network needed)…"
  python trainer.py --raw data/sample_urls.csv
else
  echo "[3/4] Trained model found — skipping training."
fi

echo "[4/4] Starting backend on http://localhost:5050 and opening the dashboard…"
python api.py &
API_PID=$!
trap 'kill $API_PID 2>/dev/null' EXIT INT TERM
sleep 3
OPEN=xdg-open; command -v open >/dev/null 2>&1 && OPEN=open
"$OPEN" "$PWD/START.html" >/dev/null 2>&1 || echo "Could not auto-open a browser — open START.html manually."
echo "Backend running. Press Ctrl+C to stop."
wait $API_PID
