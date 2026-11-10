@echo off
REM setup.bat — One-command project bootstrap for Windows.
REM
REM What this does, step by step (stops immediately if any step fails,
REM so you know exactly which part broke):
REM   1. Check Python version
REM   2. Create a virtual environment
REM   3. Install dependencies
REM   4. Copy .env.example to .env (if missing)
REM   5. Run the test suite to confirm everything works
REM
REM Usage:
REM   setup.bat

echo ============================================================
echo   UPI Phishing Detector - Setup
echo ============================================================

echo.
echo [1/5] Checking Python version...
python --version
if errorlevel 1 (
    echo   FAILED: Python not found. Install Python 3.10+ and re-run.
    exit /b 1
)
echo   OK

echo.
echo [2/5] Creating virtual environment (venv\)...
if exist venv (
    echo   venv\ already exists, skipping creation
) else (
    python -m venv venv
    echo   Created venv\
)
call venv\Scripts\activate.bat
echo   Activated venv

echo.
echo [3/5] Installing dependencies from requirements.txt...
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q
if errorlevel 1 (
    echo   FAILED: dependency installation error. Check requirements.txt.
    exit /b 1
)
echo   Dependencies installed

echo.
echo [4/5] Setting up .env file...
if exist .env (
    echo   .env already exists, skipping
) else (
    copy .env.example .env
    echo   Created .env from .env.example
    echo   Edit .env and add your API keys (optional - project works without them^)
)

echo.
echo [5/5] Running test suite to confirm everything works...
python -m pytest tests\ -q
if errorlevel 1 (
    echo   FAILED: some tests did not pass. Check tests\test_features.py output above.
    exit /b 1
)
echo   All tests passed

echo.
echo ============================================================
echo   Setup complete!
echo ============================================================
echo.
echo Next steps:
echo   1. (Optional) Add API keys to .env for full WHOIS/Safe Browsing features
echo   2. Collect data:    python collector.py
echo   3. Train model:     python trainer.py --raw data\sample_urls.csv
echo   4. Start API:       python api.py
echo   5. Open dashboard:  start index.html   (or: streamlit run dashboard.py)
echo.
