@echo off
REM run.bat - one click: install, train (first run), start backend, open the dashboard.
REM NOTE: written for Windows but not tested on a Windows machine.
setlocal
cd /d "%~dp0"
where python >nul 2>nul || (echo Python 3.10+ not found. Install it from python.org and re-run. & pause & exit /b 1)

if not exist venv ( echo [1/4] Creating virtual environment... & python -m venv venv )
call venv\Scripts\activate.bat

echo [2/4] Installing dependencies (first run takes a few minutes)...
python -m pip install -q --upgrade pip
pip install -q -r requirements-core.txt
if errorlevel 1 ( echo Dependency install failed. & pause & exit /b 1 )
if not exist .env copy .env.example .env >nul

if not exist models\best_model.pkl (
  echo [3/4] Training on data\sample_urls.csv ^(a few seconds^)...
  python trainer.py --raw data\sample_urls.csv
  if errorlevel 1 ( echo Training failed. & pause & exit /b 1 )
) else (
  echo [3/4] Trained model found - skipping training.
)

echo [4/4] Starting backend and opening the dashboard...
start "UPI Phishing Detector API" cmd /k python api.py
timeout /t 4 >nul
start "" "%~dp0START.html"
echo The backend runs in the other window - close that window to stop it.
endlocal
