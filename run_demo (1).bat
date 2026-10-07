@echo off
echo ========================================================
echo  SHIELD-AI: Security Alert Summarizer (3,000 Alerts)
echo ========================================================
echo.
echo [1] Running End-to-End Pipeline & Generating Shift Handover Report...
python main.py
echo.
echo [2] Starting Interactive Web Dashboard on http://localhost:8000 ...
python run_server.py
pause
