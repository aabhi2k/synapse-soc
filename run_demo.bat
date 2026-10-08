@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set PYTHONUTF8=1

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH.
    pause
    exit /b 1
)

:menu
cls
echo ============================================================
echo   SYNAPSE-SOC : LIVE STREAMING DETECTOR
echo ============================================================
echo.
echo   [1] 3-Minute Live Attack Simulation Demo
echo   [2] Replay Mode - recorded attacker events
echo   [3] Safe FIM Ransomware Harness
echo   [4] Live Streaming Terminal Dashboard
echo   [5] FastAPI Web SOC Console at http://localhost:8000
echo   [6] Comprehensive Test Suite
echo   [0] Exit
echo.
set "choice="
set /p "choice=Enter choice: "

if "%choice%"=="1" call :run demo_attack_simulation.py
if "%choice%"=="2" call :run replay_mode.py
if "%choice%"=="3" call :run test_fim_harness.py
if "%choice%"=="4" call :run main.py --live
if "%choice%"=="5" call :run main.py --web
if "%choice%"=="6" call :tests
if "%choice%"=="0" goto end
goto menu

:run
if not exist "%~1" (
    echo.
    echo [ERROR] Missing file: %~1
    echo         Looked in: %CD%
    pause
    exit /b 1
)
python %*
echo.
echo [exit code %errorlevel%]
pause
exit /b 0

:tests
if not exist "tests" (
    echo.
    echo [ERROR] Missing folder: tests
    pause
    exit /b 1
)
python -m unittest discover -s tests -v
echo.
echo [exit code %errorlevel%]
pause
exit /b 0

:end
endlocal