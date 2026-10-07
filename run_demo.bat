@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ============================================================
    echo [ERROR] Python was not found in your system PATH.
    echo Please ensure Python 3.10 or higher is installed and in PATH.
    echo ============================================================
    pause
    exit /b 1
)

:menu
cls
echo ============================================================
echo   SYNAPSE-SOC : LIVE STREAMING DETECTOR
echo   Multi-source AI detection, 7-phase streaming pipeline
echo ============================================================
echo.
echo Select an execution mode:
echo   [1] Run 3-Minute Live Attack Simulation Demo
echo   [2] Run Replay Mode - recorded real attacker events
echo   [3] Run Safe FIM Ransomware Harness
echo   [4] Launch Live Streaming Terminal Dashboard
echo   [5] Launch FastAPI Web SOC Console - http://localhost:8000
echo   [6] Run Comprehensive Test Suite (Unit Tests)
echo   [7] Run Telemetry Sources Health Check Diagnostics
echo   [0] Exit
echo.
set /p choice=Enter choice: 

if "%choice%"=="1" goto demo
if "%choice%"=="2" goto replay
if "%choice%"=="3" goto fim
if "%choice%"=="4" goto dashboard
if "%choice%"=="5" goto web
if "%choice%"=="6" goto tests
if "%choice%"=="7" goto health
if "%choice%"=="0" goto end
echo Invalid choice. Please try again.
pause
goto menu

:demo
if not exist demo_attack_simulation.py (
    echo [ERROR] Script demo_attack_simulation.py not found in %CD%
    pause
    goto menu
)
python demo_attack_simulation.py
goto done

:replay
if not exist replay_mode.py (
    echo [ERROR] Script replay_mode.py not found in %CD%
    pause
    goto menu
)
python replay_mode.py --dataset data/captured_attacks.json --delay 0.5
goto done

:fim
if not exist test_fim_harness.py (
    echo [ERROR] Script test_fim_harness.py not found in %CD%
    pause
    goto menu
)
python test_fim_harness.py
goto done

:dashboard
if not exist live_dashboard.py (
    echo [ERROR] Script live_dashboard.py not found in %CD%
    pause
    goto menu
)
python live_dashboard.py
goto done

:web
if not exist run_server.py (
    echo [ERROR] Script run_server.py not found in %CD%
    pause
    goto menu
)
echo Opening http://localhost:8000 in your browser...
start http://localhost:8000
python run_server.py
goto done

:tests
if not exist run_tests.py (
    echo [ERROR] Script run_tests.py not found in %CD%
    pause
    goto menu
)
python run_tests.py
goto done

:health
if not exist health_check.py (
    echo [ERROR] Script health_check.py not found in %CD%
    pause
    goto menu
)
python health_check.py
goto done

:done
echo.
echo Press any key to return to the main menu...
pause >nul
goto menu

:end
endlocal