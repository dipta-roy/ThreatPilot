@echo off
setlocal

echo ========================================================
echo Launching ThreatPilot Build Automation UI
echo ========================================================

set VENV_DIR=.venv

echo [1/3] Checking Virtual Environment...
if not exist %VENV_DIR% (
    echo [!] Virtual environment not found. Creating one now...
    python -m venv %VENV_DIR%
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment. Please ensure Python is installed and in your PATH.
        pause
        exit /b 1
    )
    echo [+] Virtual environment created successfully.
) else (
    echo [+] Existing virtual environment found.
)

echo [2/3] Checking Dependencies...
call %VENV_DIR%\Scripts\activate
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt PySide6 >nul 2>&1

echo [3/3] Launching UI...
python build_automation_ui.py

call deactivate
endlocal
