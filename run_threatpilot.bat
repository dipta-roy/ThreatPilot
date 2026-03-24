@echo off
setlocal

:: ThreatPilot Launcher Script
:: This script manages the Python virtual environment and dependencies 
:: before launching the application.

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

echo [2/3] Updating Dependencies...
call %VENV_DIR%\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install requirements. Please check your internet connection or requirements.txt.
    pause
    exit /b 1
)
echo [+] Dependencies are up to date.

echo [3/3] Launching ThreatPilot...
echo [!] Starting GUI. Please wait...
python main.py

:: If main.py crashes or exits, keep window open if it failed
if errorlevel 1 (
    echo [ERROR] ThreatPilot exited with an error.
    pause
)

deactivate
endlocal
