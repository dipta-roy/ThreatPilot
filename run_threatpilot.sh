#!/usr/bin/env bash

# ThreatPilot Launcher Script for Mac and Linux
# This script manages the Python virtual environment and dependencies 
# before launching the application.

VENV_DIR=".venv"

echo "[1/3] Checking Virtual Environment..."
if [ ! -d "$VENV_DIR" ]; then
    echo "[!] Virtual environment not found. Creating one now..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment. Please ensure python3-venv is installed."
        exit 1
    fi
    echo "[+] Virtual environment created successfully."
else
    echo "[+] Existing virtual environment found."
fi

echo "[2/3] Updating Dependencies..."
source "$VENV_DIR/bin/activate"
python3 -m pip install --upgrade pip
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install requirements. Please check your internet connection or requirements.txt."
    exit 1
fi
echo "[+] Dependencies are up to date."

echo "[3/4] Building Web Designer Interface..."
cd designer || exit 1
npm install --legacy-peer-deps
npm run build
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to build the web designer interface. Please ensure Node.js is installed."
    exit 1
fi
cd ..
echo "[+] Web Designer Interface built successfully."

echo "[4/4] Launching ThreatPilot..."
echo "[!] Starting GUI in background..."
python3 main.py &

deactivate
exit 0
