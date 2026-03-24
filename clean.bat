@echo off
setlocal
echo ========================================================
echo ThreatPilot Workspace Cleanup Utility
echo ========================================================

echo.
echo [1/4] Removing Python cache directories (__pycache__)...
for /d /r . %%d in (__pycache__) do @if exist "%%d" (
    echo   - Removing: %%d
    rd /s /q "%%d"
)

echo [2/4] Deleting compiled Python files (*.pyc, *.pyo)...
del /s /q *.pyc >nul 2>&1
del /s /q *.pyo >nul 2>&1
del /s /q *.pyd >nul 2>&1

echo [3/4] Removing test and metadata caches (.pytest_cache, .DS_Store)...
if exist ".pytest_cache" rd /s /q ".pytest_cache"
del /s /q .DS_Store >nul 2>&1

echo [4/4] Removing virtual environments (.venv, venv)...
if exist ".venv" (
    echo   - Removing: .venv
    rd /s /q ".venv"
)
if exist "venv" (
    echo   - Removing: venv
    rd /s /q "venv"
)
if exist "env" (
    echo   - Removing: env
    rd /s /q "env"
)

echo.
echo ========================================================
echo Cleanup Complete. Project workspace is now clean.
echo ========================================================
pause
endlocal
