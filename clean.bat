@echo off
setlocal
echo ========================================================
echo ThreatPilot Workspace Cleanup Utility
echo ========================================================

echo.
echo [1/6] Removing Python cache directories (__pycache__)...
for /d /r . %%d in (__pycache__) do @if exist "%%d" (
    echo   - Removing: %%d
    rd /s /q "%%d"
)

echo [2/6] Deleting compiled Python files (*.pyc, *.pyo)...
del /s /q *.pyc >nul 2>&1
del /s /q *.pyo >nul 2>&1
del /s /q *.pyd >nul 2>&1

echo [3/6] Removing test and metadata caches (.pytest_cache, .DS_Store)...
if exist ".pytest_cache" rd /s /q ".pytest_cache"
del /s /q .DS_Store >nul 2>&1

echo [4/6] Removing build and distribution outputs (build, egg-info)...
if exist "build" (
    echo   - Removing: build
    rd /s /q "build"
)
if exist "ThreatPilot.egg-info" (
    echo   - Removing: ThreatPilot.egg-info
    rd /s /q "ThreatPilot.egg-info"
)

echo [5/6] Removing virtual environments (.venv, venv)...
if "%SKIP_VENV_CLEAN%"=="1" (
    echo   - Skipping virtual environment removal because SKIP_VENV_CLEAN=1
) else (
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
)

echo.
echo [6/6] Removing Node dependencies (node_modules)...
if exist "designer\node_modules" (
    echo   - Removing: designer\node_modules
    rd /s /q "designer\node_modules"
)

echo.
echo ========================================================
echo Cleanup Complete. Project workspace is now clean.
echo ========================================================
pause
endlocal
