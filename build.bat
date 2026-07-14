@echo off
if "%~1"=="" (
    echo Usage: build.bat ^<version^>
    echo Example: build.bat 0.6.0
    exit /b 1
)

set VENV_DIR=.venv

if not exist %VENV_DIR% (
    echo [ERROR] Virtual environment not found. Please run run_threatpilot.bat first to initialize it.
    pause
    exit /b 1
)

echo Activating virtual environment...
call %VENV_DIR%\Scripts\activate

echo Updating versions in source files...
%VENV_DIR%\Scripts\python.exe update_version.py %~1

echo Installing Python build dependencies...
%VENV_DIR%\Scripts\python.exe -m pip install -r requirements.txt cx_Freeze Pillow

echo Installing PyTorch CPU version for packaging...
%VENV_DIR%\Scripts\python.exe -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu --no-cache-dir

echo Building MSI Package...
%VENV_DIR%\Scripts\python.exe msi-builder.py bdist_msi

echo Deactivating virtual environment...
call deactivate

echo Build finished! Check the 'dist' directory for the generated .msi file.
pause
