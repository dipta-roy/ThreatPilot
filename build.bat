@echo off
if "%~1"=="" (
    echo Usage: build.bat ^<version^>
    echo Example: build.bat 0.6.0
    exit /b 1
)

echo Updating versions in source files...
python update_version.py %~1

echo Installing Python build dependencies...
pip install cx_Freeze Pillow

echo Building MSI Package...
python msi-builder.py bdist_msi

echo Build finished! Check the 'dist' directory for the generated .msi file.
pause
