@echo off
echo ========================================================
echo Building ThreatPilot Architecture Designer Web Frontend
echo ========================================================
echo.

rem Navigate to the designer directory relative to this script
cd %~dp0designer

echo [1/3] Checking and installing dependencies...
call npm install

echo.
echo [2/3] Running TypeScript compilation checks...
call npx tsc
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] TypeScript compilation failed. Please resolve the errors above.
    cd %~dp0
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Compiling and bundling production static assets...
call npx vite build
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Vite build failed.
    cd %~dp0
    pause
    exit /b %errorlevel%
)

echo.
echo ========================================================
echo [SUCCESS] Frontend build completed! Output saved in designer/dist.
echo ========================================================
cd %~dp0
pause
