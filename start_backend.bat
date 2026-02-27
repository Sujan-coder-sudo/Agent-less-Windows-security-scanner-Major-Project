@echo off
REM Start the Agentless Scanner Backend API Server
echo Starting Agentless Scanner Backend...
echo.

set "PYTHON_EXE=python"

if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
)

REM Check if Python is installed
%PYTHON_EXE% --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Change to project directory
cd /d "%~dp0"

REM Clear Python cache to ensure fresh code loads
echo Clearing Python cache files...
%PYTHON_EXE% -c "import os, shutil; [shutil.rmtree(os.path.join(root, '__pycache__'), ignore_errors=True) for root, dirs, files in os.walk('backend') if '__pycache__' in dirs]"

REM Change to backend directory
cd backend

echo.
echo =========================================
echo Starting Flask server on http://localhost:5000
echo.
echo CORS is configured for:
echo   - http://127.0.0.1:5500
echo   - http://localhost:5500
echo.
echo Press Ctrl+C to stop the server
echo IMPORTANT: When prompted "Terminate batch job (Y/N)?" type N to keep the server running.
echo =========================================
echo.

REM Start the Flask application
%PYTHON_EXE% app.py

pause
