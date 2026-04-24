@echo off
title Agentless Scanner - Celery Worker

echo =========================================
echo Starting Agentless Scanner Celery Worker
echo =========================================
echo.
echo Broker: SQLite (Windows-compatible, no Redis required)
echo To use Redis, set REDIS_URL environment variable
echo.

REM --------------------------------------------------
REM STEP 1: Detect Python from local virtual environment
REM --------------------------------------------------

set "PROJECT_ROOT=%~dp0"
set "VENV_PYTHON=%PROJECT_ROOT%.venv\Scripts\python.exe"
set "SYSTEM_PYTHON=python"

if exist "%VENV_PYTHON%" (
    set "PYTHON_EXE=%VENV_PYTHON%"
    echo Using Virtual Environment Python:
    echo %PYTHON_EXE%
) else (
    set "PYTHON_EXE=%SYSTEM_PYTHON%"
    echo Virtual environment Python not found.
    echo Falling back to system Python...
)

echo.

REM --------------------------------------------------
REM STEP 2: Verify Python
REM --------------------------------------------------

"%PYTHON_EXE%" --version >nul 2>&1

if errorlevel 1 (
    echo ERROR: Python is not installed or not accessible
    echo.
    echo Fix:
    echo 1. Ensure Python 3.11 is installed
    echo 2. Ensure .venv exists
    echo 3. Activate venv:
    echo    .venv\Scripts\activate
    echo 4. Install requirements:
    echo    pip install -r backend\requirements.txt
    pause
    exit /b 1
)

echo Python verification successful:
"%PYTHON_EXE%" --version
echo.

REM --------------------------------------------------
REM STEP 3: Check required dependencies
REM --------------------------------------------------

echo Checking Celery dependencies...

"%PYTHON_EXE%" -c "import celery, sqlalchemy" >nul 2>&1

if errorlevel 1 (
    echo.
    echo Missing dependencies. Installing...
    echo.
    "%PYTHON_EXE%" -m pip install celery sqlalchemy
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo Dependencies verified.
echo.

REM --------------------------------------------------
REM STEP 4: Move to backend directory
REM --------------------------------------------------

cd /d "%PROJECT_ROOT%backend"

if errorlevel 1 (
    echo ERROR: Could not enter backend directory
    pause
    exit /b 1
)

echo Current directory: %CD%
echo.

REM --------------------------------------------------
REM STEP 5: Start Celery Worker
REM --------------------------------------------------

echo =========================================
echo Starting Celery Worker
echo =========================================
echo.
echo Using SQLite broker (no external service needed)
echo.
echo Press Ctrl+C to stop worker
echo =========================================
echo.

REM Windows-safe Celery start using solo pool (SQLite compatible)
"%PYTHON_EXE%" -m celery -A celery_worker.celery_app worker --loglevel=info -P solo

echo.
echo Celery worker stopped.
pause