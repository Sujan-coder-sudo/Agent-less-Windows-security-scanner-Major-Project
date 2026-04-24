$ErrorActionPreference = 'Stop'

Write-Host '==================================================' -ForegroundColor Cyan
Write-Host ' Agent-less Scanner - Environment Recovery Script ' -ForegroundColor Cyan
Write-Host '==================================================' -ForegroundColor Cyan

Write-Host '`n[1] Detecting global Python version...' -ForegroundColor Yellow
$pyVersion = py --version 2>&1
Write-Host "Detected: $pyVersion"

$targetPython = '3.11'
$py311Check = py -3.11 --version 2>&1
if ($py311Check -match 'Python 3.11') {
    Write-Host 'Python 3.11 is available on this system.' -ForegroundColor Green
} else {
    Write-Host 'CRITICAL ERROR: Python 3.11 is not installed or not in PATH.' -ForegroundColor Red
    Write-Host 'Please install Python 3.11.x from python.org before continuing.' -ForegroundColor Red
    exit 1
}

$venvPath = Join-Path $PWD '.venv'
Write-Host "`n[2] Checking for existing virtual environment at $venvPath..." -ForegroundColor Yellow
if (Test-Path $venvPath) {
    Write-Host 'Broken .venv detected. Removing...' -ForegroundColor Red
    Remove-Item -Path $venvPath -Recurse -Force
    Write-Host 'Successfully removed old .venv.' -ForegroundColor Green
} else {
    Write-Host 'No existing .venv found.' -ForegroundColor Green
}

Write-Host '`n[3] Creating new virtual environment using Python 3.11...' -ForegroundColor Yellow
py -3.11 -m venv .venv
if (Test-Path $venvPath) {
    Write-Host 'Successfully created new .venv.' -ForegroundColor Green
} else {
    Write-Host 'Failed to create .venv.' -ForegroundColor Red
    exit 1
}

Write-Host '`n[4] Verifying venv Python interpreter...' -ForegroundColor Yellow
$venvPython = Join-Path $venvPath 'Scripts\python.exe'
$venvVersion = & $venvPython --version
Write-Host "Venv Python Version: $venvVersion" -ForegroundColor Green
if (-not ($venvVersion -match '3.11')) {
    Write-Host 'ERROR: Venv did not create with Python 3.11!' -ForegroundColor Red
    exit 1
}

Write-Host '`n[5] Upgrading core packaging tools...' -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip setuptools wheel
Write-Host 'Core tools upgraded successfully.' -ForegroundColor Green

$reqPath = Join-Path $PWD 'requirements.txt'
Write-Host '`n[6] Installing dependencies from requirements.txt...' -ForegroundColor Yellow
& $venvPython -m pip install -r $reqPath

Write-Host '`n[7] Validating Flask and SQLAlchemy initialization...' -ForegroundColor Yellow

$validationFile = Join-Path $PWD 'validate_env.py'
$validationResult = & $venvPython $validationFile
Write-Host $validationResult

if ($LASTEXITCODE -eq 0) {
    Write-Host ''
    Write-Host '==================================================' -ForegroundColor Cyan
    Write-Host ' ENVIRONMENT RECOVERY COMPLETE ' -ForegroundColor Green
    Write-Host ' Python 3.11 is now active.' -ForegroundColor Green
    Write-Host ' All dependencies installed.' -ForegroundColor Green
    Write-Host ' Database initialized successfully.' -ForegroundColor Green
    Write-Host '==================================================' -ForegroundColor Cyan
} else {
    Write-Host ''
    Write-Host 'ENVIRONMENT RECOVERY FAILED DURING VALIDATION.' -ForegroundColor Red
}

Remove-Item -Path $validationFile -Force
