@echo off
REM Launch MultiHost SSH (development mode, requires Python + dependencies installed)
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not on PATH. Install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

python -c "import paramiko" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Installing dependencies from requirements.txt...
    python -m pip install -r requirements.txt
)

python multi_host_executor.py
endlocal
