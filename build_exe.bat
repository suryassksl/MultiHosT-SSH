@echo off
REM Build a standalone Windows executable with PyInstaller
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not on PATH. Install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

python -m pip install --upgrade pyinstaller paramiko openpyxl
if errorlevel 1 goto :fail

REM Build using the spec file (one-file, windowed, no console)
python -m PyInstaller --noconfirm MultiHostExecutor.spec
if errorlevel 1 goto :fail

echo.
echo [DONE] Executable produced in dist\MultiHostExecutor.exe
exit /b 0

:fail
echo.
echo [FAILED] Build did not complete successfully.
exit /b 1
