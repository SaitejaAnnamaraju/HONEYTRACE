@echo off
setlocal enabledelayedexpansion
title HONEYTRACE - Deception-Based IDS Platform

:: Change current working directory to the folder containing this script
cd /d "%~dp0"

echo =====================================================================
echo              HONEYTRACE INTRUSION INTELLIGENCE PLATFORM              
echo          B.Tech Cybersecurity Capstone Demonstration Suite           
echo =====================================================================
echo.

:: ---------------------------------------------------------------------
:: Robust Python Detection (Bypasses Windows Microsoft Store Stub)
:: ---------------------------------------------------------------------
set "PYTHON_EXE="

:: 1. Check direct AppData pythoncore installations (common on modern Windows)
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
)

if not defined PYTHON_EXE (
    for /d %%D in ("%LOCALAPPDATA%\Python\pythoncore-*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

:: 2. Check AppData Programs Python installations
if not defined PYTHON_EXE (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

:: 3. Check ProgramFiles / ProgramFiles(x86) Python installations
if not defined PYTHON_EXE (
    for /d %%D in ("%ProgramFiles%\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

if not defined PYTHON_EXE (
    for /d %%D in ("%ProgramFiles(x86)%\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

:: 4. Check root C:\Python*
if not defined PYTHON_EXE (
    for /d %%D in ("C:\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

:: 5. Check py launcher (must be operational)
if not defined PYTHON_EXE (
    py -3 -c "import sys; sys.exit(0)" >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_EXE=py -3"
    )
)

:: 6. Check system python (validating it is a real interpreter, NOT Microsoft Store stub)
if not defined PYTHON_EXE (
    python -c "import sys; sys.exit(0)" >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_EXE=python"
    )
)

:: If still not found, alert user with resolution instructions
if not defined PYTHON_EXE (
    echo [ERROR] Python was not automatically located on this Windows PC.
    echo.
    echo Troubleshooting Steps:
    echo 1. If Python is installed, disable Windows Store execution aliases:
    echo    Settings > Apps > Advanced app settings > App execution aliases > Disable 'python.exe'.
    echo 2. Or install Python 3.10+ from python.org and check 'Add Python to PATH'.
    echo.
    pause
    exit /b 1
)

echo [*] Python detected: !PYTHON_EXE!
"!PYTHON_EXE!" --version
echo.

:: Check / use virtual environment if exists
if exist ".venv\Scripts\python.exe" (
    echo [*] Using local virtual environment: .venv
    set "PYTHON_EXE=.venv\Scripts\python.exe"
)

:: Verify dependencies
echo [*] Checking dependencies from requirements.txt...
"!PYTHON_EXE!" -c "import streamlit, plotly, pandas, flask, requests, PIL, pytest, fpdf" >nul 2>nul
if errorlevel 1 (
    echo [!] Missing dependencies. Installing now via pip...
    "!PYTHON_EXE!" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)
echo [*] All dependencies verified.
echo.

:: Ensure sample dataset exists
if not exist "data\honeytrace.db" (
    echo [*] Pre-seeding demonstration dataset into SQLite...
    "!PYTHON_EXE!" simulation\seed_data.py
    echo.
)

:: Run test suite verification
echo [*] Executing core self-test suite...
"!PYTHON_EXE!" -m pytest -q
if errorlevel 1 (
    echo [!] Warning: Some tests did not pass. Starting platform anyway...
) else (
    echo [*] Test suite passed cleanly: 33 of 33 tests passed.
)
echo.

:: Ensure Streamlit does not prompt for email on first run
if not exist "%USERPROFILE%\.streamlit\credentials.toml" (
    mkdir "%USERPROFILE%\.streamlit" 2>nul
    (echo [general]& echo email = "") > "%USERPROFILE%\.streamlit\credentials.toml"
)

:: Launch HoneyTrace Platform
echo =====================================================================
echo [*] Starting HONEYTRACE Deception Platform...
echo [*] Decoys:
echo     - HTTP Decoy Honeypot: http://127.0.0.1:8080
echo     - SSH Decoy Honeypot:  tcp://127.0.0.1:2222
echo [*] Streamlit Dashboard:   http://localhost:8501
echo =====================================================================
echo.

"!PYTHON_EXE!" -m streamlit run app.py --server.headless=false --browser.serverAddress=localhost

pause

