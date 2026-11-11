@echo off
setlocal enabledelayedexpansion
title HONEYTRACE - PyInstaller Executable Builder

echo =====================================================================
echo           HONEYTRACE STANDALONE EXECUTABLE BUILDER (OPTIONAL)        
echo =====================================================================
echo.

:: ---------------------------------------------------------------------
:: Robust Python Detection (Bypasses Windows Microsoft Store Stub)
:: ---------------------------------------------------------------------
set "PYTHON_EXE="

if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
)

if not defined PYTHON_EXE (
    for /d %%D in ("%LOCALAPPDATA%\Python\pythoncore-*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

if not defined PYTHON_EXE (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

if not defined PYTHON_EXE (
    for /d %%D in ("%ProgramFiles%\Python*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

if not defined PYTHON_EXE (
    py -3 -c "import sys; sys.exit(0)" >nul 2>nul
    if not errorlevel 1 set "PYTHON_EXE=py -3"
)

if not defined PYTHON_EXE (
    python -c "import sys; sys.exit(0)" >nul 2>nul
    if not errorlevel 1 set "PYTHON_EXE=python"
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not automatically located.
    pause
    exit /b 1
)

echo [*] Python detected: !PYTHON_EXE!
"!PYTHON_EXE!" --version
echo.

:: Check for pyinstaller
echo [*] Checking PyInstaller installation...
%PYTHON_EXE% -m pip show pyinstaller >nul 2>nul
if %errorlevel% neq 0 (
    echo [*] PyInstaller not detected. Installing PyInstaller via pip...
    %PYTHON_EXE% -m pip install pyinstaller
    if %errorlevel% neq 0 (
        echo [!] Note: If building on Python 3.14+, PyInstaller may require
        echo     a compatible Python version (3.10, 3.11, or 3.12 recommended).
        pause
        exit /b 1
    )
)

echo [*] Compiling HONEYTRACE using honeytrace.spec...
%PYTHON_EXE% -m PyInstaller honeytrace.spec --noconfirm

if %errorlevel% equ 0 (
    echo.
    echo =====================================================================
    echo [+] BUILD SUCCESSFUL!
    echo     Executable directory: dist\HONEYTRACE\
    echo     Launch command:       dist\HONEYTRACE\HONEYTRACE.exe
    echo =====================================================================
) else (
    echo.
    echo [!] Build encountered an error.
    echo     Note: Streamlit apps are best run portable via run.bat.
)

pause

