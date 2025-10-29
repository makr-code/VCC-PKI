@echo off
title VCC PKI System - Dashboard Starter

echo.
echo ========================================
echo VCC PKI System - Management Dashboard
echo ========================================
echo.

cd /d "%~dp0"

echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Python found. Starting dashboard...
echo.

REM Try simple dashboard first (no dependencies)
echo Starting simple dashboard...
python simple_dashboard.py

REM If that fails, try the full dashboard
if %errorlevel% neq 0 (
    echo.
    echo Simple dashboard failed. Trying full dashboard with dependency check...
    python start_dashboard.py
)

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to start dashboard
    echo Please check the error messages above
    pause
)

echo.
echo Dashboard closed.
pause