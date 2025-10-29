@echo off
REM VCC PKI System - Development Server Startup Script for Windows
REM Quick startup for development and testing

setlocal

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                     VCC PKI System - Development Server                     ║
echo ║                         Starting in Mock Mode                               ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

REM Configuration
set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "VENV_DIR=%PROJECT_DIR%\venv"

REM Set development environment
set "VCC_PKI_ENVIRONMENT=development"

echo [94mℹ️  Environment: %VCC_PKI_ENVIRONMENT%[0m
echo [94mℹ️  Project Directory: %PROJECT_DIR%[0m
echo.

REM Check if virtual environment exists
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo [91m❌ Virtual environment not found. Please run setup.bat first.[0m
    pause
    exit /b 1
)

REM Activate virtual environment
echo [93m>>> Activating Python Virtual Environment[0m
call "%VENV_DIR%\Scripts\activate.bat"
echo [92m✅ Virtual environment activated[0m

REM Load development configuration
if exist "%PROJECT_DIR%\config\development.env" (
    echo [94mℹ️  Loading development configuration...[0m
    REM Note: Windows batch doesn't have built-in env file loading
    REM The Python app will load the config file directly
) else (
    echo [93m⚠️  Development config not found, using defaults[0m
)

REM Change to project directory
cd /d "%PROJECT_DIR%"

echo.
echo [93m>>> Starting VCC PKI API Server[0m
echo [94mℹ️  API will be available at: http://localhost:12091[0m
echo [94mℹ️  API Documentation: http://localhost:12091/docs[0m
echo [94mℹ️  ReDoc Documentation: http://localhost:12091/redoc[0m
echo [94mℹ️  Press Ctrl+C to stop the server[0m
echo.

REM Start development server with hot reload
python -m uvicorn app.main:app --host 127.0.0.1 --port 12091 --reload --log-level debug

echo.
echo [93m>>> Server Stopped[0m
echo [92m✅ VCC PKI System development server has been stopped[0m
echo.

pause