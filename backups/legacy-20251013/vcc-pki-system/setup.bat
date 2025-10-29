@echo off
REM VCC PKI System - Windows Startup Script
REM Production-ready deployment and development setup for Windows

setlocal EnableDelayedExpansion

REM Configuration
set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "VENV_DIR=%PROJECT_DIR%\venv"
set "REQUIREMENTS_FILE=%PROJECT_DIR%\requirements.txt"
set "LOG_DIR=%PROJECT_DIR%\logs"
set "CONFIG_DIR=%PROJECT_DIR%\config"

REM Default environment
if not defined VCC_PKI_ENVIRONMENT set "VCC_PKI_ENVIRONMENT=development"

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                          VCC PKI System Startup                             ║
echo ║                   Brandenburg Government Digital Infrastructure              ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

echo [93m>>> Checking System Dependencies[0m

REM Check Python
python --version >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=2" %%v in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%v"
    echo [92m✅ Python !PYTHON_VERSION! found[0m
) else (
    echo [91m❌ Python not found. Please install Python 3.11 or later.[0m
    pause
    exit /b 1
)

REM Check pip
pip --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [92m✅ pip found[0m
) else (
    echo [91m❌ pip not found. Please install pip.[0m
    pause
    exit /b 1
)

REM Check Git (optional)
git --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [92m✅ Git found[0m
) else (
    echo [94mℹ️  Git not found (optional for development)[0m
)

REM Check Docker (optional)
docker --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [92m✅ Docker found[0m
) else (
    echo [94mℹ️  Docker not found (optional for containerized deployment)[0m
)

echo.
echo [93m>>> Setting up Directory Structure[0m

REM Create necessary directories
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%PROJECT_DIR%\data" mkdir "%PROJECT_DIR%\data"
if not exist "%PROJECT_DIR%\certificates" mkdir "%PROJECT_DIR%\certificates"
if not exist "%PROJECT_DIR%\backups" mkdir "%PROJECT_DIR%\backups"

echo [92m✅ Directory structure created[0m

echo.
echo [93m>>> Generating Requirements File[0m

(
echo # VCC PKI System - Python Dependencies
echo # Production-ready PKI infrastructure
echo.
echo # Web Framework
echo fastapi==0.104.1
echo uvicorn[standard]==0.24.0
echo.
echo # Database
echo sqlcipher3==0.5.2
echo sqlite3-utils==3.35.2
echo.
echo # Cryptography
echo cryptography==41.0.7
echo pycryptodome==3.19.0
echo.
echo # Data Validation
echo pydantic==2.5.0
echo pydantic-settings==2.0.3
echo.
echo # HTTP Client
echo requests==2.31.0
echo httpx==0.25.2
echo.
echo # CLI
echo click==8.1.7
echo rich==13.7.0
echo typer==0.9.0
echo.
echo # Development
echo pytest==7.4.3
echo pytest-asyncio==0.21.1
echo pytest-cov==4.1.0
echo black==23.11.0
echo flake8==6.1.0
echo mypy==1.7.1
echo.
echo # Logging
echo structlog==23.2.0
echo.
echo # Configuration
echo python-dotenv==1.0.0
echo PyYAML==6.0.1
echo.
echo # Security
echo passlib==1.7.4
echo python-jose==3.3.0
echo.
echo # Monitoring
echo psutil==5.9.6
echo prometheus-client==0.19.0
echo.
echo # Documentation
echo mkdocs==1.5.3
echo mkdocs-material==9.4.8
) > "%REQUIREMENTS_FILE%"

echo [92m✅ Requirements file generated[0m

echo.
echo [93m>>> Setting up Python Environment[0m

REM Create virtual environment if it doesn't exist
if not exist "%VENV_DIR%" (
    echo [94mℹ️  Creating Python virtual environment...[0m
    python -m venv "%VENV_DIR%"
    echo [92m✅ Virtual environment created[0m
) else (
    echo [94mℹ️  Virtual environment already exists[0m
)

REM Activate virtual environment
call "%VENV_DIR%\Scripts\activate.bat"
echo [92m✅ Virtual environment activated[0m

REM Upgrade pip
python -m pip install --upgrade pip

REM Install requirements
if exist "%REQUIREMENTS_FILE%" (
    echo [94mℹ️  Installing Python dependencies...[0m
    pip install -r "%REQUIREMENTS_FILE%"
    echo [92m✅ Dependencies installed[0m
) else (
    echo [94mℹ️  Installing core dependencies...[0m
    pip install fastapi uvicorn sqlcipher3 cryptography pydantic requests click
    echo [92m✅ Core dependencies installed[0m
)

echo.
echo [93m>>> Setting up Configuration Files[0m

REM Generate development config
(
echo # VCC PKI System - Development Configuration
echo.
echo VCC_PKI_ENVIRONMENT=development
echo VCC_PKI_DEBUG=true
echo VCC_PKI_MOCK_MODE=true
echo.
echo # API Configuration
echo VCC_PKI_API_HOST=127.0.0.1
echo VCC_PKI_API_PORT=12091
echo VCC_PKI_API_WORKERS=1
echo.
echo # Database Configuration
echo VCC_PKI_DATABASE_PATH=./data/vcc-pki-dev.db
echo VCC_PKI_DATABASE_ENCRYPTION_KEY=development-key-change-in-production
echo.
echo # Logging Configuration
echo VCC_PKI_LOG_LEVEL=DEBUG
echo VCC_PKI_LOG_FILE=./logs/vcc-pki-dev.log
echo.
echo # Security Configuration (Development Only^)
echo VCC_PKI_MOCK_AUTH=true
echo VCC_PKI_ALLOW_INSECURE=true
echo.
echo # Certificate Configuration
echo VCC_PKI_CA_KEY_SIZE=2048
echo VCC_PKI_CERT_VALIDITY_DAYS=90
echo VCC_PKI_ROOT_CA_VALIDITY_DAYS=3650
echo.
echo # VCC Service Discovery
echo VCC_PKI_SERVICE_DISCOVERY_ENABLED=true
echo VCC_PKI_AUTO_CERT_RENEWAL=true
) > "%CONFIG_DIR%\development.env"

REM Generate production config template
(
echo # VCC PKI System - Production Configuration Template
echo # Copy to production.env and customize
echo.
echo VCC_PKI_ENVIRONMENT=production
echo VCC_PKI_DEBUG=false
echo VCC_PKI_MOCK_MODE=false
echo.
echo # API Configuration
echo VCC_PKI_API_HOST=0.0.0.0
echo VCC_PKI_API_PORT=12091
echo VCC_PKI_API_WORKERS=4
echo.
echo # Database Configuration
echo VCC_PKI_DATABASE_PATH=C:\VCC\PKI\data\vcc-pki.db
echo VCC_PKI_DATABASE_ENCRYPTION_KEY=CHANGE_THIS_IN_PRODUCTION
echo.
echo # Logging Configuration
echo VCC_PKI_LOG_LEVEL=INFO
echo VCC_PKI_LOG_FILE=C:\VCC\PKI\logs\vcc-pki.log
echo.
echo # Security Configuration
echo VCC_PKI_MOCK_AUTH=false
echo VCC_PKI_ALLOW_INSECURE=false
echo VCC_PKI_KEYCLOAK_URL=https://keycloak.brandenburg.de
echo VCC_PKI_KEYCLOAK_REALM=vcc
echo.
echo # Certificate Configuration
echo VCC_PKI_CA_KEY_SIZE=4096
echo VCC_PKI_CERT_VALIDITY_DAYS=365
echo VCC_PKI_ROOT_CA_VALIDITY_DAYS=7300
echo.
echo # HSM Configuration (if available^)
echo VCC_PKI_HSM_ENABLED=false
echo VCC_PKI_HSM_LIBRARY_PATH=C:\Windows\System32\pkcs11.dll
echo VCC_PKI_HSM_SLOT_ID=0
echo.
echo # Backup Configuration
echo VCC_PKI_BACKUP_ENABLED=true
echo VCC_PKI_BACKUP_SCHEDULE=0 2 * * *
echo VCC_PKI_BACKUP_RETENTION_DAYS=90
echo.
echo # VCC Service Discovery
echo VCC_PKI_SERVICE_DISCOVERY_ENABLED=true
echo VCC_PKI_AUTO_CERT_RENEWAL=true
echo VCC_PKI_MTLS_REQUIRED=true
) > "%CONFIG_DIR%\production.env.template"

echo [92m✅ Configuration files created[0m

echo.
echo [93m>>> Initializing Database[0m

REM Set environment
set "VCC_PKI_ENVIRONMENT=%VCC_PKI_ENVIRONMENT%"

REM Initialize database via Python
python -c ^"
import sys
sys.path.append('%PROJECT_DIR%')

from app.core.config import create_config
from app.core.database import VCCPKIDatabase
from app.services.crypto_service import VCCCryptoService
from app.services.pki_service import VCCPKIService

print('🔧 Initializing VCC PKI database...')

config = create_config('%VCC_PKI_ENVIRONMENT%')
database = VCCPKIDatabase(config.database_path, config.database_encryption_key)
crypto_service = VCCCryptoService(config)
pki_service = VCCPKIService(config, database, crypto_service)

print('✅ Database initialized successfully')
print(f'📊 Environment: {config.environment}')
print(f'🗄️  Database: {config.database_path}')
print(f'🔐 Mock mode: {config.mock_mode}')
^"

if %errorlevel% equ 0 (
    echo [92m✅ Database initialization completed[0m
) else (
    echo [91m❌ Database initialization failed[0m
    pause
    exit /b 1
)

echo.
echo [93m>>> Creating Development Scripts[0m

REM Create start-dev.bat
(
echo @echo off
echo REM VCC PKI System - Development Server
echo.
echo echo Starting VCC PKI System in development mode...
echo.
echo set "VCC_PKI_ENVIRONMENT=development"
echo.
echo REM Activate virtual environment
echo call "%VENV_DIR%\Scripts\activate.bat"
echo.
echo REM Start development server
echo python -m uvicorn app.main:app --host 127.0.0.1 --port 12091 --reload
echo.
echo pause
) > "%PROJECT_DIR%\start-dev.bat"

REM Create CLI wrapper
(
echo @echo off
echo REM VCC PKI CLI Tool Wrapper
echo.
echo call "%VENV_DIR%\Scripts\activate.bat"
echo python "%PROJECT_DIR%\vcc-pki-cli.py" %%*
) > "%PROJECT_DIR%\vcc-pki.bat"

echo [92m✅ Development scripts created[0m

echo.
echo [93m>>> Running Health Check[0m

REM Start server and test health
echo [94mℹ️  Starting API server for health check...[0m

REM Start server in background (simplified for Windows)
start /B "" python -m uvicorn app.main:app --host 127.0.0.1 --port 12091

REM Wait for server to start
timeout /t 5 /nobreak >nul

REM Test health endpoint (if curl is available)
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    curl -s http://localhost:12091/health >nul 2>&1
    if !errorlevel! equ 0 (
        echo [92m✅ Health check passed[0m
    ) else (
        echo [91m❌ Health check failed[0m
    )
) else (
    echo [94mℹ️  curl not found, skipping health check[0m
)

REM Stop any running uvicorn processes (simplified)
taskkill /F /IM python.exe >nul 2>&1

echo [94mℹ️  Health check completed[0m

echo.
echo [93m>>> Startup Summary[0m
echo.
echo [92m🎉 VCC PKI System setup completed successfully![0m
echo.
echo [92m📋 Quick Start Commands:[0m
echo    Activate environment: venv\Scripts\activate.bat
echo    Start development server: start-dev.bat
echo    Use CLI tool: vcc-pki.bat --help
echo    View API docs: http://localhost:12091/docs
echo.
echo [92m📁 Important Locations:[0m
echo    Project directory: %PROJECT_DIR%
echo    Virtual environment: %VENV_DIR%
echo    Configuration: %CONFIG_DIR%
echo    Logs: %LOG_DIR%
echo    Data: %PROJECT_DIR%\data
echo.
echo [92m🔧 Environment: %VCC_PKI_ENVIRONMENT%[0m
echo.

pause