#!/bin/bash

# VCC PKI System - Startup Script
# Production-ready deployment and development setup

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLU# VCC_PKI_API_PORT=12091
VCC_PKI_API_WORKERS=1'\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"
REQUIREMENTS_FILE="$PROJECT_DIR/requirements.txt"
LOG_DIR="$PROJECT_DIR/logs"
CONFIG_DIR="$PROJECT_DIR/config"

# Default environment
VCC_PKI_ENVIRONMENT="${VCC_PKI_ENVIRONMENT:-development}"

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                          VCC PKI System Startup                             ║"
    echo "║                   Brandenburg Government Digital Infrastructure              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "${YELLOW}>>> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

check_dependencies() {
    print_section "Checking System Dependencies"
    
    # Check Python
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3 not found. Please install Python 3.11 or later."
        exit 1
    fi
    
    # Check pip
    if command -v pip3 >/dev/null 2>&1; then
        print_success "pip3 found"
    else
        print_error "pip3 not found. Please install pip."
        exit 1
    fi
    
    # Check git (optional)
    if command -v git >/dev/null 2>&1; then
        print_success "Git found"
    else
        print_info "Git not found (optional for development)"
    fi
    
    # Check Docker (optional)
    if command -v docker >/dev/null 2>&1; then
        print_success "Docker found"
    else
        print_info "Docker not found (optional for containerized deployment)"
    fi
}

setup_directories() {
    print_section "Setting up Directory Structure"
    
    # Create necessary directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$PROJECT_DIR/data"
    mkdir -p "$PROJECT_DIR/certificates"
    mkdir -p "$PROJECT_DIR/backups"
    
    print_success "Directory structure created"
}

setup_python_environment() {
    print_section "Setting up Python Environment"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR"
        print_success "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    print_success "Virtual environment activated"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "$REQUIREMENTS_FILE" ]; then
        print_info "Installing Python dependencies..."
        pip install -r "$REQUIREMENTS_FILE"
        print_success "Dependencies installed"
    else
        print_info "Installing core dependencies..."
        pip install fastapi uvicorn sqlcipher3 cryptography pydantic requests click
        print_success "Core dependencies installed"
    fi
}

generate_requirements() {
    print_section "Generating Requirements File"
    
    cat > "$REQUIREMENTS_FILE" << 'EOF'
# VCC PKI System - Python Dependencies
# Production-ready PKI infrastructure

# Web Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0

# Database
sqlcipher3==0.5.2
sqlite3-utils==3.35.2

# Cryptography
cryptography==41.0.7
pycryptodome==3.19.0

# Data Validation
pydantic==2.5.0
pydantic-settings==2.0.3

# HTTP Client
requests==2.31.0
httpx==0.25.2

# CLI
click==8.1.7
rich==13.7.0
typer==0.9.0

# Development
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# Logging
structlog==23.2.0

# Configuration
python-dotenv==1.0.0
PyYAML==6.0.1

# Security
passlib==1.7.4
python-jose==3.3.0

# Monitoring
psutil==5.9.6
prometheus-client==0.19.0

# Documentation
mkdocs==1.5.3
mkdocs-material==9.4.8
EOF
    
    print_success "Requirements file generated"
}

setup_configuration() {
    print_section "Setting up Configuration Files"
    
    # Generate development config
    cat > "$CONFIG_DIR/development.env" << EOF
# VCC PKI System - Development Configuration

VCC_PKI_ENVIRONMENT=development
VCC_PKI_DEBUG=true
VCC_PKI_MOCK_MODE=true

# API Configuration
VCC_PKI_API_HOST=127.0.0.1
VCC_PKI_API_PORT=8000
VCC_PKI_API_WORKERS=1

# Database Configuration
VCC_PKI_DATABASE_PATH=./data/vcc-pki-dev.db
VCC_PKI_DATABASE_ENCRYPTION_KEY=development-key-change-in-production

# Logging Configuration
VCC_PKI_LOG_LEVEL=DEBUG
VCC_PKI_LOG_FILE=./logs/vcc-pki-dev.log

# Security Configuration (Development Only)
VCC_PKI_MOCK_AUTH=true
VCC_PKI_ALLOW_INSECURE=true

# Certificate Configuration
VCC_PKI_CA_KEY_SIZE=2048
VCC_PKI_CERT_VALIDITY_DAYS=90
VCC_PKI_ROOT_CA_VALIDITY_DAYS=3650

# VCC Service Discovery
VCC_PKI_SERVICE_DISCOVERY_ENABLED=true
VCC_PKI_AUTO_CERT_RENEWAL=true
EOF

    # Generate production config template
    cat > "$CONFIG_DIR/production.env.template" << EOF
# VCC PKI System - Production Configuration Template
# Copy to production.env and customize

VCC_PKI_ENVIRONMENT=production
VCC_PKI_DEBUG=false
VCC_PKI_MOCK_MODE=false

# API Configuration
VCC_PKI_API_HOST=0.0.0.0
VCC_PKI_API_PORT=12091
VCC_PKI_API_WORKERS=4

# Database Configuration
VCC_PKI_DATABASE_PATH=/var/lib/vcc-pki/vcc-pki.db
VCC_PKI_DATABASE_ENCRYPTION_KEY=CHANGE_THIS_IN_PRODUCTION

# Logging Configuration
VCC_PKI_LOG_LEVEL=INFO
VCC_PKI_LOG_FILE=/var/log/vcc-pki/vcc-pki.log

# Security Configuration
VCC_PKI_MOCK_AUTH=false
VCC_PKI_ALLOW_INSECURE=false
VCC_PKI_KEYCLOAK_URL=https://keycloak.brandenburg.de
VCC_PKI_KEYCLOAK_REALM=vcc

# Certificate Configuration
VCC_PKI_CA_KEY_SIZE=4096
VCC_PKI_CERT_VALIDITY_DAYS=365
VCC_PKI_ROOT_CA_VALIDITY_DAYS=7300

# HSM Configuration (if available)
VCC_PKI_HSM_ENABLED=false
VCC_PKI_HSM_LIBRARY_PATH=/usr/lib/libpkcs11.so
VCC_PKI_HSM_SLOT_ID=0

# Backup Configuration
VCC_PKI_BACKUP_ENABLED=true
VCC_PKI_BACKUP_SCHEDULE=0 2 * * *
VCC_PKI_BACKUP_RETENTION_DAYS=90

# VCC Service Discovery
VCC_PKI_SERVICE_DISCOVERY_ENABLED=true
VCC_PKI_AUTO_CERT_RENEWAL=true
VCC_PKI_MTLS_REQUIRED=true
EOF

    print_success "Configuration files created"
}

setup_systemd_service() {
    print_section "Setting up Systemd Service (Optional)"
    
    if [ "$VCC_PKI_ENVIRONMENT" != "production" ]; then
        print_info "Skipping systemd service setup (not in production mode)"
        return
    fi
    
    # Generate systemd service file
    cat > "$PROJECT_DIR/vcc-pki.service" << EOF
[Unit]
Description=VCC PKI System API Server
Documentation=https://vcc-pki.brandenburg.de/docs
After=network.target postgresql.service

[Service]
Type=exec
User=vcc-pki
Group=vcc-pki
WorkingDirectory=$PROJECT_DIR
Environment=VCC_PKI_ENVIRONMENT=production
EnvironmentFile=$CONFIG_DIR/production.env
ExecStart=$VENV_DIR/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 12091 --workers 4
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure
RestartSec=10

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$PROJECT_DIR/data $PROJECT_DIR/logs $PROJECT_DIR/certificates
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
    
    print_info "Systemd service file created: $PROJECT_DIR/vcc-pki.service"
    print_info "To install: sudo cp vcc-pki.service /etc/systemd/system/"
    print_info "Then: sudo systemctl enable vcc-pki && sudo systemctl start vcc-pki"
}

create_cli_symlink() {
    print_section "Setting up CLI Tool"
    
    # Make CLI executable
    chmod +x "$PROJECT_DIR/vcc-pki-cli.py"
    
    # Create symlink if in PATH location
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$PROJECT_DIR/vcc-pki-cli.py" "/usr/local/bin/vcc-pki"
        print_success "CLI tool linked to /usr/local/bin/vcc-pki"
    else
        print_info "To use CLI globally, run: sudo ln -sf $PROJECT_DIR/vcc-pki-cli.py /usr/local/bin/vcc-pki"
    fi
}

initialize_database() {
    print_section "Initializing Database"
    
    # Set environment
    export VCC_PKI_ENVIRONMENT="$VCC_PKI_ENVIRONMENT"
    
    # Source environment config
    if [ -f "$CONFIG_DIR/${VCC_PKI_ENVIRONMENT}.env" ]; then
        set -a
        source "$CONFIG_DIR/${VCC_PKI_ENVIRONMENT}.env"
        set +a
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Initialize database via Python
    python3 -c "
import sys
sys.path.append('$PROJECT_DIR')

from app.core.config import create_config
from app.core.database import VCCPKIDatabase
from app.services.crypto_service import VCCCryptoService
from app.services.pki_service import VCCPKIService

print('🔧 Initializing VCC PKI database...')

config = create_config('$VCC_PKI_ENVIRONMENT')
database = VCCPKIDatabase(config.database_path, config.database_encryption_key)
crypto_service = VCCCryptoService(config)
pki_service = VCCPKIService(config, database, crypto_service)

print('✅ Database initialized successfully')
print(f'📊 Environment: {config.environment}')
print(f'🗄️  Database: {config.database_path}')
print(f'🔐 Mock mode: {config.mock_mode}')
"
    
    print_success "Database initialization completed"
}

run_health_check() {
    print_section "Running Health Check"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Start API server in background
    print_info "Starting API server for health check..."
    
    # Set environment
    export VCC_PKI_ENVIRONMENT="$VCC_PKI_ENVIRONMENT"
    
    # Source environment config
    if [ -f "$CONFIG_DIR/${VCC_PKI_ENVIRONMENT}.env" ]; then
        set -a
        source "$CONFIG_DIR/${VCC_PKI_ENVIRONMENT}.env"
        set +a
    fi
    
    # Start server in background
    cd "$PROJECT_DIR"
    python3 -m uvicorn app.main:app --host 127.0.0.1 --port 12091 &
    SERVER_PID=$!
    
    # Wait for server to start
    print_info "Waiting for server to start..."
    sleep 5
    
    # Test health endpoint
    if command -v curl >/dev/null 2>&1; then
        if curl -s http://localhost:12091/health >/dev/null; then
            print_success "Health check passed"
        else
            print_error "Health check failed"
        fi
    else
        print_info "curl not found, skipping health check"
    fi
    
    # Stop server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    print_info "Health check completed"
}

show_startup_summary() {
    print_section "Startup Summary"
    
    echo -e "${GREEN}"
    echo "🎉 VCC PKI System setup completed successfully!"
    echo ""
    echo "📋 Quick Start Commands:"
    echo "   Source environment: source venv/bin/activate"
    echo "   Start development server: ./start-dev.sh"
    echo "   Use CLI tool: ./vcc-pki-cli.py --help"
    echo "   View API docs: http://localhost:12091/docs"
    echo ""
    echo "📁 Important Locations:"
    echo "   Project directory: $PROJECT_DIR"
    echo "   Virtual environment: $VENV_DIR"
    echo "   Configuration: $CONFIG_DIR"
    echo "   Logs: $LOG_DIR"
    echo "   Data: $PROJECT_DIR/data"
    echo ""
    echo "🔧 Environment: $VCC_PKI_ENVIRONMENT"
    echo -e "${NC}"
}

main() {
    print_header
    
    # Parse command line arguments
    SETUP_MODE="full"
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick)
                SETUP_MODE="quick"
                shift
                ;;
            --production)
                VCC_PKI_ENVIRONMENT="production"
                shift
                ;;
            --help)
                echo "VCC PKI System Setup Script"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --quick       Quick setup (skip optional components)"
                echo "  --production  Setup for production environment"
                echo "  --help        Show this help message"
                echo ""
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    print_info "Setup mode: $SETUP_MODE"
    print_info "Environment: $VCC_PKI_ENVIRONMENT"
    
    # Core setup steps
    check_dependencies
    setup_directories
    generate_requirements
    setup_python_environment
    setup_configuration
    initialize_database
    
    # Optional setup steps
    if [ "$SETUP_MODE" != "quick" ]; then
        create_cli_symlink
        setup_systemd_service
        run_health_check
    fi
    
    show_startup_summary
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${RED}❌ Setup interrupted by user${NC}"; exit 130' INT

# Run main function
main "$@"