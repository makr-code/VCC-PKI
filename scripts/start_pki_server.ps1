#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start VCC PKI Server

.DESCRIPTION
    PowerShell script to start the VCC PKI Server with proper configuration.
    Handles certificate generation, environment setup, and server startup.

.PARAMETER Port
    Server port (default: 8443)

.PARAMETER Host
    Server host (default: 127.0.0.1)

.PARAMETER Reload
    Enable auto-reload for development

.PARAMETER HTTP
    Run in HTTP mode (not recommended for production)

.EXAMPLE
    .\start_pki_server.ps1
    
.EXAMPLE
    .\start_pki_server.ps1 -Port 9443 -Host 0.0.0.0
    
.EXAMPLE
    .\start_pki_server.ps1 -Reload
#>

param(
    [int]$Port = 8443,
    [string]$ServerHost = "127.0.0.1",
    [switch]$Reload,
    [switch]$HTTP
)

# Colors for output
$Color_Info = "Cyan"
$Color_Success = "Green"
$Color_Warning = "Yellow"
$Color_Error = "Red"

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor $Color_Info
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor $Color_Success
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor $Color_Warning
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor $Color_Error
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

Write-Info "Starting VCC PKI Server pre-flight checks..."

# Check if we're in the correct directory
if (-not (Test-Path "src/pki_server.py")) {
    Write-Error-Custom "pki_server.py not found. Please run this script from C:\VCC\PKI"
    exit 1
}

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Success "Python detected: $pythonVersion"
} catch {
    Write-Error-Custom "Python not found. Please install Python 3.8+"
    exit 1
}

# Check required Python packages
Write-Info "Checking Python dependencies..."
$requiredPackages = @("fastapi", "uvicorn", "pydantic", "cryptography")

foreach ($package in $requiredPackages) {
    try {
        python -c "import $package" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$package installed"
        } else {
            Write-Warning "$package not found. Installing..."
            pip install $package
        }
    } catch {
        Write-Warning "$package not found. Installing..."
        pip install $package
    }
}

# ============================================================================
# CA Certificate Check
# ============================================================================

Write-Info "Checking CA certificates..."

if (-not (Test-Path "ca_storage/root_ca.pem")) {
    Write-Error-Custom "Root CA not found. Please initialize CA first:"
    Write-Host "  python src/ca_manager.py init-root --password your_password" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path "ca_storage/intermediate_ca.pem")) {
    Write-Error-Custom "Intermediate CA not found. Please create intermediate CA first:"
    Write-Host "  python src/ca_manager.py create-intermediate --root-password root_pw --ca-password intermediate_pw" -ForegroundColor Yellow
    exit 1
}

Write-Success "CA certificates found"

# ============================================================================
# PKI Server Certificate
# ============================================================================

Write-Info "Checking PKI Server certificate..."

$serverCertDir = "service_certificates/pki-server"

if (-not (Test-Path "$serverCertDir/cert.pem") -or -not (Test-Path "$serverCertDir/key.pem")) {
    Write-Warning "PKI Server certificate not found. Generating..."
    
    # Generate certificate for PKI server itself
    $caPassword = Read-Host "Enter Intermediate CA password" -AsSecureString
    $caPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($caPassword)
    )
    
    Write-Info "Issuing certificate for pki-server..."
    python src/service_cert_manager.py issue `
        --service-id pki-server `
        --cn pki-server.vcc.local `
        --san-dns pki-server localhost `
        --san-ip 127.0.0.1 192.168.178.94 `
        --ca-password $caPasswordPlain
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "Failed to issue PKI Server certificate"
        exit 1
    }
    
    Write-Success "PKI Server certificate issued"
} else {
    Write-Success "PKI Server certificate found"
    
    # Check expiry
    $certInfo = python -c @"
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

cert_file = Path('$serverCertDir/cert.pem')
with open(cert_file, 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())

not_after = cert.not_valid_after_utc
days_until_expiry = (not_after - datetime.now(not_after.tzinfo)).days
print(f'{days_until_expiry}')
"@
    
    $daysUntilExpiry = [int]$certInfo
    
    if ($daysUntilExpiry -lt 30) {
        Write-Warning "PKI Server certificate expires in $daysUntilExpiry days. Consider renewal."
    } else {
        Write-Success "Certificate valid for $daysUntilExpiry days"
    }
}

# ============================================================================
# Create Necessary Directories
# ============================================================================

Write-Info "Creating directories..."

$directories = @(
    "logs",
    "database",
    "backups"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Success "Created $dir/"
    }
}

# ============================================================================
# Environment Variables
# ============================================================================

Write-Info "Setting environment variables..."

# Set CA password (in production, use secure vault!)
if (-not $env:VCC_INTERMEDIATE_CA_PASSWORD) {
    Write-Warning "VCC_INTERMEDIATE_CA_PASSWORD not set. Using default (NOT RECOMMENDED FOR PRODUCTION!)"
    $env:VCC_INTERMEDIATE_CA_PASSWORD = "vcc_intermediate_pw_2025"
}

# ============================================================================
# Start Server
# ============================================================================

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "   VCC PKI Server Starting" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server URL: " -NoNewline
if ($HTTP) {
    Write-Host "http://${ServerHost}:${Port}" -ForegroundColor Yellow
    Write-Warning "Running in HTTP mode (NOT SECURE!)"
} else {
    Write-Host "https://${ServerHost}:${Port}" -ForegroundColor Green
}
Write-Host "API Docs:   " -NoNewline
Write-Host "https://${ServerHost}:${Port}/api/docs" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host ""

# Build command
$cmd = "python src/pki_server.py --host $ServerHost --port $Port"

if (-not $HTTP) {
    $cmd += " --ssl-cert $serverCertDir/cert.pem --ssl-key $serverCertDir/key.pem"
}

if ($Reload) {
    $cmd += " --reload"
    Write-Warning "Auto-reload enabled (development mode)"
}

# Change to src directory
Push-Location src

try {
    # Start server
    Invoke-Expression $cmd
} catch {
    Write-Error-Custom "Server error: $_"
    exit 1
} finally {
    Pop-Location
}
