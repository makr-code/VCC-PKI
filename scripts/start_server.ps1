#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start VCC PKI Server

.DESCRIPTION
    Starts the VCC PKI Server with specified configuration.
    Creates necessary directories and initializes CA if needed.

.PARAMETER Port
    Server port (default: 8443)

.PARAMETER Host
    Server host (default: 0.0.0.0)

.PARAMETER InitCA
    Initialize CA on first start

.PARAMETER Background
    Run server in background

.EXAMPLE
    .\start_server.ps1
    .\start_server.ps1 -Port 8443 -InitCA
    .\start_server.ps1 -Background

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8443,
    
    [Parameter(Mandatory=$false)]
    [string]$Host = "0.0.0.0",
    
    [Parameter(Mandatory=$false)]
    [switch]$InitCA,
    
    [Parameter(Mandatory=$false)]
    [switch]$Background
)

# Script configuration
$ErrorActionPreference = "Stop"
$PKI_ROOT = Split-Path -Parent $PSScriptRoot
$SERVER_SCRIPT = Join-Path $PKI_ROOT "src" "pki_server.py"
$PID_FILE = Join-Path $PKI_ROOT "pki_server.pid"
$LOG_FILE = Join-Path $PKI_ROOT "logs" "pki_server.log"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput "✓ $Message" "Green" }
function Write-Error-Msg { param([string]$Message) Write-ColorOutput "✗ $Message" "Red" }
function Write-Warning-Msg { param([string]$Message) Write-ColorOutput "⚠ $Message" "Yellow" }
function Write-Info { param([string]$Message) Write-ColorOutput "ℹ $Message" "Cyan" }

# Banner
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "    VCC PKI Server - Start Script" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Check if server is already running
if (Test-Path $PID_FILE) {
    $pid = Get-Content $PID_FILE
    $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
    
    if ($process) {
        Write-Warning-Msg "PKI Server is already running (PID: $pid)"
        Write-Info "Use 'stop_server.ps1' to stop it first"
        exit 1
    } else {
        Write-Warning-Msg "Stale PID file found, removing..."
        Remove-Item $PID_FILE -Force
    }
}

# Check if Python is available
Write-Info "Checking Python installation..."
try {
    $pythonVersion = python --version 2>&1
    Write-Success "Python found: $pythonVersion"
} catch {
    Write-Error-Msg "Python not found in PATH"
    Write-Info "Please install Python 3.8+ and add it to PATH"
    exit 1
}

# Check if server script exists
if (-not (Test-Path $SERVER_SCRIPT)) {
    Write-Error-Msg "Server script not found: $SERVER_SCRIPT"
    exit 1
}

# Create logs directory
$logsDir = Join-Path $PKI_ROOT "logs"
if (-not (Test-Path $logsDir)) {
    Write-Info "Creating logs directory..."
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    Write-Success "Logs directory created"
}

# Create data directories
Write-Info "Checking data directories..."
$dataDirs = @("data", "data/ca", "data/certs", "data/crl")
foreach ($dir in $dataDirs) {
    $fullPath = Join-Path $PKI_ROOT $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Success "Created: $dir"
    }
}

# Initialize CA if requested
if ($InitCA) {
    Write-Info "Initializing Certificate Authority..."
    try {
        Push-Location $PKI_ROOT
        python $SERVER_SCRIPT --init-ca
        Write-Success "CA initialized successfully"
    } catch {
        Write-Error-Msg "Failed to initialize CA: $_"
        Pop-Location
        exit 1
    } finally {
        Pop-Location
    }
}

# Build server command
$serverArgs = @(
    $SERVER_SCRIPT,
    "--port", $Port,
    "--host", $Host
)

Write-Host ""
Write-Info "Starting PKI Server..."
Write-Info "  Host: $Host"
Write-Info "  Port: $Port"
Write-Info "  Log:  $LOG_FILE"

# Start server
try {
    Push-Location $PKI_ROOT
    
    if ($Background) {
        # Start in background
        Write-Info "Starting server in background..."
        
        $process = Start-Process -FilePath "python" `
                                 -ArgumentList $serverArgs `
                                 -RedirectStandardOutput $LOG_FILE `
                                 -RedirectStandardError $LOG_FILE `
                                 -PassThru `
                                 -WindowStyle Hidden
        
        # Save PID
        $process.Id | Out-File $PID_FILE -Encoding ASCII
        
        # Wait a moment to check if server started
        Start-Sleep -Seconds 2
        
        if ($process.HasExited) {
            Write-Error-Msg "Server failed to start"
            Write-Info "Check logs: $LOG_FILE"
            Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
            exit 1
        }
        
        Write-Host ""
        Write-Success "PKI Server started successfully!"
        Write-Success "  PID: $($process.Id)"
        Write-Success "  URL: https://localhost:$Port"
        Write-Info "  Check logs: $LOG_FILE"
        Write-Info "  Check status: .\scripts\status_server.ps1"
        Write-Info "  Stop server: .\scripts\stop_server.ps1"
        
    } else {
        # Start in foreground
        Write-Info "Starting server in foreground (Press Ctrl+C to stop)..."
        Write-Host ""
        
        python @serverArgs
    }
    
} catch {
    Write-Error-Msg "Failed to start server: $_"
    exit 1
} finally {
    Pop-Location
}

Write-Host ""
