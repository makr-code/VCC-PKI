#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start VCC PKI Server and GUI

.DESCRIPTION
    Starts both the PKI Server and the GUI frontend.

.PARAMETER Port
    Server port (default: 8443)

.PARAMETER InitCA
    Initialize CA on first start

.EXAMPLE
    .\start_all.ps1
    .\start_all.ps1 -InitCA

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8443,
    
    [Parameter(Mandatory=$false)]
    [switch]$InitCA
)

# Script configuration
$ErrorActionPreference = "Stop"
$SCRIPTS_DIR = $PSScriptRoot

# Colors for output
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput "✓ $Message" "Green" }
function Write-Info { param([string]$Message) Write-ColorOutput "ℹ $Message" "Cyan" }

# Banner
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "    VCC PKI - Start All Services" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Start server
Write-Info "Starting PKI Server..."
if ($InitCA) {
    & "$SCRIPTS_DIR\start_server.ps1" -Port $Port -Background -InitCA
} else {
    & "$SCRIPTS_DIR\start_server.ps1" -Port $Port -Background
}

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to start PKI Server"
    exit 1
}

# Wait for server to be ready
Write-Info "Waiting for server to be ready..."
Start-Sleep -Seconds 3

# Check server status
& "$SCRIPTS_DIR\status_server.ps1" -Port $Port | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Server may not be fully ready yet"
}

# Start GUI
Write-Host ""
Write-Info "Starting PKI Manager GUI..."
& "$SCRIPTS_DIR\start_frontend.ps1" -Server "https://localhost:$Port"

Write-Host ""
Write-Success "All services started successfully!"
Write-Info "Check status: .\scripts\status_all.ps1"
Write-Info "Stop all: .\scripts\stop_all.ps1"
Write-Host ""
