#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Restart VCC PKI Server

.DESCRIPTION
    Restarts the VCC PKI Server (stop and start).

.PARAMETER Port
    Server port (default: 8443)

.PARAMETER Background
    Run server in background

.EXAMPLE
    .\restart_server.ps1
    .\restart_server.ps1 -Background

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8443,
    
    [Parameter(Mandatory=$false)]
    [switch]$Background
)

# Script configuration
$ErrorActionPreference = "Stop"
$SCRIPTS_DIR = $PSScriptRoot

# Colors for output
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Info { param([string]$Message) Write-ColorOutput "ℹ $Message" "Cyan" }

# Banner
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "    VCC PKI Server - Restart" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Stop server
Write-Info "Stopping PKI Server..."
& "$SCRIPTS_DIR\stop_server.ps1"

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Stop script exited with code $LASTEXITCODE, continuing anyway..."
}

# Wait a moment
Write-Info "Waiting 2 seconds..."
Start-Sleep -Seconds 2

# Start server
Write-Info "Starting PKI Server..."
if ($Background) {
    & "$SCRIPTS_DIR\start_server.ps1" -Port $Port -Background
} else {
    & "$SCRIPTS_DIR\start_server.ps1" -Port $Port
}

exit $LASTEXITCODE
