#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Stop VCC PKI Server and GUI

.DESCRIPTION
    Stops both the PKI Server and the GUI frontend.

.PARAMETER Force
    Force kill all processes

.EXAMPLE
    .\stop_all.ps1
    .\stop_all.ps1 -Force

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Script configuration
$ErrorActionPreference = "Continue"
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
Write-ColorOutput "    VCC PKI - Stop All Services" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

$allStopped = $true

# Stop GUI
Write-Info "Stopping PKI Manager GUI..."
if ($Force) {
    & "$SCRIPTS_DIR\stop_frontend.ps1" -Force
} else {
    & "$SCRIPTS_DIR\stop_frontend.ps1"
}

if ($LASTEXITCODE -ne 0) {
    $allStopped = $false
}

Write-Host ""

# Stop server
Write-Info "Stopping PKI Server..."
if ($Force) {
    & "$SCRIPTS_DIR\stop_server.ps1" -Force
} else {
    & "$SCRIPTS_DIR\stop_server.ps1"
}

if ($LASTEXITCODE -ne 0) {
    $allStopped = $false
}

# Summary
Write-Host ""
if ($allStopped) {
    Write-Success "All services stopped successfully!"
} else {
    Write-ColorOutput "⚠ Some services may not have stopped properly" "Yellow"
    Write-Info "Check status: .\scripts\status_all.ps1"
}
Write-Host ""
