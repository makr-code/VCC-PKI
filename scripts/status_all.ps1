#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Check status of all VCC PKI services

.DESCRIPTION
    Checks the status of both the PKI Server and GUI frontend.

.PARAMETER Port
    Server port (default: 8443)

.EXAMPLE
    .\status_all.ps1

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8443
)

# Script configuration
$ErrorActionPreference = "Continue"
$PKI_ROOT = Split-Path -Parent $PSScriptRoot
$SERVER_PID_FILE = Join-Path $PKI_ROOT "pki_server.pid"
$GUI_PID_FILE = Join-Path $PKI_ROOT "pki_frontend.pid"

# Colors for output
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput "✓ $Message" "Green" }
function Write-Error-Msg { param([string]$Message) Write-ColorOutput "✗ $Message" "Red" }
function Write-Info { param([string]$Message) Write-ColorOutput "ℹ $Message" "Cyan" }

# Banner
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "    VCC PKI - Status Overview" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Check server status
Write-ColorOutput "PKI SERVER:" "Yellow"
Write-ColorOutput "───────────────────────────────────────────────────────" "Gray"

$serverRunning = $false
if (Test-Path $SERVER_PID_FILE) {
    $serverProcessId = Get-Content $SERVER_PID_FILE
    $process = Get-Process -Id $serverProcessId -ErrorAction SilentlyContinue
    
    if ($process) {
        $serverRunning = $true
        Write-Success "Process is running (PID: $serverProcessId)"
        
        $uptime = (Get-Date) - $process.StartTime
        Write-Info "  Uptime:  $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        Write-Info "  CPU:     $($process.CPU.ToString('0.00'))s"
        Write-Info "  Memory:  $([math]::Round($process.WorkingSet64/1MB, 2)) MB"
    } else {
        Write-Error-Msg "PID file exists but process not found"
    }
} else {
    Write-Error-Msg "Not running (no PID file)"
}

# Check server HTTP endpoint
if ($serverRunning) {
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $request = [System.Net.WebRequest]::Create("https://localhost:$Port/api/health")
        $request.Method = "GET"
        $request.Timeout = 5000
        $response = $request.GetResponse()
        $response.Close()
        
        Write-Success "HTTP endpoint responding"
        Write-Info "  URL: https://localhost:$Port"
    } catch {
        Write-Error-Msg "HTTP endpoint NOT responding"
    }
}

Write-Host ""

# Check GUI status
Write-ColorOutput "PKI MANAGER GUI:" "Yellow"
Write-ColorOutput "───────────────────────────────────────────────────────" "Gray"

$guiRunning = $false
if (Test-Path $GUI_PID_FILE) {
    $guiProcessId = Get-Content $GUI_PID_FILE
    $process = Get-Process -Id $guiProcessId -ErrorAction SilentlyContinue
    
    if ($process) {
        $guiRunning = $true
        Write-Success "Process is running (PID: $guiProcessId)"
        
        $uptime = (Get-Date) - $process.StartTime
        Write-Info "  Uptime:  $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        Write-Info "  Memory:  $([math]::Round($process.WorkingSet64/1MB, 2)) MB"
    } else {
        Write-Error-Msg "PID file exists but process not found"
    }
} else {
    Write-Error-Msg "Not running (no PID file)"
}

# Summary
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Gray"

if ($serverRunning -and $guiRunning) {
    Write-Success "All services are RUNNING"
} elseif ($serverRunning) {
    Write-ColorOutput "⚠ Server is running, GUI is stopped" "Yellow"
} elseif ($guiRunning) {
    Write-ColorOutput "⚠ GUI is running, server is stopped" "Yellow"
} else {
    Write-Error-Msg "All services are STOPPED"
}

# Quick actions
Write-Host ""
Write-Info "Quick Actions:"
Write-Info "  Start all:   .\scripts\start_all.ps1"
Write-Info "  Stop all:    .\scripts\stop_all.ps1"
Write-Info "  Restart:     .\scripts\restart_server.ps1"
Write-Info "  Server logs: Get-Content logs\pki_server.log -Tail 50"

Write-Host ""
