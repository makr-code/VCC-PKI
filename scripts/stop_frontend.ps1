#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Stop VCC PKI Manager GUI

.DESCRIPTION
    Stops the running VCC PKI Manager GUI.

.PARAMETER Force
    Force kill the GUI process

.EXAMPLE
    .\stop_frontend.ps1
    .\stop_frontend.ps1 -Force

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Script configuration
$ErrorActionPreference = "Stop"
$PKI_ROOT = Split-Path -Parent $PSScriptRoot
$PID_FILE = Join-Path $PKI_ROOT "pki_frontend.pid"

# Colors for output
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput "✓ $Message" "Green" }
function Write-Error-Msg { param([string]$Message) Write-ColorOutput "✗ $Message" "Red" }
function Write-Warning-Msg { param([string]$Message) Write-ColorOutput "⚠ $Message" "Yellow" }
function Write-Info { param([string]$Message) Write-ColorOutput "ℹ $Message" "Cyan" }

# Banner
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "    VCC PKI Manager GUI - Stop Script" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Check if PID file exists
if (-not (Test-Path $PID_FILE)) {
    Write-Warning-Msg "PKI Manager GUI is not running (no PID file found)"
    Write-Info "You can also close the GUI window directly"
    exit 0
}

# Read PID
$processId = Get-Content $PID_FILE
Write-Info "Found PID: $processId"

# Check if process is running
$process = Get-Process -Id $processId -ErrorAction SilentlyContinue

if (-not $process) {
    Write-Warning-Msg "Process not found (PID: $processId)"
    Write-Info "Removing stale PID file..."
    Remove-Item $PID_FILE -Force
    Write-Success "Cleanup complete"
    exit 0
}

# Stop process
Write-Info "Stopping PKI Manager GUI (PID: $processId)..."

try {
    if ($Force) {
        # Force kill
        Write-Warning-Msg "Force killing process..."
        Stop-Process -Id $processId -Force
        Write-Success "Process killed"
    } else {
        # Graceful stop
        Write-Info "Sending stop signal..."
        Stop-Process -Id $processId
        
        # Wait for process to exit (max 5 seconds)
        $timeout = 5
        $elapsed = 0
        while ($elapsed -lt $timeout) {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if (-not $process) {
                break
            }
            Start-Sleep -Seconds 1
            $elapsed++
        }
        
        # Check if process is still running
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            Write-Warning-Msg "Process did not stop gracefully"
            Write-Info "Use -Force to kill the process"
            exit 1
        }
        
        Write-Success "GUI stopped gracefully"
    }
    
    # Remove PID file
    Remove-Item $PID_FILE -Force
    Write-Success "PID file removed"
    
} catch {
    Write-Error-Msg "Failed to stop GUI: $_"
    exit 1
}

Write-Host ""
Write-Success "PKI Manager GUI stopped successfully!"
Write-Host ""
