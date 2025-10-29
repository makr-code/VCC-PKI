#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start VCC PKI Manager GUI

.DESCRIPTION
    Starts the VCC PKI Manager GUI (Tkinter frontend).

.PARAMETER Server
    PKI server URL (default: https://localhost:8443)

.PARAMETER Background
    Run GUI in background (not recommended for GUI apps)

.EXAMPLE
    .\start_frontend.ps1
    .\start_frontend.ps1 -Server https://pki.vcc.local:8443

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Server = "https://localhost:8443",
    
    [Parameter(Mandatory=$false)]
    [switch]$Background
)

# Script configuration
$ErrorActionPreference = "Stop"
$PKI_ROOT = Split-Path -Parent $PSScriptRoot
$GUI_SCRIPT = Join-Path $PKI_ROOT "pki_manager_gui.py"
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
Write-ColorOutput "    VCC PKI Manager GUI - Start Script" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Check if GUI is already running
if (Test-Path $PID_FILE) {
    $processId = Get-Content $PID_FILE
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    
    if ($process) {
        Write-Warning-Msg "PKI Manager GUI is already running (PID: $processId)"
        Write-Info "Use 'stop_frontend.ps1' to stop it first"
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

# Check if GUI script exists
if (-not (Test-Path $GUI_SCRIPT)) {
    Write-Error-Msg "GUI script not found: $GUI_SCRIPT"
    exit 1
}

# Check if tkinter is available
Write-Info "Checking tkinter availability..."
try {
    python -c "import tkinter" 2>&1 | Out-Null
    Write-Success "tkinter is available"
} catch {
    Write-Error-Msg "tkinter is not available"
    Write-Info "tkinter is usually included with Python, but may need to be installed separately"
    Write-Info "On Windows: Reinstall Python with 'tcl/tk and IDLE' option"
    Write-Info "On Linux: sudo apt-get install python3-tk"
    exit 1
}

# Build GUI command
$guiArgs = @(
    $GUI_SCRIPT,
    "--server", $Server
)

Write-Host ""
Write-Info "Starting PKI Manager GUI..."
Write-Info "  Server: $Server"

# Start GUI
try {
    Push-Location $PKI_ROOT
    
    if ($Background) {
        # Start in background (not recommended for GUI)
        Write-Warning-Msg "Starting GUI in background (window may not be visible)..."
        
        $process = Start-Process -FilePath "python" `
                                 -ArgumentList $guiArgs `
                                 -PassThru `
                                 -WindowStyle Normal
        
        # Save PID
        $process.Id | Out-File $PID_FILE -Encoding ASCII
        
        Write-Host ""
        Write-Success "PKI Manager GUI started!"
        Write-Success "  PID: $($process.Id)"
        Write-Info "  Stop GUI: .\scripts\stop_frontend.ps1"
        
    } else {
        # Start in foreground (normal for GUI apps)
        Write-Info "Starting GUI (close window to stop)..."
        Write-Host ""
        
        $process = Start-Process -FilePath "python" `
                                 -ArgumentList $guiArgs `
                                 -PassThru `
                                 -Wait `
                                 -WindowStyle Normal
        
        Write-Host ""
        Write-Success "GUI closed"
    }
    
} catch {
    Write-Error-Msg "Failed to start GUI: $_"
    exit 1
} finally {
    Pop-Location
}

Write-Host ""
