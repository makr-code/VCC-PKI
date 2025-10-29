#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Launch VCC Bulk Code Signing GUI

.DESCRIPTION
    Starts the Tkinter GUI for bulk code signing.
    
    Features:
    - Directory browser
    - Key file selection
    - Classification filters
    - Dry-run preview
    - Real-time progress tracking
    - Statistics display
    
.EXAMPLE
    .\start_gui.ps1
    
.NOTES
    Author: VCC Development Team
    Date: 2025-10-13
#>

# Script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VCC Bulk Code Signing - GUI" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] Python: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Python not found!" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from https://www.python.org/" -ForegroundColor Yellow
    exit 1
}

# Check if tkinter is available
Write-Host "[INFO] Checking Tkinter..." -ForegroundColor Cyan
$tkinterTest = python -c "import tkinter; print('OK')" 2>&1

if ($tkinterTest -ne "OK") {
    Write-Host "[ERROR] Tkinter not available!" -ForegroundColor Red
    Write-Host "Tkinter should be included with Python." -ForegroundColor Yellow
    Write-Host "If missing, reinstall Python with Tkinter enabled." -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Tkinter available" -ForegroundColor Green
Write-Host ""

# Check if required files exist
$guiScript = Join-Path $ScriptDir "bulk_sign_gui.py"

if (-not (Test-Path $guiScript)) {
    Write-Host "[ERROR] GUI script not found: $guiScript" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] GUI script: $guiScript" -ForegroundColor Green
Write-Host ""

# Launch GUI
Write-Host "[INFO] Launching GUI..." -ForegroundColor Cyan
Write-Host ""

Set-Location $RootDir

try {
    python $guiScript
}
catch {
    Write-Host ""
    Write-Host "[ERROR] GUI crashed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[INFO] GUI closed." -ForegroundColor Cyan
