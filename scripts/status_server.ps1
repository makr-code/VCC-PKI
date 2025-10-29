#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Check VCC PKI Server Status

.DESCRIPTION
    Checks the status of the VCC PKI Server and displays health information.

.PARAMETER Port
    Server port (default: 8443)

.PARAMETER Detailed
    Show detailed health information

.EXAMPLE
    .\status_server.ps1
    .\status_server.ps1 -Detailed

.NOTES
    Author: VCC Team
    Date: 2025-10-13
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8443,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed
)

# Script configuration
$ErrorActionPreference = "Stop"
$PKI_ROOT = Split-Path -Parent $PSScriptRoot
$PID_FILE = Join-Path $PKI_ROOT "pki_server.pid"
$SERVER_URL = "https://localhost:$Port"

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
Write-ColorOutput "    VCC PKI Server - Status Check" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════" "Cyan"
Write-Host ""

# Check PID file
Write-Info "Checking process status..."
$processRunning = $false
$processId = $null

if (Test-Path $PID_FILE) {
    $processId = Get-Content $PID_FILE
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    
    if ($process) {
        $processRunning = $true
        Write-Success "Process is running (PID: $processId)"
        
        # Show process info
        $uptime = (Get-Date) - $process.StartTime
        Write-Info "  Started: $($process.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Info "  Uptime:  $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        Write-Info "  CPU:     $($process.CPU.ToString('0.00'))s"
        Write-Info "  Memory:  $([math]::Round($process.WorkingSet64/1MB, 2)) MB"
    } else {
        Write-Warning-Msg "PID file exists but process not found (PID: $processId)"
        Write-Info "Server may have crashed. Check logs."
    }
} else {
    Write-Warning-Msg "No PID file found"
    Write-Info "Server is not running or was not started with start_server.ps1"
}

# Check HTTP endpoint
Write-Host ""
Write-Info "Checking HTTP endpoint..."

try {
    # Ignore SSL certificate validation for self-signed certs
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    # Create web request
    $request = [System.Net.WebRequest]::Create("$SERVER_URL/api/health")
    $request.Method = "GET"
    $request.Timeout = 5000
    
    # Get response
    $response = $request.GetResponse()
    $stream = $response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $content = $reader.ReadToEnd()
    $reader.Close()
    $stream.Close()
    $response.Close()
    
    Write-Success "Server is responding"
    Write-Info "  URL: $SERVER_URL"
    Write-Info "  Status: $($response.StatusCode) $($response.StatusDescription)"
    
    # Parse JSON response
    if ($Detailed) {
        Write-Host ""
        Write-Info "Health Details:"
        Write-ColorOutput "─────────────────────────────────────────────────────" "Gray"
        
        try {
            $health = $content | ConvertFrom-Json
            
            # Overall status
            $statusColor = if ($health.status -eq "healthy") { "Green" } else { "Yellow" }
            Write-ColorOutput "  Overall Status: $($health.status.ToUpper())" $statusColor
            
            # Components
            if ($health.components) {
                Write-Host ""
                Write-Info "  Components:"
                foreach ($comp in $health.components.PSObject.Properties) {
                    $compColor = if ($comp.Value -eq "healthy") { "Green" } else { "Red" }
                    $icon = if ($comp.Value -eq "healthy") { "✓" } else { "✗" }
                    Write-ColorOutput "    $icon $($comp.Name): $($comp.Value)" $compColor
                }
            }
            
            # Statistics
            if ($health.statistics) {
                Write-Host ""
                Write-Info "  Statistics:"
                Write-Info "    Total Certificates:    $($health.statistics.total_certificates)"
                Write-Info "    Active Certificates:   $($health.statistics.active_certificates)"
                Write-Info "    Revoked Certificates:  $($health.statistics.revoked_certificates)"
                Write-Info "    Registered Services:   $($health.statistics.registered_services)"
            }
            
            # Server info
            if ($health.version) {
                Write-Host ""
                Write-Info "  Server Info:"
                Write-Info "    Version: $($health.version)"
                if ($health.uptime) {
                    Write-Info "    Uptime:  $($health.uptime)"
                }
            }
            
        } catch {
            Write-Warning-Msg "Could not parse health response"
            Write-Host $content
        }
    }
    
} catch [System.Net.WebException] {
    Write-Error-Msg "Server is NOT responding"
    Write-Info "  URL: $SERVER_URL"
    Write-Info "  Error: $($_.Exception.Message)"
    
    if ($processRunning) {
        Write-Warning-Msg "Process is running but not responding"
        Write-Info "Server may be starting up or having issues"
    }
    
} catch {
    Write-Error-Msg "Failed to check server: $_"
}

# Summary
Write-Host ""
Write-ColorOutput "═══════════════════════════════════════════════════════" "Gray"

if ($processRunning -and $response) {
    Write-Success "PKI Server is RUNNING and HEALTHY"
} elseif ($processRunning) {
    Write-Warning-Msg "PKI Server is RUNNING but NOT RESPONDING"
} else {
    Write-Error-Msg "PKI Server is NOT RUNNING"
}

Write-Host ""
