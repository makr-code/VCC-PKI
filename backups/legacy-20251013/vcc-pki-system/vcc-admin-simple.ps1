# VCC PKI System - PowerShell Administration Wrapper
# Simple wrapper for Windows administrators

param(
    [Parameter(Position=0)]
    [string]$Command = "help",
    [switch]$Verbose,
    [int]$Days = 30,
    [string]$BackupName,
    [string]$BackupType = "manual"
)

function Show-Help {
    Write-Host ""
    Write-Host "VCC PKI System - Administration Tool" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "COMMANDS:" -ForegroundColor Yellow
    Write-Host "  health          - Run system health check"
    Write-Host "  backup          - Create system backup"
    Write-Host "  expiry-check    - Check certificate expiry"
    Write-Host "  expiry-report   - Generate expiry report"
    Write-Host "  db-stats        - Show database statistics"
    Write-Host "  db-maintenance  - Run database maintenance"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\vcc-pki-admin.ps1 health -Verbose"
    Write-Host "  .\vcc-pki-admin.ps1 backup -BackupType manual"
    Write-Host "  .\vcc-pki-admin.ps1 expiry-check -Days 30"
    Write-Host ""
}

# Check Python
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Python not found" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error: Python not installed" -ForegroundColor Red
    exit 1
}

# Execute command
switch ($Command.ToLower()) {
    "health" { 
        Write-Host "Running health check..." -ForegroundColor Green
        if ($Verbose) {
            & python "vcc-pki-admin.py" "health" "--verbose"
        } else {
            & python "vcc-pki-admin.py" "health"
        }
    }
    "backup" { 
        Write-Host "Creating backup..." -ForegroundColor Green
        $args = @("vcc-pki-admin.py", "backup", "--type", $BackupType)
        if ($BackupName) { $args += @("--name", $BackupName) }
        & python @args
    }
    "expiry-check" { 
        Write-Host "Checking certificate expiry..." -ForegroundColor Green
        & python "vcc-pki-admin.py" "expiry-check" "--days" $Days
    }
    "expiry-report" { 
        Write-Host "Generating expiry report..." -ForegroundColor Green
        & python "vcc-pki-admin.py" "expiry-report"
    }
    "db-stats" { 
        Write-Host "Getting database statistics..." -ForegroundColor Green
        & python "vcc-pki-admin.py" "db-stats"
    }
    "db-maintenance" { 
        Write-Host "Running database maintenance..." -ForegroundColor Green
        & python "vcc-pki-admin.py" "db-maintenance"
    }
    default { 
        Show-Help
    }
}

Write-Host "Operation completed." -ForegroundColor Green