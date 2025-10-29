# VCC PKI System - PowerShell Administration Wrapper
# Convenience wrapper for Windows administrators

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet(
        "health", "backup", "restore", "expiry-check", "expiry-report", 
        "db-stats", "db-maintenance", "cleanup-logs", "monitor", "help"
    )]
    [string]$Command = "help",
    
    [Parameter()]
    [switch]$Verbose,
    
    [Parameter()]
    [int]$Days = 30,
    
    [Parameter()]
    [string]$BackupName,
    
    [Parameter()]
    [ValidateSet("manual", "daily", "weekly", "monthly")]
    [string]$BackupType = "manual",
    
    [Parameter()]
    [string]$RestorePath,
    
    [Parameter()]
    [switch]$DryRun,
    
    [Parameter()]
    [switch]$Continuous
)

# Set console encoding for emoji support
if ($PSVersionTable.PSVersion.Major -ge 7) {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}

# Colors for output
$colors = @{
    Success = "Green"
    Warning = "Yellow" 
    Error = "Red"
    Info = "Cyan"
    Header = "Magenta"
}

function Write-Header {
    param([string]$Text)
    Write-Host "`n$Text" -ForegroundColor $colors.Header
    Write-Host ("=" * $Text.Length) -ForegroundColor $colors.Header
}

function Write-Status {
    param([string]$Text, [string]$Status = "Info")
    Write-Host $Text -ForegroundColor $colors[$Status]
}

function Show-Help {
    Write-Header "VCC PKI System - PowerShell Administration Tool"
    
    Write-Host @"

USAGE:
    .\vcc-pki-admin.ps1 <command> [options]

COMMANDS:
    health              Run system health check
    backup              Create system backup
    restore             Restore from backup
    expiry-check        Check certificate expiry
    expiry-report       Generate expiry report
    db-stats            Show database statistics
    db-maintenance      Run database maintenance
    cleanup-logs        Clean up old audit logs
    monitor             Start health monitoring
    help                Show this help

EXAMPLES:
    # System health check with verbose output
    .\vcc-pki-admin.ps1 health -Verbose
    
    # Create manual backup
    .\vcc-pki-admin.ps1 backup -BackupType manual -BackupName "monthly-backup"
    
    # Check certificates expiring in 30 days
    .\vcc-pki-admin.ps1 expiry-check -Days 30
    
    # Generate expiry report
    .\vcc-pki-admin.ps1 expiry-report
    
    # Database maintenance
    .\vcc-pki-admin.ps1 db-maintenance
    
    # Restore from backup (dry run)
    .\vcc-pki-admin.ps1 restore -RestorePath "backup.tar.gz" -DryRun
    
    # Start continuous monitoring
    .\vcc-pki-admin.ps1 monitor -Continuous

OPTIONS:
    -Verbose            Enable verbose output
    -Days <number>      Number of days for expiry check (default: 30)
    -BackupName         Custom backup name
    -BackupType         Backup type: manual, daily, weekly, monthly
    -RestorePath        Path to backup file for restoration
    -DryRun             Simulate operations without making changes
    -Continuous         Run continuous monitoring

"@ -ForegroundColor White
}

function Test-Prerequisites {
    # Check Python installation
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Status "❌ Python not found. Please install Python 3.8 or higher." "Error"
            return $false
        }
        Write-Status "✅ Python found: $pythonVersion" "Success"
    } catch {
        Write-Status "❌ Python not installed or not in PATH" "Error"
        return $false
    }
    
    # Check if we're in the correct directory
    if (-not (Test-Path "vcc-pki-admin.py")) {
        Write-Status "❌ vcc-pki-admin.py not found. Please run from VCC PKI directory." "Error"
        return $false
    }
    
    return $true
}

function Invoke-HealthCheck {
    Write-Header "VCC PKI System Health Check"
    
    $args = @("vcc-pki-admin.py", "health")
    if ($Verbose) { $args += "--verbose" }
    
    try {
        & python @args
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Health check completed successfully" "Success"
        } else {
            Write-Status "⚠️  Health check found issues (exit code: $LASTEXITCODE)" "Warning"
        }
    } catch {
        Write-Status "❌ Health check failed: $_" "Error"
    }
}

function Invoke-Backup {
    Write-Header "VCC PKI System Backup"
    
    $args = @("vcc-pki-admin.py", "backup", "--type", $BackupType)
    if ($BackupName) { $args += @("--name", $BackupName) }
    
    try {
        Write-Status "Creating $BackupType backup..." "Info"
        & python @args
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Backup completed successfully" "Success"
        } else {
            Write-Status "❌ Backup failed (exit code: $LASTEXITCODE)" "Error"
        }
    } catch {
        Write-Status "❌ Backup failed: $_" "Error"
    }
}

function Invoke-ExpiryCheck {
    Write-Header "Certificate Expiry Check"
    
    try {
        Write-Status "Checking certificates expiring within $Days days..." "Info"
        & python "vcc-pki-admin.py" "expiry-check" "--days" $Days
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Expiry check completed" "Success"
        } else {
            Write-Status "⚠️  Found expiring certificates (exit code: $LASTEXITCODE)" "Warning"
        }
    } catch {
        Write-Status "❌ Expiry check failed: $_" "Error"
    }
}

function Invoke-ExpiryReport {
    Write-Header "Certificate Expiry Report"
    
    try {
        Write-Status "Generating expiry report..." "Info"
        & python "vcc-pki-admin.py" "expiry-report"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Report generated successfully" "Success"
        } else {
            Write-Status "❌ Report generation failed (exit code: $LASTEXITCODE)" "Error"
        }
    } catch {
        Write-Status "❌ Report generation failed: $_" "Error"
    }
}

function Invoke-DatabaseStats {
    Write-Header "Database Statistics"
    
    try {
        & python "vcc-pki-admin.py" "db-stats"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Statistics retrieved successfully" "Success"
        } else {
            Write-Status "❌ Failed to retrieve statistics (exit code: $LASTEXITCODE)" "Error"
        }
    } catch {
        Write-Status "❌ Database stats failed: $_" "Error"
    }
}

function Invoke-DatabaseMaintenance {
    Write-Header "Database Maintenance"
    
    try {
        Write-Status "Running database maintenance (VACUUM, ANALYZE, REINDEX)..." "Info"
        & python "vcc-pki-admin.py" "db-maintenance"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Database maintenance completed successfully" "Success"
        } else {
            Write-Status "❌ Database maintenance failed (exit code: $LASTEXITCODE)" "Error"
        }
    } catch {
        Write-Status "❌ Database maintenance failed: $_" "Error"
    }
}

function Invoke-LogCleanup {
    Write-Header "Audit Log Cleanup"
    
    try {
        Write-Status "Cleaning up audit logs older than $Days days..." "Info"
        & python "vcc-pki-admin.py" "cleanup-logs" "--days" $Days
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Log cleanup completed successfully" "Success"
        } else {
            Write-Status "❌ Log cleanup failed (exit code: $LASTEXITCODE)" "Error"
        }
    } catch {
        Write-Status "❌ Log cleanup failed: $_" "Error"
    }
}

function Invoke-Restore {
    if (-not $RestorePath) {
        Write-Status "❌ RestorePath parameter required for restore command" "Error"
        return
    }
    
    Write-Header "System Restoration"
    
    if ($DryRun) {
        Write-Status "🔍 DRY RUN MODE - No changes will be made" "Warning"
    } else {
        Write-Status "⚠️  WARNING: This will overwrite current system data!" "Warning"
        $confirm = Read-Host "Type 'YES' to confirm restoration"
        if ($confirm -ne "YES") {
            Write-Status "❌ Restoration cancelled by user" "Warning"
            return
        }
    }
    
    $args = @("vcc-pki-admin.py", "restore", $RestorePath)
    if ($DryRun) { $args += "--dry-run" }
    
    try {
        & python @args
        
        if ($LASTEXITCODE -eq 0) {
            if ($DryRun) {
                Write-Status "✅ Dry run completed successfully" "Success"
            } else {
                Write-Status "✅ Restoration completed successfully" "Success"
            }
        } else {
            Write-Status "❌ Restoration failed (exit code: $LASTEXITCODE)" "Error"
        }
    } catch {
        Write-Status "❌ Restoration failed: $_" "Error"
    }
}

# Main execution
try {
    Write-Header "VCC PKI System Administration"
    Write-Host "Land Brandenburg - Verwaltungscloud-Computing (VCC)" -ForegroundColor Gray
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    # Execute command
    switch ($Command.ToLower()) {
        "health" { Invoke-HealthCheck }
        "backup" { Invoke-Backup }
        "restore" { Invoke-Restore }
        "expiry-check" { Invoke-ExpiryCheck }
        "expiry-report" { Invoke-ExpiryReport }
        "db-stats" { Invoke-DatabaseStats }
        "db-maintenance" { Invoke-DatabaseMaintenance }
        "cleanup-logs" { Invoke-LogCleanup }
        "monitor" { 
            if ($Continuous) {
                Write-Status "Starting continuous monitoring (Ctrl+C to stop)..." "Info"
                & python "vcc-pki-monitor.py" "--continuous"
            } else {
                & python "vcc-pki-monitor.py" "--health-check"
            }
        }
        "help" { Show-Help }
        default { 
            Write-Status "❌ Unknown command: $Command" "Error"
            Show-Help
            exit 1
        }
    }
    
} catch {
    Write-Status "❌ Unexpected error: $_" "Error"
    exit 1
}

Write-Host "`n✨ VCC PKI Administration completed`n" -ForegroundColor Green