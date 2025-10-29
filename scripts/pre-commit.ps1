#!/usr/bin/env pwsh
<#
.SYNOPSIS
    VCC Git Pre-Commit Hook (PowerShell Version)

.DESCRIPTION
    Automatically validates code classification before commit:
    1. Check that all .py files have VCC headers
    2. Verify classification is appropriate
    3. Scan for hard-coded secrets
    4. Verify header integrity

.NOTES
    Installation:
        # Copy to git hooks directory
        Copy-Item scripts\pre-commit.ps1 .git\hooks\pre-commit.ps1
        
        # Configure git to run PowerShell hooks
        git config core.hooksPath .git/hooks
        
        # Create wrapper script .git/hooks/pre-commit (Unix-style)
        @'
        #!/bin/sh
        exec pwsh -File "$(dirname "$0")/pre-commit.ps1" "$@"
        '@ | Out-File -Encoding ASCII -NoNewline .git\hooks\pre-commit
        
    Usage:
        Runs automatically on 'git commit'
        To bypass (emergency only): git commit --no-verify
#>

param(
    [switch]$Verbose
)

# ==================== Configuration ====================

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SrcPath = Join-Path $RepoRoot 'src'

# Colors for output
$Colors = @{
    Red = "`e[91m"
    Green = "`e[92m"
    Yellow = "`e[93m"
    Blue = "`e[94m"
    Cyan = "`e[96m"
    White = "`e[97m"
    Bold = "`e[1m"
    Reset = "`e[0m"
}

function Write-Colored {
    param(
        [string]$Text,
        [string]$Color = 'White'
    )
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host "$($Colors[$Color])$Text$($Colors.Reset)"
    } else {
        Write-Host $Text
    }
}

# ==================== Git Helper Functions ====================

function Get-StagedPythonFiles {
    <#
    .SYNOPSIS
        Get list of staged Python files
    #>
    try {
        $output = git diff --cached --name-only --diff-filter=ACM 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "git diff failed: $output"
        }
        
        $files = $output -split "`n" | Where-Object { 
            $_ -match '\.py$' -and (Test-Path $_)
        }
        
        return $files
    }
    catch {
        Write-Colored "ERROR: Failed to get staged files: $_" 'Red'
        return @()
    }
}

# ==================== Validation Functions ====================

function Test-VCCHeader {
    param([string]$FilePath)
    
    try {
        $result = & python "$SrcPath\code_header.py" extract --file $FilePath 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            return @{
                Success = $false
                Error = "Missing VCC header in $FilePath"
                Fix = "python src\code_header.py generate --file $FilePath"
            }
        }
        
        return @{ Success = $true }
    }
    catch {
        return @{
            Success = $false
            Error = "Failed to check header: $_"
        }
    }
}

function Test-Classification {
    param([string]$FilePath)
    
    try {
        # Run classifier
        $result = & python "$SrcPath\classify_code.py" --file $FilePath --format json 2>&1 | ConvertFrom-Json
        
        # Check for security violations
        if ($result.suggested_classification -eq 'ERROR') {
            return @{
                Success = $false
                Errors = @(
                    "SECURITY VIOLATION in ${FilePath}:",
                    "  $($result.reasons[0])",
                    "  DO NOT COMMIT THIS FILE!"
                )
            }
        }
        
        # Get current classification from header
        $header = & python "$SrcPath\code_header.py" extract --file $FilePath --format json 2>&1 | ConvertFrom-Json
        $currentClass = $header.security_info.classification
        $suggestedClass = $result.suggested_classification
        
        # Classification levels
        $levels = @{
            'PUBLIC' = 1
            'INTERNAL' = 2
            'CONFIDENTIAL' = 3
            'SECRET' = 4
        }
        
        $currentLevel = $levels[$currentClass]
        $suggestedLevel = $levels[$suggestedClass]
        $diff = [Math]::Abs($currentLevel - $suggestedLevel)
        
        if ($diff -ge 2) {
            return @{
                Success = $true
                Warnings = @(
                    "Classification mismatch in ${FilePath}:",
                    "  Current: $currentClass, Suggested: $suggestedClass",
                    "  Confidence: $([int]($result.confidence * 100))%",
                    "  Reasons: $($result.reasons[0..1] -join ', ')",
                    "  Consider re-classifying or review manually."
                )
            }
        }
        
        return @{ Success = $true; Warnings = @() }
    }
    catch {
        return @{
            Success = $true
            Warnings = @("Failed to check classification: $_")
        }
    }
}

function Test-Secrets {
    param([string]$FilePath)
    
    $content = Get-Content -Path $FilePath -Raw -ErrorAction SilentlyContinue
    if (-not $content) {
        return @{ Success = $true }
    }
    
    $errors = @()
    
    # Forbidden patterns (using single quotes to avoid escaping issues)
    $patterns = @(
        @{ Pattern = 'password\s*=\s*["''](?!.*\$\{)[\w@#$%]{8,}["'']'; Description = 'Hard-coded password' },
        @{ Pattern = 'api_key\s*=\s*["''][A-Za-z0-9]{20,}["'']'; Description = 'Hard-coded API key' },
        @{ Pattern = '-----BEGIN (?:RSA )?PRIVATE KEY-----'; Description = 'Embedded private key' },
        @{ Pattern = 'aws_secret_access_key\s*='; Description = 'AWS secret key' },
        @{ Pattern = 'AKIA[0-9A-Z]{16}'; Description = 'AWS access key ID' }
    )
    
    foreach ($p in $patterns) {
        $regexMatches = [regex]::Matches($content, $p.Pattern, 'IgnoreCase,Multiline')
        foreach ($match in $regexMatches) {
            $lineNum = ($content.Substring(0, $match.Index) -split "`n").Count
            $errors += "SECURITY VIOLATION in ${FilePath}:${lineNum}:"
            $errors += "  $($p.Description)"
            $errors += "  Matched: $($match.Value.Substring(0, [Math]::Min(50, $match.Value.Length)))..."
        }
    }
    
    if ($errors.Count -gt 0) {
        return @{ Success = $false; Errors = $errors }
    }
    
    return @{ Success = $true }
}

function Test-HeaderIntegrity {
    param([string]$FilePath)
    
    try {
        $result = & python "$SrcPath\code_header.py" verify --file $FilePath 2>&1
        
        if ($result -match 'Hash mismatch' -or $result -match 'integrity failed') {
            return @{
                Success = $true
                Warnings = @(
                    "Header integrity mismatch in ${FilePath}:",
                    "  Code changed since header generation.",
                    "  Run: python src\code_header.py generate --file $FilePath"
                )
            }
        }
        
        return @{ Success = $true; Warnings = @() }
    }
    catch {
        return @{
            Success = $true
            Warnings = @("Failed to verify header integrity: $_")
        }
    }
}

# ==================== Main Pre-Commit Logic ====================

function Invoke-PreCommitChecks {
    Write-Colored ('=' * 80) 'Cyan'
    Write-Colored 'VCC Pre-Commit Hook - Code Classification Validation' 'Cyan'
    Write-Colored ('=' * 80) 'Cyan'
    Write-Host
    
    # Get staged files
    $stagedFiles = Get-StagedPythonFiles
    
    if ($stagedFiles.Count -eq 0) {
        Write-Colored 'No Python files staged for commit.' 'Green'
        return 0
    }
    
    Write-Host "Checking $($stagedFiles.Count) Python file(s)..."
    Write-Host
    
    # Track results
    $allErrors = @()
    $allWarnings = @()
    $checkedFiles = 0
    
    # Check each file
    foreach ($file in $stagedFiles) {
        $checkedFiles++
        $fileWarnings = @()
        $fileErrors = @()
        
        # 1. Check for VCC header
        $result = Test-VCCHeader -FilePath $file
        if (-not $result.Success) {
            $fileErrors += $result.Error
            if ($result.Fix) {
                $fileErrors += "  Fix: $($result.Fix)"
            }
        }
        
        # 2. Check for hard-coded secrets (CRITICAL)
        if ($result.Success) {
            $secretResult = Test-Secrets -FilePath $file
            if (-not $secretResult.Success) {
                $fileErrors += $secretResult.Errors
            }
        }
        
        # 3. Check classification appropriateness
        if ($result.Success) {
            $classResult = Test-Classification -FilePath $file
            if (-not $classResult.Success) {
                $fileErrors += $classResult.Errors
            } elseif ($classResult.Warnings) {
                $fileWarnings += $classResult.Warnings
            }
        }
        
        # 4. Check header integrity
        if ($result.Success) {
            $integrityResult = Test-HeaderIntegrity -FilePath $file
            if ($integrityResult.Warnings) {
                $fileWarnings += $integrityResult.Warnings
            }
        }
        
        # Report results for this file
        if ($fileErrors.Count -gt 0) {
            Write-Colored "✗ $file" 'Red'
            foreach ($err in $fileErrors) {
                Write-Colored "  $err" 'Red'
            }
            $allErrors += $fileErrors
        }
        elseif ($fileWarnings.Count -gt 0) {
            Write-Colored "⚠ $file" 'Yellow'
            foreach ($warn in $fileWarnings) {
                Write-Colored "  $warn" 'Yellow'
            }
            $allWarnings += $fileWarnings
        }
        else {
            Write-Colored "✓ $file" 'Green'
        }
    }
    
    Write-Host
    Write-Colored ('=' * 80) 'Cyan'
    
    # Summary
    if ($allErrors.Count -gt 0) {
        Write-Colored "COMMIT REJECTED: $($allErrors.Count) error(s) found!" 'Red'
        Write-Host
        Write-Colored 'Fix the errors above and try again.' 'Red'
        Write-Colored 'To bypass (emergency only): git commit --no-verify' 'Yellow'
        return 1
    }
    
    if ($allWarnings.Count -gt 0) {
        Write-Colored "⚠ $($allWarnings.Count) warning(s) found" 'Yellow'
        Write-Host
        Write-Colored 'Review warnings before commit.' 'Yellow'
        Write-Colored 'Proceeding with commit...' 'Green'
        Write-Host
    }
    else {
        Write-Colored "✓ All $checkedFiles file(s) passed validation!" 'Green'
        Write-Host
    }
    
    return 0
}

# ==================== Entry Point ====================

try {
    $exitCode = Invoke-PreCommitChecks
    exit $exitCode
}
catch {
    Write-Host
    Write-Colored "ERROR: Pre-commit hook failed: $_" 'Red'
    Write-Colored 'To bypass (emergency only): git commit --no-verify' 'Yellow'
    exit 1
}
