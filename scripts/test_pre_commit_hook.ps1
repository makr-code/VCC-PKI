#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test VCC Pre-Commit Hook Installation

.DESCRIPTION
    Tests the pre-commit hook with sample scenarios:
    1. File with valid header (should pass)
    2. File without header (should fail)
    3. File with hard-coded secret (should fail)
    4. File with classification mismatch (should warn)

.NOTES
    Run this after installing the pre-commit hook to verify it works.
#>

param(
    [switch]$Install,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SrcPath = Join-Path $RepoRoot 'src'
$TestDir = Join-Path $RepoRoot 'test_hook_tmp'

# Colors
$Colors = @{
    Red = "`e[91m"
    Green = "`e[92m"
    Yellow = "`e[93m"
    Blue = "`e[94m"
    Cyan = "`e[96m"
    Reset = "`e[0m"
}

function Write-Colored {
    param([string]$Text, [string]$Color = 'White')
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host "$($Colors[$Color])$Text$($Colors.Reset)"
    } else {
        Write-Host $Text
    }
}

function Test-HookInstalled {
    $hookPath = Join-Path $RepoRoot '.git\hooks\pre-commit'
    $hookPsPath = Join-Path $RepoRoot '.git\hooks\pre-commit.ps1'
    
    if ((Test-Path $hookPath) -or (Test-Path $hookPsPath)) {
        Write-Colored "✓ Pre-commit hook installed" 'Green'
        return $true
    } else {
        Write-Colored "✗ Pre-commit hook NOT installed" 'Red'
        Write-Host "  Run with -Install to install automatically"
        return $false
    }
}

function Install-Hook {
    Write-Colored "Installing pre-commit hook..." 'Cyan'
    
    # Copy PowerShell hook
    $sourcePath = Join-Path $PSScriptRoot 'pre-commit.ps1'
    $destPath = Join-Path $RepoRoot '.git\hooks\pre-commit.ps1'
    Copy-Item $sourcePath $destPath -Force
    Write-Colored "  Copied pre-commit.ps1" 'Green'
    
    # Create wrapper script
    $wrapperPath = Join-Path $RepoRoot '.git\hooks\pre-commit'
    $wrapper = @'
#!/bin/sh
exec pwsh -File "$(dirname "$0")/pre-commit.ps1" "$@"
'@
    $wrapper | Out-File -Encoding ASCII -NoNewline $wrapperPath
    Write-Colored "  Created wrapper script" 'Green'
    
    Write-Colored "✓ Pre-commit hook installed successfully!" 'Green'
    Write-Host
}

function New-TestEnvironment {
    # Create test directory
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir
    }
    New-Item -ItemType Directory -Path $TestDir | Out-Null
    
    Write-Colored "Created test environment: $TestDir" 'Cyan'
}

function Remove-TestEnvironment {
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir
    }
    Write-Colored "Cleaned up test environment" 'Green'
}

function Test-Scenario {
    param(
        [string]$Name,
        [string]$Description,
        [scriptblock]$Setup,
        [bool]$ExpectedSuccess
    )
    
    Write-Host
    Write-Colored ("=" * 80) 'Cyan'
    Write-Colored "TEST: $Name" 'Cyan'
    Write-Colored $Description 'White'
    Write-Colored ("=" * 80) 'Cyan'
    Write-Host
    
    # Run setup
    & $Setup
    
    # Stage test file
    $testFile = Join-Path $TestDir 'test_module.py'
    git add $testFile 2>&1 | Out-Null
    
    # Run pre-commit hook
    Write-Colored "Running pre-commit hook..." 'Yellow'
    Write-Host
    
    $hookPath = Join-Path $RepoRoot '.git\hooks\pre-commit.ps1'
    $output = & pwsh $hookPath 2>&1
    $success = $LASTEXITCODE -eq 0
    
    # Display output
    Write-Host $output
    Write-Host
    
    # Check result
    if ($success -eq $ExpectedSuccess) {
        Write-Colored "✓ TEST PASSED" 'Green'
        Write-Host "  Expected: $(if ($ExpectedSuccess) { 'Success' } else { 'Failure' })"
        Write-Host "  Got: $(if ($success) { 'Success' } else { 'Failure' })"
        return $true
    } else {
        Write-Colored "✗ TEST FAILED" 'Red'
        Write-Host "  Expected: $(if ($ExpectedSuccess) { 'Success' } else { 'Failure' })"
        Write-Host "  Got: $(if ($success) { 'Success' } else { 'Failure' })"
        return $false
    }
}

# ==================== Main Test Suite ====================

Write-Colored ("=" * 80) 'Cyan'
Write-Colored "VCC Pre-Commit Hook Test Suite" 'Cyan'
Write-Colored ("=" * 80) 'Cyan'
Write-Host

# Check if in git repository
if (-not (Test-Path (Join-Path $RepoRoot '.git'))) {
    Write-Colored "ERROR: Not a git repository!" 'Red'
    Write-Host "  Run from PKI repository root"
    exit 1
}

# Install hook if requested
if ($Install) {
    Install-Hook
}

# Check hook installed
if (-not (Test-HookInstalled)) {
    Write-Host
    Write-Colored "Run with -Install to install hook automatically:" 'Yellow'
    Write-Host "  .\scripts\test_pre_commit_hook.ps1 -Install"
    exit 1
}

# Create test environment
New-TestEnvironment

# Track test results
$testResults = @()

# ==================== Test 1: Valid File with Header ====================
$testResults += Test-Scenario `
    -Name "Valid File with Header" `
    -Description "File with proper VCC header should pass validation" `
    -ExpectedSuccess $true `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        # Generate file with header
        $content = @'
def hello_world():
    """Simple test function."""
    return "Hello, World!"
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        # Generate header
        & python "$SrcPath\code_header.py" generate `
            --file $testFile `
            --version 1.0.0 `
            --author "Test User" `
            --description "Test module" `
            --classification INTERNAL `
            2>&1 | Out-Null
    }

# ==================== Test 2: File Without Header ====================
$testResults += Test-Scenario `
    -Name "File Without Header" `
    -Description "File missing VCC header should fail validation" `
    -ExpectedSuccess $false `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        # Create file WITHOUT header
        $content = @'
def hello_world():
    """Simple test function."""
    return "Hello, World!"
'@
        $content | Out-File -Encoding UTF8 $testFile
    }

# ==================== Test 3: File with Hard-Coded Secret ====================
$testResults += Test-Scenario `
    -Name "File with Hard-Coded Secret" `
    -Description "File with hard-coded password should fail validation" `
    -ExpectedSuccess $false `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        # Create file with header and secret
        $content = @'
import os

# Hard-coded password (SECURITY VIOLATION!)
password = "SuperSecret123"

def connect_database():
    """Connect to database."""
    return f"Connected with {password}"
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        # Generate header (but secret will be detected)
        & python "$SrcPath\code_header.py" generate `
            --file $testFile `
            --version 1.0.0 `
            --classification INTERNAL `
            2>&1 | Out-Null
    }

# ==================== Test 4: File with Classification Mismatch ====================
$testResults += Test-Scenario `
    -Name "File with Classification Mismatch" `
    -Description "File with mismatched classification should warn but pass" `
    -ExpectedSuccess $true `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        # Create file with CONFIDENTIAL content but INTERNAL classification
        $content = @'
import hashlib

def verify_password(password_hash, password):
    """
    Verify password against hash.
    
    Uses proprietary algorithm for enhanced security.
    """
    # Proprietary password verification (should be CONFIDENTIAL)
    salt = "vcc_salt_123"
    computed_hash = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    return computed_hash == password_hash
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        # Generate header with INTERNAL (wrong classification)
        & python "$SrcPath\code_header.py" generate `
            --file $testFile `
            --version 1.0.0 `
            --classification INTERNAL `
            2>&1 | Out-Null
    }

# ==================== Summary ====================

# Unstage all test files
git reset HEAD $TestDir 2>&1 | Out-Null

# Clean up
Remove-TestEnvironment

Write-Host
Write-Colored ("=" * 80) 'Cyan'
Write-Colored "TEST SUMMARY" 'Cyan'
Write-Colored ("=" * 80) 'Cyan'
Write-Host

$passed = ($testResults | Where-Object { $_ -eq $true }).Count
$total = $testResults.Count

Write-Host "Tests Passed: $passed / $total"
Write-Host

if ($passed -eq $total) {
    Write-Colored "✓ ALL TESTS PASSED!" 'Green'
    Write-Host
    Write-Colored "Pre-commit hook is working correctly." 'Green'
    Write-Host "You can now commit with confidence:"
    Write-Host "  git add src/my_module.py"
    Write-Host "  git commit -m 'Add new module'"
    exit 0
} else {
    Write-Colored "✗ SOME TESTS FAILED!" 'Red'
    Write-Host
    Write-Colored "Please check the hook installation:" 'Yellow'
    Write-Host "  .\scripts\test_pre_commit_hook.ps1 -Install"
    exit 1
}
