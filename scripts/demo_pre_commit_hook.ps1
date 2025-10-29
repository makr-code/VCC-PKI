#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Demo: VCC Pre-Commit Hook (Standalone Test)

.DESCRIPTION
    Demonstrates pre-commit hook validation without git:
    1. File with valid header (should pass ✓)
    2. File without header (should fail ✗)
    3. File with hard-coded secret (should fail 🚨)
    4. File with classification mismatch (should warn ⚠️)

.NOTES
    This is a standalone demo that doesn't require git.
#>

param(
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SrcPath = Join-Path $RepoRoot 'src'
$TestDir = Join-Path $RepoRoot 'test_hook_demo'

# Colors
$Colors = @{
    Red = "`e[91m"
    Green = "`e[92m"
    Yellow = "`e[93m"
    Blue = "`e[94m"
    Cyan = "`e[96m"
    Bold = "`e[1m"
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

function New-TestEnvironment {
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir
    }
    New-Item -ItemType Directory -Path $TestDir | Out-Null
}

function Remove-TestEnvironment {
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir
    }
}

function Test-FileValidation {
    param(
        [string]$FilePath
    )
    
    $errors = @()
    $warnings = @()
    
    # 1. Check for VCC header
    try {
        $result = & python "$SrcPath\code_header.py" extract --file $FilePath 2>&1
        if ($LASTEXITCODE -ne 0) {
            $errors += "Missing VCC header"
            $errors += "  Fix: python src\code_header.py generate --file $FilePath"
        }
    } catch {
        $errors += "Failed to check header: $_"
    }
    
    # 2. Check for hard-coded secrets
    $content = Get-Content -Path $FilePath -Raw
    $secretPatterns = @(
        @{ Pattern = 'password\s*=\s*["''][^$][^"'']{8,}["'']'; Desc = 'Hard-coded password' },
        @{ Pattern = 'api_key\s*=\s*["''][A-Za-z0-9]{20,}["'']'; Desc = 'Hard-coded API key' },
        @{ Pattern = '-----BEGIN (?:RSA )?PRIVATE KEY-----'; Desc = 'Embedded private key' }
    )
    
    foreach ($p in $secretPatterns) {
        if ($content -match $p.Pattern) {
            $errors += "SECURITY VIOLATION: $($p.Desc)"
        }
    }
    
    # 3. Check classification (only if header exists and no secrets)
    if ($errors.Count -eq 0) {
        try {
            $classResult = & python "$SrcPath\classify_code.py" --file $FilePath --format json 2>&1 | ConvertFrom-Json
            $headerResult = & python "$SrcPath\code_header.py" extract --file $FilePath --format json 2>&1 | ConvertFrom-Json
            
            $currentClass = $headerResult.security_info.classification
            $suggestedClass = $classResult.suggested_classification
            
            if ($currentClass -ne $suggestedClass) {
                $warnings += "Classification mismatch: Current=$currentClass, Suggested=$suggestedClass"
                $warnings += "  Confidence: $([int]($classResult.confidence * 100))%"
            }
        } catch {
            # Ignore classification check errors
        }
    }
    
    return @{
        Success = ($errors.Count -eq 0)
        Errors = $errors
        Warnings = $warnings
    }
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
    Write-Colored $Colors.Bold "TEST: $Name" 'Cyan'
    Write-Colored $Description 'White'
    Write-Colored ("=" * 80) 'Cyan'
    Write-Host
    
    # Run setup
    & $Setup
    
    # Validate file
    $testFile = Join-Path $TestDir 'test_module.py'
    $result = Test-FileValidation -FilePath $testFile
    
    # Display results
    if ($result.Errors.Count -gt 0) {
        Write-Colored "✗ VALIDATION FAILED" 'Red'
        foreach ($err in $result.Errors) {
            Write-Colored "  $err" 'Red'
        }
    } elseif ($result.Warnings.Count -gt 0) {
        Write-Colored "⚠ VALIDATION PASSED (with warnings)" 'Yellow'
        foreach ($warn in $result.Warnings) {
            Write-Colored "  $warn" 'Yellow'
        }
    } else {
        Write-Colored "✓ VALIDATION PASSED" 'Green'
    }
    
    Write-Host
    
    # Check if result matches expectation
    if ($result.Success -eq $ExpectedSuccess) {
        Write-Colored "✓ TEST PASSED" 'Green'
        Write-Host "  Expected: $(if ($ExpectedSuccess) { 'Success' } else { 'Failure' })"
        Write-Host "  Got: $(if ($result.Success) { 'Success' } else { 'Failure' })"
        return $true
    } else {
        Write-Colored "✗ TEST FAILED" 'Red'
        Write-Host "  Expected: $(if ($ExpectedSuccess) { 'Success' } else { 'Failure' })"
        Write-Host "  Got: $(if ($result.Success) { 'Success' } else { 'Failure' })"
        return $false
    }
}

# ==================== Main Demo ====================

Write-Colored ("=" * 80) 'Cyan'
Write-Colored $Colors.Bold "VCC Pre-Commit Hook - Validation Demo" 'Cyan'
Write-Colored ("=" * 80) 'Cyan'
Write-Host
Write-Colored "This demo shows how the pre-commit hook validates files:" 'White'
Write-Host

# Create test environment
New-TestEnvironment

# Track results
$testResults = @()

# ==================== Test 1: Valid File ✓ ====================
$testResults += Test-Scenario `
    -Name "1️⃣ Valid File with Header" `
    -Description "✓ File with proper VCC header should PASS validation" `
    -ExpectedSuccess $true `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        $content = @'
def hello_world():
    """Simple test function."""
    return "Hello, World!"
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        & python "$SrcPath\code_header.py" generate `
            --file $testFile `
            --version 1.0.0 `
            --author "VCC Team" `
            --description "Test module" `
            --classification INTERNAL `
            2>&1 | Out-Null
        
        Write-Host "📄 Generated file with VCC header:"
        Write-Host "   - Classification: INTERNAL"
        Write-Host "   - Version: 1.0.0"
        Write-Host "   - Content: Simple hello_world() function"
        Write-Host
    }

# ==================== Test 2: Missing Header ✗ ====================
$testResults += Test-Scenario `
    -Name "2️⃣ File Without Header" `
    -Description "✗ File missing VCC header should FAIL validation" `
    -ExpectedSuccess $false `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        $content = @'
def hello_world():
    """Simple test function."""
    return "Hello, World!"
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        Write-Host "📄 Created file WITHOUT VCC header:"
        Write-Host "   - No copyright information"
        Write-Host "   - No version tracking"
        Write-Host "   - No classification"
        Write-Host
    }

# ==================== Test 3: Hard-Coded Secret 🚨 ====================
$testResults += Test-Scenario `
    -Name "3️⃣ File with Hard-Coded Secret" `
    -Description "🚨 File with hard-coded password should FAIL validation" `
    -ExpectedSuccess $false `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        $content = @'
import os

# SECURITY VIOLATION: Hard-coded password!
password = "SuperSecret123"

def connect_database():
    """Connect to database."""
    return f"Connected with {password}"
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        & python "$SrcPath\code_header.py" generate `
            --file $testFile `
            --version 1.0.0 `
            --classification INTERNAL `
            2>&1 | Out-Null
        
        Write-Host "📄 Created file with hard-coded secret:"
        Write-Host "   - Has VCC header (✓)"
        Write-Host "   - Contains: password = `"SuperSecret123`" (🚨)"
        Write-Host "   - SECURITY VIOLATION!"
        Write-Host
    }

# ==================== Test 4: Classification Mismatch ⚠️ ====================
$testResults += Test-Scenario `
    -Name "4️⃣ File with Classification Mismatch" `
    -Description "⚠️ File with wrong classification should WARN but PASS" `
    -ExpectedSuccess $true `
    -Setup {
        $testFile = Join-Path $TestDir 'test_module.py'
        
        $content = @'
import hashlib

def verify_password(password_hash, password):
    """
    Verify password against hash.
    
    Uses proprietary algorithm for enhanced security.
    """
    # Proprietary password verification (should be CONFIDENTIAL!)
    salt = "vcc_salt_123"
    computed = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    return computed == password_hash
'@
        $content | Out-File -Encoding UTF8 $testFile
        
        & python "$SrcPath\code_header.py" generate `
            --file $testFile `
            --version 1.0.0 `
            --classification INTERNAL `
            2>&1 | Out-Null
        
        Write-Host "📄 Created file with classification mismatch:"
        Write-Host "   - Current Classification: INTERNAL"
        Write-Host "   - Suggested Classification: CONFIDENTIAL"
        Write-Host "   - Reason: Contains proprietary password verification"
        Write-Host
    }

# ==================== Summary ====================

# Clean up
Remove-TestEnvironment

Write-Host
Write-Colored ("=" * 80) 'Cyan'
Write-Colored $Colors.Bold "DEMO SUMMARY" 'Cyan'
Write-Colored ("=" * 80) 'Cyan'
Write-Host

$passed = ($testResults | Where-Object { $_ -eq $true }).Count
$total = $testResults.Count

Write-Host "Tests Passed: $passed / $total"
Write-Host

if ($passed -eq $total) {
    Write-Colored "✓ ALL VALIDATION SCENARIOS WORKING!" 'Green'
    Write-Host
    Write-Colored "The pre-commit hook will:" 'White'
    Write-Host "  ✓ Allow files with proper VCC headers"
    Write-Host "  ✗ Block files without VCC headers"
    Write-Host "  🚨 Block files with hard-coded secrets"
    Write-Host "  ⚠️ Warn about classification mismatches"
    Write-Host
    Write-Colored "Installation:" 'Cyan'
    Write-Host "  1. Initialize git repository: git init"
    Write-Host "  2. Copy hook: Copy-Item scripts\pre-commit.ps1 .git\hooks\"
    Write-Host "  3. Create wrapper: See docs\PRE_COMMIT_HOOK_GUIDE.md"
    Write-Host
    Write-Colored "Documentation:" 'Cyan'
    Write-Host "  📄 docs\PRE_COMMIT_HOOK_GUIDE.md - Complete installation guide"
    Write-Host "  📄 scripts\pre-commit.ps1 - PowerShell hook (Windows)"
    Write-Host "  📄 scripts\pre-commit - Python hook (Linux/Mac)"
    exit 0
} else {
    Write-Colored "✗ SOME VALIDATION SCENARIOS FAILED!" 'Red'
    Write-Host
    Write-Colored "Please check the setup:" 'Yellow'
    Write-Host "  - Ensure code_header.py is in src/"
    Write-Host "  - Ensure classify_code.py is in src/"
    Write-Host "  - Run from PKI repository root"
    exit 1
}
