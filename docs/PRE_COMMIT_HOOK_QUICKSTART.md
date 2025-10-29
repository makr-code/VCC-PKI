# VCC Pre-Commit Hook - Quick Start

**⏱️ Setup Time:** 5 minutes  
**Status:** ✅ Ready to install

---

## What is it?

The **VCC Pre-Commit Hook** automatically validates your code before commits:

✅ Ensures all files have **VCC headers** (copyright, version, classification)  
🚨 Blocks **hard-coded secrets** (passwords, API keys, private keys)  
⚠️ Warns about **classification mismatches**  
✅ Verifies **header integrity** (detects unauthorized changes)

---

## Quick Demo (No Installation Required)

```powershell
# Run standalone demo
cd C:\VCC\PKI
.\scripts\demo_pre_commit_hook.ps1
```

**Expected Output:**
```
✓ Test 1: Valid File with Header → PASSED
✓ Test 2: File Without Header → PASSED (correctly rejected)
✓ Test 3: File with Secret → PASSED (correctly rejected)
✓ Test 4: Classification Mismatch → PASSED (warned but allowed)

Tests Passed: 4/4 (100%)
```

---

## Installation (5 Minutes)

### Step 1: Initialize Git Repository

```powershell
cd C:\VCC\PKI
git init
```

### Step 2: Copy Hook Script

```powershell
# Copy PowerShell hook
Copy-Item scripts\pre-commit.ps1 .git\hooks\pre-commit.ps1

# Create wrapper script
@'
#!/bin/sh
exec pwsh -File "$(dirname "$0")/pre-commit.ps1" "$@"
'@ | Out-File -Encoding ASCII -NoNewline .git\hooks\pre-commit
```

### Step 3: Test Installation

```powershell
# Create test file with header
echo "def test(): pass" > test_file.py
python src\code_header.py generate --file test_file.py

# Stage and commit
git add test_file.py
git commit -m "Test commit"

# Expected output:
# ✓ test_file.py
# ✓ All 1 file(s) passed validation!
```

---

## Usage Examples

### ✅ Successful Commit

```powershell
# 1. Create file with header
python src\code_header.py generate --file src\my_module.py

# 2. Commit
git add src\my_module.py
git commit -m "Add new module"

# Output: ✓ All files passed validation!
```

---

### ❌ Missing Header (Blocked)

```powershell
# 1. Try to commit without header
echo "def test(): pass" > src\test.py
git add src\test.py
git commit -m "Add test"

# Output:
# ✗ src\test.py
#   Missing VCC header
# COMMIT REJECTED!

# 2. Fix it
python src\code_header.py generate --file src\test.py
git add src\test.py
git commit -m "Add test"

# Output: ✓ All files passed validation!
```

---

### 🚨 Hard-Coded Secret (Blocked)

```powershell
# 1. Try to commit with secret
echo 'password = "secret123"' > src\config.py
git add src\config.py
git commit -m "Add config"

# Output:
# ✗ src\config.py
#   SECURITY VIOLATION: Hard-coded password
# COMMIT REJECTED!

# 2. Fix it
echo 'password = os.environ.get("PASSWORD")' > src\config.py
git add src\config.py
git commit -m "Add config"

# Output: ✓ All files passed validation!
```

---

## Common Commands

### Generate Header

```powershell
# Basic
python src\code_header.py generate --file my_module.py

# With options
python src\code_header.py generate `
    --file my_module.py `
    --version 1.0.0 `
    --author "Your Name" `
    --classification CONFIDENTIAL
```

### Extract Header

```powershell
python src\code_header.py extract --file my_module.py
```

### Verify Integrity

```powershell
python src\code_header.py verify --file my_module.py
```

### Auto-Classify

```powershell
python src\classify_code.py --file my_module.py --suggest
```

---

## Bypass (Emergency Only)

```powershell
# Skip validation (NOT RECOMMENDED!)
git commit --no-verify -m "HOTFIX: Critical bug"
```

⚠️ **Only use in emergencies!**

---

## Troubleshooting

### Hook Not Running

```powershell
# Check hook exists
Test-Path .git\hooks\pre-commit  # Should return True

# Test manually
pwsh .git\hooks\pre-commit.ps1
```

### Import Errors

```powershell
# Ensure you're in repository root
cd C:\VCC\PKI

# Check files exist
Test-Path src\code_header.py    # Should return True
Test-Path src\classify_code.py  # Should return True
```

---

## What's Validated?

| Check | Action | Severity |
|-------|--------|----------|
| **Missing VCC Header** | Block commit | ❌ ERROR |
| **Hard-coded Secret** | Block commit | 🚨 CRITICAL |
| **Classification Mismatch** | Warn (allow commit) | ⚠️ WARNING |
| **Header Integrity** | Warn (allow commit) | ⚠️ WARNING |

---

## Next Steps

1. ✅ Install hook (see above)
2. ✅ Test with demo (`.\scripts\demo_pre_commit_hook.ps1`)
3. ⏳ Apply classification to all files
4. ⏳ Train your team
5. ⏳ Set up CI/CD integration

---

## Documentation

- **Full Guide:** `docs\PRE_COMMIT_HOOK_GUIDE.md` (650 lines)
- **Implementation:** `docs\PRE_COMMIT_HOOK_COMPLETE.md` (400 lines)
- **Classification:** `docs\CLASSIFICATION_GUIDE.md` (5,000 lines)

---

## Need Help?

Run the demo to see how it works:
```powershell
.\scripts\demo_pre_commit_hook.ps1
```

---

**Quick Start Version:** 1.0.0  
**Last Updated:** 2025-10-13
