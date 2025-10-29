# VCC Pre-Commit Hook Installation Guide

## Overview

The VCC Pre-Commit Hook automatically validates code before commit:

✅ **Checks for VCC headers** on all Python files  
✅ **Verifies classification** is appropriate  
✅ **Scans for hard-coded secrets** (passwords, API keys, private keys)  
✅ **Validates header integrity** (hash matches content)  

---

## Installation

### Windows (PowerShell)

```powershell
# 1. Navigate to repository root
cd C:\VCC\PKI

# 2. Copy PowerShell hook
Copy-Item scripts\pre-commit.ps1 .git\hooks\pre-commit.ps1

# 3. Create wrapper script for git
@'
#!/bin/sh
exec pwsh -File "$(dirname "$0")/pre-commit.ps1" "$@"
'@ | Out-File -Encoding ASCII -NoNewline .git\hooks\pre-commit

# 4. Verify installation
git hook run pre-commit  # Git 2.36+
# OR
pwsh .git\hooks\pre-commit.ps1
```

### Linux/Mac (Python)

```bash
# 1. Navigate to repository root
cd /path/to/PKI

# 2. Copy Python hook
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# 3. Verify installation
git hook run pre-commit  # Git 2.36+
# OR
.git/hooks/pre-commit
```

---

## Usage

### Automatic Validation

The hook runs automatically on `git commit`:

```bash
git add src/my_module.py
git commit -m "Add new module"

# Output:
# ================================================================================
# VCC Pre-Commit Hook - Code Classification Validation
# ================================================================================
# 
# Checking 1 Python file(s)...
# 
# ✓ src/my_module.py
# 
# ================================================================================
# ✓ All 1 file(s) passed validation!
```

### Bypass (Emergency Only)

```bash
# Skip pre-commit checks (NOT RECOMMENDED!)
git commit --no-verify -m "Emergency commit"
```

⚠️ **WARNING:** Only use `--no-verify` in emergencies. All commits should pass validation.

---

## Validation Rules

### 1. VCC Header Required ✅

All Python files **must** have a VCC header:

```python
# ==============================================================================
# VCC PROTECTED SOURCE CODE
# ==============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# ...
```

**Fix:**
```bash
python src/code_header.py generate --file src/my_module.py
```

---

### 2. Classification Verification ⚠️

Hook checks if classification matches content:

**Warning Example:**
```
⚠ src/auth_module.py
  Classification mismatch in src/auth_module.py:
    Current: INTERNAL, Suggested: CONFIDENTIAL
    Confidence: 85%
    Reasons: CONFIDENTIAL keywords detected
    Consider re-classifying or review manually.
```

**Fix:**
```bash
# Re-classify if needed
python src/code_header.py generate --file src/auth_module.py --classification CONFIDENTIAL
```

---

### 3. Secret Detection 🚨

Hook **blocks commits** with hard-coded secrets:

**Error Example:**
```
✗ src/config.py
  SECURITY VIOLATION in src/config.py:42:
    Hard-coded password
    Matched: password = "SuperSecret123"
  DO NOT COMMIT THIS FILE!

COMMIT REJECTED: 1 error(s) found!
```

**Fix:**
```python
# WRONG ❌
password = "SuperSecret123"

# RIGHT ✅
password = os.environ.get('DB_PASSWORD')
# OR
from vault import get_secret
password = get_secret('db/password')
```

**Detected Patterns:**
- Hard-coded passwords: `password = "secret123"`
- Hard-coded API keys: `api_key = "ABC123XYZ"`
- Embedded private keys: `-----BEGIN PRIVATE KEY-----`
- AWS credentials: `aws_secret_access_key = "..."`
- AWS access keys: `AKIA1234567890ABCDEF`

---

### 4. Header Integrity ⚠️

Hook warns if code changed since header generation:

**Warning Example:**
```
⚠ src/utils.py
  Header integrity mismatch in src/utils.py:
    Code changed since header generation.
    Run: python src\code_header.py generate --file src/utils.py
```

**Fix:**
```bash
# Regenerate header with current hash
python src/code_header.py generate --file src/utils.py
```

---

## Testing

Test the hook without committing:

```powershell
# Stage files
git add src/my_module.py

# Test hook (Git 2.36+)
git hook run pre-commit

# OR manually
pwsh .git\hooks\pre-commit.ps1  # Windows
.git/hooks/pre-commit           # Linux/Mac
```

---

## Examples

### Example 1: Clean Commit ✅

```powershell
# 1. Create file with header
python src/code_header.py generate --file src/new_module.py

# 2. Stage and commit
git add src/new_module.py
git commit -m "Add new module"

# Output:
# ✓ src/new_module.py
# ✓ All 1 file(s) passed validation!
```

---

### Example 2: Missing Header ❌

```powershell
# 1. Create file WITHOUT header
echo "def hello(): pass" > src/new_module.py

# 2. Try to commit
git add src/new_module.py
git commit -m "Add new module"

# Output:
# ✗ src/new_module.py
#   Missing VCC header in src/new_module.py
#   Fix: python src/code_header.py generate --file src/new_module.py
# 
# COMMIT REJECTED: 1 error(s) found!

# 3. Fix and retry
python src/code_header.py generate --file src/new_module.py
git add src/new_module.py
git commit -m "Add new module"

# Output:
# ✓ src/new_module.py
# ✓ All 1 file(s) passed validation!
```

---

### Example 3: Secret Detection 🚨

```powershell
# 1. Create file with hard-coded secret
echo 'password = "SuperSecret123"' > src/config.py

# 2. Try to commit
git add src/config.py
git commit -m "Add config"

# Output:
# ✗ src/config.py
#   SECURITY VIOLATION in src/config.py:1:
#     Hard-coded password
#     Matched: password = "SuperSecret123"
#   DO NOT COMMIT THIS FILE!
# 
# COMMIT REJECTED: 1 error(s) found!

# 3. Fix by using environment variables
echo 'password = os.environ.get("DB_PASSWORD")' > src/config.py
git add src/config.py
git commit -m "Add config"

# Output:
# ✓ src/config.py
# ✓ All 1 file(s) passed validation!
```

---

### Example 4: Classification Mismatch ⚠️

```powershell
# 1. Create file with INTERNAL classification but CONFIDENTIAL content
python src/code_header.py generate --file src/auth.py --classification INTERNAL

# 2. Add proprietary authentication logic
echo 'def verify_password(hash, password): ...' >> src/auth.py

# 3. Try to commit
git add src/auth.py
git commit -m "Add authentication"

# Output:
# ⚠ src/auth.py
#   Classification mismatch in src/auth.py:
#     Current: INTERNAL, Suggested: CONFIDENTIAL
#     Confidence: 80%
#     Reasons: CONFIDENTIAL keywords detected
#     Consider re-classifying or review manually.
# 
# ⚠ 1 warning(s) found
# Review warnings before commit.
# Proceeding with commit...

# 4. (Optional) Re-classify
python src/code_header.py generate --file src/auth.py --classification CONFIDENTIAL
git add src/auth.py
git commit --amend --no-edit
```

---

## Troubleshooting

### Hook Not Running

**Problem:** Git doesn't execute the hook.

**Solution:**
```powershell
# Check hook is executable (Linux/Mac)
chmod +x .git/hooks/pre-commit

# Check git hooks path
git config core.hooksPath
# Should return: .git/hooks

# Verify hook exists
Test-Path .git\hooks\pre-commit  # Windows
ls -l .git/hooks/pre-commit      # Linux/Mac
```

---

### Python Import Errors

**Problem:** Hook fails with `ImportError: No module named 'code_header'`

**Solution:**
```powershell
# Ensure you're in repository root
cd C:\VCC\PKI

# Check Python can find modules
python -c "import sys; sys.path.insert(0, 'src'); from code_header import HeaderExtractor"

# Verify src/ directory exists
Test-Path src\code_header.py  # Should be True
```

---

### Hook Always Fails

**Problem:** Hook rejects valid commits.

**Solution:**
```powershell
# Run hook with verbose output
pwsh .git\hooks\pre-commit.ps1 -Verbose  # PowerShell
python .git/hooks/pre-commit             # Python

# Check staged files
git diff --cached --name-only

# Manually validate each file
python src/code_header.py extract --file src/my_module.py
python src/classify_code.py --file src/my_module.py --suggest
```

---

### Bypass Hook (Emergency)

**Problem:** Critical bug fix needed, but hook blocks commit.

**Solution:**
```bash
# Bypass pre-commit hook (EMERGENCY ONLY!)
git commit --no-verify -m "HOTFIX: Critical bug #1234"

# ⚠️ Create follow-up task to fix violations
git commit --allow-empty -m "TODO: Fix VCC header violations from commit abc123"
```

---

## Configuration

### Custom Rules

Edit hook files to customize:

**PowerShell:** `.git/hooks/pre-commit.ps1`  
**Python:** `.git/hooks/pre-commit`

**Example:** Allow test files without headers:

```python
# In pre-commit (Python version)
def check_header_exists(file_path: str, content: str):
    # Skip test files
    if file_path.startswith('tests/'):
        return True, None
    
    # ... rest of check
```

---

### Disable Specific Checks

Comment out checks in hook:

```python
# Disable classification check
# success, warnings = check_classification(file_path, content)

# Disable integrity check
# success, warnings = check_header_integrity(file_path, content)
```

---

## Integration with CI/CD

Run validation in CI pipeline:

```yaml
# .github/workflows/pre-commit.yml
name: Pre-Commit Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Run Pre-Commit Checks
        run: |
          # Get changed Python files
          git diff --name-only ${{ github.event.before }} ${{ github.sha }} | grep '\.py$' > changed_files.txt
          
          # Validate each file
          while read file; do
            if [ -f "$file" ]; then
              python scripts/pre-commit
            fi
          done < changed_files.txt
```

---

## Uninstallation

Remove the hook:

```powershell
# Windows
Remove-Item .git\hooks\pre-commit
Remove-Item .git\hooks\pre-commit.ps1

# Linux/Mac
rm .git/hooks/pre-commit
```

---

## Summary

| Check | Action | Severity |
|-------|--------|----------|
| **Missing VCC Header** | Block commit | ❌ ERROR |
| **Hard-coded Secrets** | Block commit | 🚨 CRITICAL |
| **Classification Mismatch** | Warn (allow commit) | ⚠️ WARNING |
| **Header Integrity** | Warn (allow commit) | ⚠️ WARNING |

**Recommended Workflow:**
1. ✅ Always generate headers before committing
2. ✅ Use classification tool to verify
3. ✅ Never hard-code secrets
4. ✅ Regenerate header after major changes

---

## Next Steps

- ✅ Install pre-commit hook (this guide)
- ✅ Test with sample commit
- ⏳ Apply classification to all files (`python src/classify_code.py --scan src/ --recursive --report`)
- ⏳ Set up CI/CD validation
- ⏳ Train team on classification system

---

**Documentation Version:** 1.0.0  
**Last Updated:** 2025-10-13  
**Author:** VCC Development Team
