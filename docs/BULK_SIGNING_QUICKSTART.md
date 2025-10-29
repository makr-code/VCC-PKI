# VCC Bulk Code Signing - Quick Start Guide

**⏱️ Setup Time:** 5 minutes  
**Purpose:** Sign all Python files in VCC directory with cryptographic signatures

---

## What Does It Do?

The **Bulk Code Signing Script** signs all Python files with:

✅ **Digital Signatures** - ECDSA (Elliptic Curve) with SHA-256  
✅ **Enhanced Headers** - Copyright, version, UUID, hashes, classification  
✅ **Auto-Classification** - Automatically determines security level  
✅ **Manifest Database** - Central JSON file tracking all signatures  
✅ **Runtime Verification** - Verifies code before execution  

---

## Quick Start (3 Steps)

### Step 1: Generate Keys (30 seconds)

```powershell
# Generate ECDSA key pair
cd C:\VCC\PKI
python scripts\generate_keys.py --output keys
```

**Output:**
```
✓ Private key saved: keys\private_key.pem  ⚠️ KEEP SECRET!
✓ Public key saved: keys\public_key.pem    ✅ Safe to distribute
```

**⚠️ Important:** Never commit `private_key.pem` to git!

---

### Step 2: Preview (Dry Run)

```powershell
# Preview what will be signed (no changes)
python scripts\bulk_sign_vcc.py `
    --directory src `
    --dry-run `
    --verbose `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

**Expected Output:**
```
============================================================================
VCC Bulk Code Signing
============================================================================

Directory: src
Recursive: True
Dry Run: True

Found 10 Python files

[1/10] ca_manager.py
  [DRY-RUN] Would sign: ca_manager.py as INTERNAL
[2/10] code_manifest.py
  [DRY-RUN] Would sign: code_manifest.py as SECRET
...

SIGNING SUMMARY
============================================================================
Total Files: 10
  Signed:    10 (100.0%)
  Skipped:   0 (0.0%)
  Failed:    0 (0.0%)

By Classification:
  PUBLIC            1 files
  INTERNAL          5 files
  CONFIDENTIAL      3 files
  SECRET            1 files
```

---

### Step 3: Sign Files (Real)

```powershell
# Actually sign files (removes --dry-run)
python scripts\bulk_sign_vcc.py `
    --directory src `
    --verbose `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

**Result:** All files now have cryptographic signatures in headers!

---

## Common Use Cases

### Use Case 1: Sign Entire VCC Directory

```powershell
# Sign all Python files in C:\VCC (recursive)
python scripts\bulk_sign_vcc.py `
    --directory C:\VCC `
    --recursive `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

---

### Use Case 2: Sign Only SECRET/CONFIDENTIAL Files

```powershell
# Sign only high-security files
python scripts\bulk_sign_vcc.py `
    --directory C:\VCC `
    --classification CONFIDENTIAL SECRET `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

---

### Use Case 3: Generate Manifest Database

```powershell
# Sign files + generate JSON manifest
python scripts\bulk_sign_vcc.py `
    --directory C:\VCC `
    --generate-manifest `
    --manifest-output vcc_manifest.json `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

**Output:** `vcc_manifest.json` with all signatures

---

### Use Case 4: Re-Sign All Files (Force)

```powershell
# Re-sign files even if already signed
python scripts\bulk_sign_vcc.py `
    --directory C:\VCC `
    --force `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

---

## What Gets Signed?

### Included:
- ✅ All `.py` files
- ✅ Subdirectories (if `--recursive`)
- ✅ Files without existing signatures
- ✅ Files with invalid signatures (if `--force`)

### Excluded (Default):
- ❌ `__pycache__/`
- ❌ `.git/`
- ❌ `.venv/`, `venv/`, `env/`
- ❌ `node_modules/`
- ❌ `build/`, `dist/`
- ❌ `test_*`, `*_tmp`, `*_temp`
- ❌ `backup_*`

**Custom Exclusions:**
```powershell
# Exclude additional patterns
python scripts\bulk_sign_vcc.py `
    --directory C:\VCC `
    --exclude "experiments" "legacy" "archive" `
    --private-key keys\private_key.pem
```

---

## Classification Levels

The script automatically classifies files:

| Level | Example Files | Criteria |
|-------|---------------|----------|
| **PUBLIC** | `examples/`, MIT License | Open source, no secrets |
| **INTERNAL** | `utils.py`, `config.py` | Internal tools, no business logic |
| **CONFIDENTIAL** | `business_logic.py`, `payment.py` | Proprietary algorithms, customer data |
| **SECRET** | `ca_manager.py`, `key_manager.py` | Cryptographic keys, CA operations |

---

## Manifest Database

### What Is It?

A central JSON file tracking all signed files:

```json
{
  "version": "1.0.0",
  "created_at": "2025-10-13T18:30:00Z",
  "total_files": 150,
  "files": {
    "C:\\VCC\\PKI\\src\\pki_server.py": {
      "classification": "CONFIDENTIAL",
      "signature": "3045022100d8f7e9c1a2b3c4d5e6f7a8b9...",
      "uuid": "8e5707f2-12c3-4bff-8494-4016143b09f0",
      "content_hash": "35e0d147b0231021931e76394fcdf76b...",
      "timestamp": "2025-10-13T18:30:00Z"
    }
  }
}
```

### Why Use It?

- ✅ **Central Inventory**: All signatures in one place
- ✅ **Audit Trail**: Compliance tracking
- ✅ **Fast Verification**: No need to parse files
- ✅ **Integrity Monitoring**: Detect unsigned files

---

## Verification

### Verify Single File

```powershell
# Verify signature is valid
python src\code_manifest.py verify --file src\pki_server.py
```

**Output:**
```
[OK] Signature valid: pki_server.py
  UUID: 8e5707f2-12c3-4bff-8494-4016143b09f0
  Classification: CONFIDENTIAL
  Signed: 2025-10-13T18:30:00Z
```

---

### Runtime Verification

```python
# In your application startup (e.g., main.py)
from runtime_verifier import install_verification_hook

# Install import hook (verifies all imports)
install_verification_hook(
    strict_mode=True,  # Block unsigned code
    public_key_path='keys/public_key.pem'
)

# Now all imports are automatically verified
import my_module  # ← Verified before execution ✅
```

---

## Troubleshooting

### Issue 1: "Invalid key" Error

**Problem:**
```
ValueError: Invalid key
```

**Solution:**
```powershell
# Generate new keys
python scripts\generate_keys.py --output keys

# Use new keys
python scripts\bulk_sign_vcc.py `
    --directory src `
    --private-key keys\private_key.pem `
    --public-key keys\public_key.pem
```

---

### Issue 2: Files Already Signed (Skipped)

**Problem:**
```
[SKIP] Already signed: my_module.py
```

**Solution:**
```powershell
# Force re-signing
python scripts\bulk_sign_vcc.py `
    --directory src `
    --force `
    --private-key keys\private_key.pem
```

---

### Issue 3: Unicode Output Errors

**Problem:**
```
UnicodeEncodeError: 'charmap' codec can't encode characters
```

**Solution:**
```powershell
# Set UTF-8 encoding (PowerShell)
$OutputEncoding = [System.Text.UTF8Encoding]::new()

# Or use Python UTF-8 mode
$env:PYTHONUTF8=1
python scripts\bulk_sign_vcc.py ...
```

---

## Security Best Practices

### Private Key Storage

**Development:**
```
keys/private_key.pem (encrypted drive, NOT in git)
```

**Production:**
```
HSM (Hardware Security Module) - BEST ⭐⭐⭐⭐⭐
TPM (Trusted Platform Module) - GOOD ⭐⭐⭐⭐
Encrypted file + passphrase - ACCEPTABLE ⭐⭐⭐
```

---

### .gitignore

Add to `.gitignore`:
```
# Private keys (NEVER COMMIT!)
keys/private_key.pem
*.pem
*.key

# Manifest database (optional)
vcc_manifest.json
```

---

### Key Rotation

Rotate keys annually:

```powershell
# 1. Generate new keys
python scripts\generate_keys.py --output keys/2026

# 2. Re-sign all code
python scripts\bulk_sign_vcc.py `
    --directory C:\VCC `
    --force `
    --private-key keys/2026/private_key.pem

# 3. Update runtime_verifier.py with new public key
```

---

## Command Reference

### Basic Commands

```powershell
# Dry run (preview)
python scripts\bulk_sign_vcc.py --directory <dir> --dry-run

# Sign files
python scripts\bulk_sign_vcc.py --directory <dir> --private-key <key>

# Verbose output
python scripts\bulk_sign_vcc.py --directory <dir> --verbose

# Force re-sign
python scripts\bulk_sign_vcc.py --directory <dir> --force

# Generate manifest
python scripts\bulk_sign_vcc.py --directory <dir> --generate-manifest
```

---

### Advanced Options

```powershell
# Sign only specific classifications
--classification CONFIDENTIAL SECRET

# Custom exclusions
--exclude "test_*" "backup_*" "legacy"

# Non-recursive (top-level only)
# (Note: --recursive is True by default, cannot disable via flag)

# Custom manifest output
--manifest-output path/to/manifest.json

# Custom keys
--private-key path/to/private_key.pem
--public-key path/to/public_key.pem
```

---

## Next Steps

1. ✅ **Generate Keys** (`python scripts\generate_keys.py`)
2. ✅ **Test Dry Run** (`--dry-run`)
3. ✅ **Sign Files** (remove `--dry-run`)
4. ⏳ **Verify Signatures** (`python src\code_manifest.py verify`)
5. ⏳ **Install Runtime Hook** (in your app startup)
6. ⏳ **Store Private Key in HSM** (production)

---

## Documentation

- **Full Technical Docs:** `docs/CODE_MANIFEST_TECHNICAL.md` (15,000+ lines)
- **Bulk Signing Script:** `scripts/bulk_sign_vcc.py` (650+ lines)
- **Classification Guide:** `docs/CLASSIFICATION_GUIDE.md` (5,000+ lines)

---

## Summary

✅ **Asymmetric Encryption**: ECDSA (Elliptic Curve) with SHA-256  
✅ **Private Key**: Signs code (⚠️ keep secret in HSM)  
✅ **Public Key**: Verifies signatures (✅ safe to distribute)  
✅ **Bulk Signing**: Sign entire directory in seconds  
✅ **Auto-Classification**: Automatic security level detection  
✅ **Manifest Database**: Central JSON tracking all signatures  

**Security Level:** 🔥 **HIGH** (128-bit security, NIST P-256 curve)

---

**Quick Start Version:** 1.0.0  
**Last Updated:** 2025-10-13  
**Author:** VCC Development Team
