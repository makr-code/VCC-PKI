# VCC Bulk Code Signing - GUI Documentation

**Version:** 1.0.0  
**Date:** 2025-10-13  
**Author:** VCC Development Team

---

## Overview

**Graphical User Interface** for the VCC Bulk Code Signing System.

**Purpose:**
- User-friendly interface for bulk signing Python files
- Visual progress tracking
- Real-time statistics
- Key generation with GUI
- Classification filtering
- Dry-run preview mode

**Features:**
- 🖱️ **Directory browser** (no typing paths!)
- 🔑 **Key file selection** with browse buttons
- 🎨 **Color-coded logging** (info/success/warning/error)
- 📊 **Real-time statistics** (signed/skipped/failed)
- ⏸️ **Dry-run mode** (preview without modifying files)
- 🔐 **Key generation** directly from GUI
- 🎯 **Classification filters** (PUBLIC, INTERNAL, CONFIDENTIAL, SECRET)
- 📝 **Manifest generation** (JSON database)

---

## Quick Start

### 1. Launch GUI

```powershell
cd C:\VCC\PKI
python scripts\bulk_sign_gui.py
```

### 2. Generate Keys (First Time)

1. Click **"Generate New Keys"** button
2. Select output directory (e.g., `C:\VCC\PKI\keys`)
3. Keys are automatically loaded into GUI
4. ⚠️ **Keep private key secret!**

### 3. Select Directory

1. Click **"Browse..."** button next to Directory field
2. Select directory to sign (e.g., `C:\VCC\PKI\src`)
3. Directory path appears in text field

### 4. Configure Options

**Classifications (Checkboxes):**
- ✅ **PUBLIC** - Open source, public APIs
- ✅ **INTERNAL** - Internal tools, utilities
- ✅ **CONFIDENTIAL** - Business logic, customer data
- ✅ **SECRET** - CA keys, HSM, critical infrastructure

**Options (Checkboxes):**
- ✅ **Recursive** - Scan subdirectories (recommended)
- ☐ **Force** - Re-sign already signed files
- ✅ **Dry Run** - Preview without signing (safe!)
- ☐ **Generate Manifest** - Create JSON database

### 5. Start Signing

1. Click **"Start Signing"** button
2. Progress bar shows real-time progress
3. Output log displays each file
4. Statistics update live
5. Notification when complete

---

## GUI Layout

### Left Panel: Configuration

```
┌─────────────────────────────────────────────┐
│ Directory                                   │
│ ┌─────────────────────┐ ┌────────────┐     │
│ │ C:\VCC\PKI\src     │ │ Browse...  │     │
│ └─────────────────────┘ └────────────┘     │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Keys                                        │
│                                             │
│ Private Key:                                │
│ ┌────────────────┐ ┌────────────┐          │
│ │ keys\private.. │ │ Browse...  │          │
│ └────────────────┘ └────────────┘          │
│                                             │
│ Public Key:                                 │
│ ┌────────────────┐ ┌────────────┐          │
│ │ keys\public..  │ │ Browse...  │          │
│ └────────────────┘ └────────────┘          │
│                                             │
│      ┌──────────────────────┐              │
│      │ Generate New Keys    │              │
│      └──────────────────────┘              │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Classifications                             │
│ ☑ PUBLIC        ☑ INTERNAL                 │
│ ☑ CONFIDENTIAL  ☑ SECRET                   │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Options                                     │
│ ☑ Recursive (scan subdirectories)          │
│ ☐ Force (re-sign already signed files)     │
│ ☑ Dry Run (preview without signing)        │
│ ☐ Generate Manifest Database (JSON)        │
└─────────────────────────────────────────────┘

┌─────────────┐ ┌────────────┐
│ Start Sign  │ │   Stop     │
└─────────────┘ └────────────┘
```

### Right Panel: Progress & Output

```
┌─────────────────────────────────────────────┐
│ Progress                                    │
│ Processing 7/10: crypto_utils.py (INTERNAL)│
│ ████████████████░░░░░░░░ 70%               │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Statistics                                  │
│ Total Files: 10                             │
│   Signed:  7                                │
│   Skipped: 2                                │
│   Failed:  1                                │
│                                             │
│ By Classification:                          │
│   PUBLIC: 1                                 │
│   INTERNAL: 5                               │
│   CONFIDENTIAL: 3                           │
│   SECRET: 1                                 │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Output Log                                  │
│ ────────────────────────────────────────    │
│ Starting bulk signing...                    │
│ Directory: C:\VCC\PKI\src                   │
│ Dry Run: True                               │
│ Classifications: PUBLIC, INTERNAL, ...      │
│                                             │
│ Found 10 Python files                       │
│ [OK] ca_manager.py (INTERNAL)               │
│ [OK] cert_manager_base.py (INTERNAL)        │
│ [SKIP] classify_code.py (already signed)    │
│ [OK] code_header.py (CONFIDENTIAL)          │
│ [OK] code_manifest.py (SECRET)              │
│ ...                                         │
│ Signing completed!                          │
│                                             │
│ ▼ (scrollable)                              │
└─────────────────────────────────────────────┘
```

---

## Workflows

### Workflow 1: First-Time Setup (Generate Keys)

```
1. Launch GUI
   → python scripts\bulk_sign_gui.py

2. Generate Keys
   → Click "Generate New Keys"
   → Select directory (e.g., C:\VCC\PKI\keys)
   → Keys created: private_key.pem, public_key.pem
   → ⚠️ Add keys/ to .gitignore!

3. Ready to Sign!
```

### Workflow 2: Dry-Run (Preview Mode)

```
1. Select Directory
   → Browse to C:\VCC\PKI\src

2. Configure
   → ✅ Recursive
   → ✅ Dry Run (IMPORTANT!)
   → Select classifications (e.g., CONFIDENTIAL + SECRET)

3. Preview
   → Click "Start Signing"
   → Review output log
   → Check statistics
   → No files modified!

4. Decide
   → If looks good → Uncheck "Dry Run" → Re-run
   → If issues → Fix → Re-run dry-run
```

### Workflow 3: Actual Signing

```
1. Select Directory
   → Browse to C:\VCC\PKI\src

2. Configure
   → ✅ Recursive
   → ☐ Dry Run (unchecked!)
   → Select classifications (e.g., all)
   → Private Key: keys\private_key.pem
   → Public Key: keys\public_key.pem

3. Sign
   → Click "Start Signing"
   → Watch progress bar
   → Monitor output log
   → Wait for "Signing completed!" message

4. Verify
   → Check statistics (X files signed)
   → Review log for errors (red text)
   → Optionally generate manifest
```

### Workflow 4: Generate Manifest Database

```
1. Configure
   → Select directory
   → ✅ Generate Manifest Database (JSON)
   → (Optional) Change manifest output path

2. Sign + Manifest
   → Click "Start Signing"
   → Files are signed
   → Manifest database created

3. Review Manifest
   → File: vcc_code_manifest.json
   → Contains: All signed files with metadata
   → Format: JSON (schema version 1.0)
```

---

## Color Coding

### Log Messages

| Color      | Level       | Meaning                                |
|------------|-------------|----------------------------------------|
| **Black**  | INFO        | General information                    |
| **Green**  | SUCCESS     | Operation successful                   |
| **Orange** | WARNING     | Non-critical issue (e.g., file skipped)|
| **Red**    | ERROR       | Critical failure                       |

### Example Log Output

```
[INFO]    Starting bulk signing...
[INFO]    Directory: C:\VCC\PKI\src
[INFO]    Found 10 Python files
[SUCCESS] ca_manager.py (INTERNAL)
[SUCCESS] code_header.py (CONFIDENTIAL)
[WARNING] classify_code.py (already signed, skipped)
[ERROR]   database.py (signature failed: invalid key)
[SUCCESS] Signing completed!
```

---

## Classification Levels

### PUBLIC (Least Sensitive)

**Definition:** Open source, publicly accessible code

**Examples:**
- Public APIs
- Utility functions (generic)
- Documentation generators
- Example code

**Indicators:**
- MIT/Apache/GPL license
- Public GitHub repository
- No proprietary algorithms
- No sensitive data

**Header Example:**
```python
# VCC-CLASSIFICATION: PUBLIC
# VCC-LICENSE: MIT
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100...
```

### INTERNAL (Default)

**Definition:** Internal tools and utilities (proprietary but not critical)

**Examples:**
- Internal development tools
- Build scripts
- Test utilities
- Non-critical business logic

**Indicators:**
- Proprietary license
- Internal-only usage
- No customer data
- No critical infrastructure

**Header Example:**
```python
# VCC-CLASSIFICATION: INTERNAL
# VCC-LICENSE: Proprietary
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100...
```

### CONFIDENTIAL (High Sensitivity)

**Definition:** Business-critical code with proprietary algorithms or customer data

**Examples:**
- Core business logic
- Customer data handling
- Payment processing
- Proprietary algorithms
- API keys/secrets

**Indicators:**
- NDA required
- Customer data access
- Revenue-generating code
- Competitive advantage

**Header Example:**
```python
# VCC-CLASSIFICATION: CONFIDENTIAL
# VCC-DRM: NDA-REQUIRED
# VCC-ALLOWED-DOMAINS: vcc.internal
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100...
```

### SECRET (Maximum Sensitivity)

**Definition:** Critical infrastructure and security components

**Examples:**
- CA private keys
- HSM integration
- Root certificates
- Master encryption keys
- Authentication systems

**Indicators:**
- Strict NDA required
- Physical access control
- Audit logging
- Regulatory compliance

**Header Example:**
```python
# VCC-CLASSIFICATION: SECRET
# VCC-DRM: STRICT-NDA-REQUIRED
# VCC-SECURITY-CONTACT: security@vcc.internal
# VCC-ALLOWED-DOMAINS: vcc.internal,localhost
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100...
```

---

## Key Management

### Generating Keys (GUI Method)

**Steps:**
1. Launch GUI: `python scripts\bulk_sign_gui.py`
2. Click **"Generate New Keys"** button
3. Select output directory (e.g., `C:\VCC\PKI\keys`)
4. Keys are saved:
   - `private_key.pem` (ECDSA P-256, 32 bytes)
   - `public_key.pem` (ECDSA P-256, 64 bytes)
5. GUI automatically loads keys

**Security Warning:**
```
⚠️ KEEP PRIVATE KEY SECRET!
   - Never commit to git
   - Store in secure location
   - Consider HSM/TPM for production
   - Use strong passphrase if encrypting
```

### Generating Keys (CLI Method)

```powershell
# Generate ECDSA P-256 key pair
python scripts\generate_keys.py --output keys

# Output:
# Generating ECDSA key pair (NIST P-256 curve)...
# ✓ Private key saved: keys\private_key.pem
#   ⚠️ KEEP THIS SECRET! Never commit to git!
# ✓ Public key saved: keys\public_key.pem
#   ✅ Safe to distribute
```

### Key Storage Best Practices

**Development (Windows):**
- Store in `keys/` directory (add to `.gitignore`)
- Use file system permissions (read-only for public key)
- Backup private key to encrypted USB drive

**Production (Linux):**
- **BEST:** Hardware Security Module (HSM)
  - FIPS 140-2 Level 3+ certified
  - Keys never leave hardware
  - Cost: €2,000-€10,000
- **GOOD:** Trusted Platform Module (TPM)
  - Built into modern servers
  - Hardware-protected keys
  - Cost: Free (built-in)
- **ACCEPTABLE:** Encrypted file
  - AES-256 encryption
  - Strong passphrase (20+ characters)
  - Never commit to git

### Key Rotation

**Schedule:**
- Development: Every 180 days
- Production: Every 90 days
- After security incident: Immediately

**Process:**
1. Generate new key pair
2. Sign all files with new key
3. Update public key in verification systems
4. Archive old private key (encrypted backup)
5. Revoke old public key after grace period (30 days)

---

## Troubleshooting

### Problem: GUI doesn't launch

**Symptoms:**
```
ImportError: No module named 'tkinter'
```

**Solution (Windows):**
```powershell
# Tkinter should be included with Python
# If missing, reinstall Python with Tkinter checkbox enabled
python -m tkinter  # Test if Tkinter works
```

**Solution (Linux):**
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora/RHEL
sudo dnf install python3-tkinter
```

---

### Problem: Cannot import VCC tools

**Symptoms:**
```
ERROR: Cannot import VCC tools: No module named 'code_manifest'
```

**Solution:**
```powershell
# Ensure src/ directory exists
dir C:\VCC\PKI\src

# Files should exist:
#   code_manifest.py
#   code_header.py
#   classify_code.py

# If missing, check project structure
```

---

### Problem: Invalid key error

**Symptoms:**
```
ValueError: Invalid key format
```

**Solution:**
```powershell
# Generate new keys
python scripts\generate_keys.py --output keys

# OR use GUI "Generate New Keys" button

# Verify keys exist:
dir keys\private_key.pem
dir keys\public_key.pem
```

---

### Problem: Files already signed

**Symptoms:**
```
[SKIP] Already signed: example.py
```

**Solution:**
```
Option 1: Normal behavior (files won't be re-signed)
Option 2: Force re-signing (check "Force" checkbox)
```

---

### Problem: Classification wrong

**Symptoms:**
```
File classified as INTERNAL but should be CONFIDENTIAL
```

**Solution:**
```
1. Open file: src/classify_code.py
2. Add file to classification rules:
   CONFIDENTIAL_FILES = [
       'payment_processor.py',
       'customer_database.py',
       # Add your file here
   ]
3. Re-run classification
```

---

### Problem: Signing fails silently

**Symptoms:**
```
No error message, but files not signed
```

**Solution:**
```
1. Check "Dry Run" is UNCHECKED
2. Verify private key path is correct
3. Ensure file permissions allow writing
4. Check Output Log for red ERROR messages
```

---

## Advanced Usage

### Custom Exclude Patterns

**Edit:** `scripts/bulk_sign_vcc.py`

```python
DEFAULT_EXCLUDE_PATTERNS = [
    '__pycache__',
    '.git',
    'test_*',        # Exclude test files
    '*_backup',      # Exclude backups
    'vendor',        # Exclude vendor directory
    'my_custom_dir', # Add your pattern here
]
```

### Manifest Database Schema

**File:** `vcc_code_manifest.json`

```json
{
  "schema_version": "1.0",
  "total_files": 42,
  "signed_files": 40,
  "generated_at": "2025-10-13T20:30:00Z",
  "files": [
    {
      "file_path": "src/pki_server.py",
      "signature": "3045022100d8f7e9c1a2b3c4d5...",
      "classification": "CONFIDENTIAL",
      "version": "1.2.3",
      "content_hash_sha256": "35e0d147ab5c2f8e...",
      "content_hash_sha512": "7f9c3d5e1a4b8c9d...",
      "signed_at": "2025-10-13T20:30:00Z",
      "file_size": 4567,
      "line_count": 123
    }
  ]
}
```

### Threading Behavior

**Background Thread:**
- Signing runs in separate thread
- UI remains responsive
- Progress updates via queue
- Can't cancel mid-signing (TODO)

**Main Thread:**
- UI updates every 100ms
- Reads from progress queue
- Updates progress bar, log, statistics

---

## Performance

### Signing Speed

**Typical Performance:**
- Small files (<100 lines): ~0.5ms per file
- Medium files (100-500 lines): ~1-2ms per file
- Large files (>500 lines): ~3-5ms per file

**Bottlenecks:**
1. **Classification** (~50ms per file)
   - CPU-intensive (pattern matching, AST parsing)
2. **Signature computation** (~0.5ms per file)
   - ECDSA P-256 signing
3. **File I/O** (~1ms per file)
   - Reading + writing to disk

**Expected Throughput:**
- **10 files**: ~2 seconds
- **100 files**: ~15 seconds
- **1000 files**: ~2-3 minutes

---

## Security Considerations

### ECDSA Cryptography

**Algorithm Details:**
- **Curve:** NIST P-256 (SECP256R1)
- **Hash:** SHA-256 (32-byte digest)
- **Signature Size:** 64-72 bytes (DER-encoded)
- **Security Level:** 128-bit (equivalent to RSA 3072-bit)

**Signing Process:**
```python
digest = SHA256(source_code)           # 32 bytes
signature = ECDSA_Sign(private_key, digest)  # 64-72 bytes
signature_hex = signature.hex()        # 128-144 characters
```

**Verification Process:**
```python
ECDSA_Verify(public_key, signature, digest)
# Returns: True (valid) or raises InvalidSignature (tampered)
```

### Threat Model

**Protected Against:**
- ✅ Code tampering (unauthorized modification)
- ✅ Malware injection (code insertion)
- ✅ Supply chain attacks (compromised dependencies)
- ✅ MITM attacks (man-in-the-middle)

**NOT Protected Against:**
- ❌ Key compromise (if private key stolen)
- ❌ Zero-day exploits (vulnerabilities in signed code)
- ❌ Social engineering (authorized but malicious signing)

**Mitigation:**
- Use HSM/TPM for key storage
- Rotate keys every 90-180 days
- Audit all signing operations
- Implement code review before signing

---

## Best Practices

### 1. Always Use Dry-Run First

```
✅ DO:
1. Enable "Dry Run" checkbox
2. Click "Start Signing"
3. Review output log
4. If OK → Disable "Dry Run" → Re-run
5. Sign actual files

❌ DON'T:
1. Skip dry-run
2. Sign files directly
3. Hope for the best
```

### 2. Backup Before Signing

```powershell
# Create timestamped backup
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
xcopy C:\VCC\PKI\src C:\VCC\PKI\backup_$timestamp /E /I

# Sign files
python scripts\bulk_sign_gui.py

# Verify
# If issues → Restore backup
```

### 3. Version Control Commits

```powershell
# Commit before signing
git add .
git commit -m "Pre-signing snapshot"

# Sign files
python scripts\bulk_sign_gui.py

# Commit after signing
git add .
git commit -m "Signed code with ECDSA signatures"
```

### 4. Key Storage

```
✅ DO:
- Store private key in HSM/TPM (production)
- Use encrypted USB drive (backup)
- Add keys/ to .gitignore
- Set file permissions (read-only for public key)

❌ DON'T:
- Commit private key to git
- Store unencrypted on shared drive
- Email private key
- Share private key via Slack/Teams
```

### 5. Audit Logging

```python
# Log all signing operations
import logging

logging.info(f"Signed {file_path} with key {key_id}")
logging.info(f"Classification: {classification}")
logging.info(f"Signature: {signature_hex[:16]}...")
```

---

## FAQ

### Q: Can I sign non-Python files?

**A:** No, currently only `.py` files are supported.

**Workaround:** Extend `find_python_files()` to support other extensions:
```python
def find_files(self, directory, extensions=['.py', '.js', '.ts']):
    # Add your logic here
```

---

### Q: Can I use RSA instead of ECDSA?

**A:** No, system is designed for ECDSA P-256.

**Reason:** ECDSA offers better performance and smaller signatures than RSA:
- ECDSA P-256: 64-72 bytes, 128-bit security
- RSA 3072: 384 bytes, 128-bit security

---

### Q: Can I cancel signing mid-operation?

**A:** Not yet implemented (TODO).

**Current Behavior:** Stop button is disabled during signing. Must wait for completion.

**Future Feature:** Graceful cancellation with partial results.

---

### Q: What if I lose the private key?

**A:** You cannot sign new files or re-sign existing files.

**Recovery:**
1. Generate new key pair
2. Re-sign all files with new key
3. Update public key in verification systems

---

### Q: Can I distribute the public key?

**A:** Yes! Public key is safe to distribute.

**Distribution Methods:**
- Commit to git repository
- Host on internal server
- Include in deployment packages
- Share via email/Slack

---

### Q: How do I verify signatures at runtime?

**A:** Use the runtime verifier:

```python
from runtime_verifier import install_import_hook

# Install import hook (verifies on import)
install_import_hook(
    public_key_path='keys/public_key.pem',
    strict_mode=True  # Fail on invalid signature
)

# Now all imports are verified
import my_signed_module  # ✅ Verified before import
```

---

## Related Documentation

- **Technical Deep Dive:** `docs/CODE_MANIFEST_TECHNICAL.md` (15,000+ lines)
  - ECDSA cryptography details
  - Mathematical formulas
  - Security model
  - Performance benchmarks

- **Quick Start Guide:** `docs/BULK_SIGNING_QUICKSTART.md` (3,000+ lines)
  - CLI usage examples
  - Common use cases
  - Troubleshooting

- **Classification Guide:** `docs/CLASSIFICATION_GUIDE.md` (5,000+ lines)
  - 4-level classification system
  - Decision matrix
  - Industry standards

---

## Support

**Issues:**
- File bug reports in issue tracker
- Include error messages from Output Log
- Attach `vcc_code_manifest.json` if relevant

**Contact:**
- Security Team: `security@vcc.internal`
- Development Team: `dev@vcc.internal`

---

**End of GUI Documentation**
