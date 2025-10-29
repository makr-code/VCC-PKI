# VCC PKI - Code Signing & Runtime Verification

**Complete Documentation for Inline Code Signing System**

**Version:** 1.0  
**Date:** 13. Oktober 2025  
**Status:** ✅ Production Ready

---

## 📖 Table of Contents

1. [Overview](#overview)
2. [Security Model](#security-model)
3. [Architecture](#architecture)
4. [Quick Start](#quick-start)
5. [API Reference](#api-reference)
6. [Integration Guide](#integration-guide)
7. [Production Deployment](#production-deployment)
8. [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

### What is Code Signing?

Code signing ist eine Sicherheitsmaßnahme, die **cryptographische Signaturen** verwendet, um:
- **Integrität** von Source Code zu garantieren
- **Authentizität** des Code-Ursprungs zu verifizieren
- **Manipulation** zur Laufzeit zu erkennen
- **Zero-Trust Security** für Python-Anwendungen zu ermöglichen

### Why Inline Manifests?

**Problem mit externen Manifest-Dateien:**
- Können getrennt vom Code manipuliert werden
- File-System-basierte Synchronisation fehleranfällig
- Schwer zu verteilen und zu verwalten

**Lösung: Inline Manifests:**
- Signatur direkt im Python-File (Header-Comment)
- Keine separaten Dateien nötig
- Automatische Synchronisation
- Tamper-evident (Änderung = ungültige Signatur)

### Key Features

✅ **Inline Signatures** - Embedded in Python file headers  
✅ **Runtime Verification** - Automatic import hook protection  
✅ **Zero External Files** - No separate manifest files  
✅ **Performance Optimized** - Cached verification results  
✅ **ECDSA Signatures** - Fast and secure (SECP256R1)  
✅ **Transparent Integration** - No code changes needed  
✅ **Strict/Permissive Modes** - Flexible deployment  
✅ **CI/CD Ready** - Automated signing pipeline  

---

## 🔒 Security Model

### Threat Model

**Protected against:**
- ✅ **Runtime Code Injection** - Modified .py files detected
- ✅ **Supply Chain Attacks** - Tampered dependencies detected
- ✅ **Malware Injection** - Infected files rejected
- ✅ **Insider Threats** - Unauthorized code changes blocked
- ✅ **File System Tampering** - Modified files immediately detected

**NOT protected against:**
- ❌ **Memory Manipulation** - Runtime memory corruption (use OS-level protections)
- ❌ **Interpreter Tampering** - Modified Python interpreter (use OS-level signing)
- ❌ **Kernel Rootkits** - Kernel-level attacks (use Secure Boot + TPM)

### Cryptographic Design

**Algorithm:** ECDSA with SECP256R1 (NIST P-256)  
**Hash Function:** SHA-256  
**Signature Format:** ASN.1 DER (hex-encoded)  
**Key Size:** 256 bits (equivalent to 3072-bit RSA)

**Why ECDSA?**
- **Performance:** 10-100x faster than RSA
- **Size:** Smaller signatures (64 bytes vs 256-512 bytes RSA)
- **Security:** 256-bit ECDSA ≈ 3072-bit RSA security level

**Signature Process:**
```
1. Remove existing manifest (if any)
2. Compute SHA-256 hash of source code
3. Sign hash with ECDSA private key
4. Encode signature as hex string
5. Prepend manifest header to file
6. Write signed file
```

**Verification Process:**
```
1. Extract manifest header from file
2. Remove manifest header from source
3. Compute SHA-256 hash of source
4. Verify ECDSA signature with public key
5. Cache result for performance
6. Allow/reject import based on result
```

### Key Management

**Private Key:**
- 🔐 Stored in HSM (Hardware Security Module) - Production
- 🔐 Stored in CI/CD secrets (GitHub Actions, GitLab CI)
- ⚠️ NEVER commit to git
- ⚠️ NEVER expose in logs/environment

**Public Key:**
- ✅ Embedded in application binary
- ✅ Can be committed to git
- ✅ Distributed with application
- ✅ Used for verification only

**Key Rotation:**
- Generate new key pair: `python src/code_manifest.py keygen`
- Re-sign all code with new key
- Update public key in verifier
- Deploy new version

---

## 🏗️ Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│                 VCC Code Signing System                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────┐         ┌──────────────────┐       │
│  │  Code Signer  │────────▶│  Signed Python   │       │
│  │  (Offline)    │         │  Source Files    │       │
│  └───────────────┘         └──────────────────┘       │
│         │                           │                  │
│         │ Private Key               │ Embedded         │
│         │ (HSM/CI/CD)              │ Signature        │
│         ▼                           ▼                  │
│  ┌───────────────┐         ┌──────────────────┐       │
│  │  Key Storage  │         │  Runtime         │       │
│  │               │         │  Verifier        │       │
│  └───────────────┘         └──────────────────┘       │
│                                     │                  │
│                                     │ Public Key       │
│                                     │ (Embedded)       │
│                                     ▼                  │
│                            ┌──────────────────┐       │
│                            │  Import Hook     │       │
│                            │  (Auto-Verify)   │       │
│                            └──────────────────┘       │
│                                     │                  │
│                                     ▼                  │
│                            ┌──────────────────┐       │
│                            │  Python          │       │
│                            │  Interpreter     │       │
│                            └──────────────────┘       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### File Structure

```python
# Signed Python File (example.py)

# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100ab12cd34...
# Signed: 2025-10-13T20:30:00
# This file is cryptographically signed. Do not modify.

import os
import sys

def my_function():
    """This code is protected by signature above."""
    print("Hello, World!")

if __name__ == '__main__':
    my_function()
```

### Modules

**`code_manifest.py` (950 lines)**
- `CodeSigner` - Sign Python files
- `CodeVerifier` - Verify signatures
- CLI commands: `sign`, `verify`, `keygen`

**`runtime_verifier.py` (450 lines)**
- `SecureModuleFinder` - Import hook
- `enable_runtime_verification()` - Enable protection
- `@verified_execution` - Function decorator
- Verification cache for performance

**`code_signing_example.py` (450 lines)**
- Integration examples
- Best practices
- CI/CD templates
- Error handling patterns

---

## 🚀 Quick Start

### 1. Generate Key Pair

```bash
# Generate production keys (DO THIS FIRST!)
python src/code_manifest.py keygen \
    --private-key production_private.pem \
    --public-key production_public.pem

# Secure private key (example)
chmod 600 production_private.pem
# Store in HSM or CI/CD secrets
```

### 2. Sign Application Code

```bash
# Sign all Python files recursively
python src/code_manifest.py sign \
    --directory . \
    --recursive \
    --private-key production_private.pem

# Verify signatures
python src/code_manifest.py verify \
    --directory . \
    --recursive \
    --public-key production_public.pem
```

### 3. Enable Runtime Verification

```python
# main.py - Application entry point

from runtime_verifier import enable_runtime_verification

# Enable verification BEFORE any imports!
enable_runtime_verification(
    strict=True,
    public_key_path='production_public.pem'
)

# Now import application modules (will be verified)
import my_app
import my_services
import my_workers

# Run application
if __name__ == '__main__':
    my_app.run()
```

### 4. Test Protection

```bash
# Run application (should work)
python main.py

# Tamper with file
echo "# malicious code" >> my_app.py

# Run again (should fail!)
python main.py
# ImportError: Code verification failed for my_app: Invalid signature
```

---

## 📚 API Reference

### CodeSigner Class

```python
from code_manifest import CodeSigner

signer = CodeSigner(private_key_path='private.pem')
```

**Methods:**

#### `sign_file(file_path, output_path=None) -> bool`
Sign a single Python file.

```python
signer.sign_file('my_module.py')
# Returns: True if successful
```

#### `sign_directory(directory, recursive=True) -> Dict[str, bool]`
Sign all .py files in directory.

```python
results = signer.sign_directory('.', recursive=True)
# Returns: {'file1.py': True, 'file2.py': True, ...}
```

---

### CodeVerifier Class

```python
from code_manifest import CodeVerifier

verifier = CodeVerifier(
    public_key_path='public.pem',
    strict_mode=True
)
```

**Methods:**

#### `verify_file(file_path) -> Tuple[bool, Optional[str]]`
Verify signature of Python file.

```python
success, error = verifier.verify_file('my_module.py')
if success:
    print("Valid signature")
else:
    print(f"Invalid: {error}")
```

#### `get_statistics() -> Dict`
Get verification statistics.

```python
stats = verifier.get_statistics()
# Returns: {'verified': 10, 'failed': 0, 'total': 10}
```

---

### Runtime Verification API

#### `enable_runtime_verification(strict, public_key_path=None)`
Enable automatic import verification.

**Parameters:**
- `strict` (bool): Reject invalid code (True) or warn only (False)
- `public_key_path` (str): Path to public key PEM file

```python
from runtime_verifier import enable_runtime_verification

# Strict mode (production)
enable_runtime_verification(strict=True)

# Permissive mode (development)
enable_runtime_verification(strict=False)
```

#### `get_verification_statistics() -> Dict`
Get runtime verification statistics.

```python
from runtime_verifier import get_verification_statistics

stats = get_verification_statistics()
print(f"Verified: {stats['verified_modules']}")
print(f"Failed:   {stats['failed_modules']}")
```

#### `@verified_execution` Decorator
Verify code signature before function execution.

```python
from runtime_verifier import verified_execution

@verified_execution
def critical_payment_function():
    """This function verifies its source file before execution."""
    process_payment()
```

#### `VerifiedContext` Context Manager
Temporary verification mode.

```python
from runtime_verifier import VerifiedContext

with VerifiedContext(strict=True):
    import untrusted_module  # Verified
    untrusted_module.run()
```

---

## 🔧 Integration Guide

### Application Entry Point Pattern

**Recommended structure:**

```python
# main.py - Production entry point

#!/usr/bin/env python3
"""
My Application - Production Version
"""

import sys
import os

# ==================== STEP 1: Enable Verification ====================
# MUST be done BEFORE any application imports!

from runtime_verifier import enable_runtime_verification

# Production: Strict mode with embedded public key
enable_runtime_verification(
    strict=True,
    public_key_path='/etc/myapp/public_key.pem'
)

# ==================== STEP 2: Import Application Modules ====================
# All imports will be verified automatically

try:
    from my_app import core
    from my_app.services import database, api
    from my_app.workers import background_tasks
    
except ImportError as e:
    print(f"FATAL: Code verification failed: {e}")
    print("Action: Re-sign application code or check logs")
    sys.exit(1)

# ==================== STEP 3: Run Application ====================

def main():
    """Main application entry point."""
    # Application code here
    core.initialize()
    api.start_server()
    background_tasks.start()

if __name__ == '__main__':
    main()
```

### Development vs. Production

**Development Mode (`dev_main.py`):**
```python
# Permissive mode during development
enable_runtime_verification(strict=False)
# Warns about unsigned code but allows execution
```

**Production Mode (`main.py`):**
```python
# Strict mode in production
enable_runtime_verification(strict=True)
# Rejects unsigned/tampered code immediately
```

### Dockerfile Integration

```dockerfile
# Dockerfile - Production build with code signing

FROM python:3.11-slim

WORKDIR /app

# Copy application code
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Sign application code (in CI/CD with secret key)
# Note: This should be done in CI/CD, not in Dockerfile
# ARG CODE_SIGNING_KEY
# RUN echo "$CODE_SIGNING_KEY" > /tmp/key.pem && \
#     python src/code_manifest.py sign --directory /app --recursive --private-key /tmp/key.pem && \
#     rm /tmp/key.pem

# Embed public key
COPY production_public.pem /etc/myapp/public_key.pem

# Run application with verification
CMD ["python", "main.py"]
```

---

## 🏭 Production Deployment

### CI/CD Pipeline (GitHub Actions)

```yaml
# .github/workflows/build-and-sign.yml

name: Build and Sign Application

on:
  push:
    branches: [main]

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install cryptography
      
      - name: Sign application code
        env:
          CODE_SIGNING_KEY: ${{ secrets.CODE_SIGNING_PRIVATE_KEY }}
        run: |
          echo "$CODE_SIGNING_KEY" > /tmp/private_key.pem
          python src/code_manifest.py sign \
            --directory . \
            --recursive \
            --private-key /tmp/private_key.pem
          rm /tmp/private_key.pem
      
      - name: Verify signatures
        run: |
          python src/code_manifest.py verify \
            --directory . \
            --recursive \
            --public-key production_public.pem \
            --verbose
      
      - name: Build Docker image
        run: |
          docker build -t myapp:${{ github.sha }} .
          docker tag myapp:${{ github.sha }} myapp:latest
      
      - name: Push to registry
        run: |
          docker push myapp:${{ github.sha }}
          docker push myapp:latest
      
      - name: Deploy to production
        run: |
          kubectl set image deployment/myapp \
            myapp=myapp:${{ github.sha }}
```

### Key Management Best Practices

**Private Key Storage:**
1. **HSM (Hardware Security Module)** - Best option for production
   - AWS CloudHSM
   - Azure Key Vault
   - YubiHSM
   
2. **CI/CD Secrets** - Good for automated signing
   - GitHub Secrets
   - GitLab CI/CD Variables
   - Azure DevOps Variable Groups
   
3. **Vault Systems** - Centralized secret management
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault

**Public Key Distribution:**
- ✅ Embed in Docker image
- ✅ Embed in binary (PyInstaller)
- ✅ Commit to git (it's public!)
- ✅ Deploy with application

### Monitoring & Alerting

**Log Verification Events:**
```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('code_verification')

# Log verification failures
def on_verification_failure(module_name, file_path, error):
    logger.error(
        f"CODE_VERIFICATION_FAILED: {module_name}",
        extra={
            'file_path': file_path,
            'error': error,
            'severity': 'CRITICAL'
        }
    )
    # Trigger alert (PagerDuty, Slack, etc.)
```

**Metrics to Monitor:**
- Verification failure rate
- Number of unsigned modules attempted
- Verification cache hit rate
- Import latency (performance)

---

## 🔍 Troubleshooting

### Error: "No manifest found"

**Cause:** File is not signed.

**Solution:**
```bash
python src/code_manifest.py sign --file module.py
```

### Error: "Invalid signature (code tampered)"

**Cause:** File content changed after signing.

**Solution:**
```bash
# Restore original or re-sign
git checkout module.py
python src/code_manifest.py sign --file module.py
```

### Error: "Unsupported manifest version"

**Cause:** Signed with different version.

**Solution:**
```bash
# Re-sign with current version
python src/code_manifest.py sign --file module.py
```

### Performance Issues

**Symptom:** Slow import times.

**Solution:**
```python
# Verification is cached automatically
# First import: ~5ms (verification)
# Subsequent: ~0.1ms (cache hit)

# Clear cache if needed
from runtime_verifier import clear_verification_cache
clear_verification_cache()
```

### Development Workflow Issues

**Problem:** Constantly need to re-sign during development.

**Solution:**
```python
# Use permissive mode during development
enable_runtime_verification(strict=False)  # Warns only

# Or disable completely (NOT RECOMMENDED)
# No verification during active development
```

---

## 📊 Performance Impact

### Benchmark Results

**Signing Performance:**
- Sign single file: ~2-5ms
- Sign 100 files: ~500ms (5ms per file)
- Sign 1000 files: ~5s (5ms per file)

**Verification Performance:**
- First verification: ~5ms (includes ECDSA verify)
- Cached verification: ~0.1ms (hash lookup)
- Import overhead: <1% for typical application

**Memory Impact:**
- Verifier: ~100KB
- Cache (1000 files): ~200KB
- Total: <1MB overhead

**Recommendation:** Performance impact is negligible for production use.

---

## 🎓 Best Practices

### DO's ✅

- ✅ Sign ALL Python files (including tests)
- ✅ Use strict mode in production
- ✅ Store private key in HSM/secrets
- ✅ Sign code in CI/CD pipeline
- ✅ Verify signatures before deployment
- ✅ Monitor verification failures
- ✅ Rotate keys periodically (annually)
- ✅ Use separate keys for dev/prod

### DON'Ts ❌

- ❌ Never commit private key to git
- ❌ Never use dev keys in production
- ❌ Never disable verification in production
- ❌ Never sign code manually on developer machines
- ❌ Never use permissive mode in production
- ❌ Never skip verification for "trusted" modules
- ❌ Never store private key in source code
- ❌ Never share private keys between environments

---

## 📞 Support & Resources

**Documentation:**
- This file: `docs/CODE_SIGNING.md`
- Examples: `examples/code_signing_example.py`
- Source: `src/code_manifest.py`, `src/runtime_verifier.py`

**Tools:**
- Sign: `python src/code_manifest.py sign --help`
- Verify: `python src/code_manifest.py verify --help`
- Keygen: `python src/code_manifest.py keygen --help`

**Security:**
- Report vulnerabilities: security@vcc.local
- Security policy: `SECURITY.md`

---

**Last Updated:** 13. Oktober 2025  
**Version:** 1.0  
**Status:** Production Ready ✅
