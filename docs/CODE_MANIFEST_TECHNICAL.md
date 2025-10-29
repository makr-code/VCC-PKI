# VCC Code Manifest System - Technical Documentation

**Version:** 1.0.0  
**Date:** 2025-10-13  
**Classification:** CONFIDENTIAL

---

## Table of Contents

1. [Overview](#overview)
2. [Cryptographic Architecture](#cryptographic-architecture)
3. [Manifest Structure](#manifest-structure)
4. [Signing Process](#signing-process)
5. [Verification Process](#verification-process)
6. [Key Management](#key-management)
7. [Security Model](#security-model)
8. [Usage Examples](#usage-examples)

---

## Overview

The **VCC Code Manifest System** provides cryptographic integrity protection for Python source code through:

- **Digital Signatures**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Inline Manifests**: Signatures embedded in source files
- **Runtime Verification**: Import hooks verify code before execution
- **Enhanced Metadata**: Copyright, version, UUID, hashes, classification
- **Zero-Trust Architecture**: Every execution is verified

---

## Cryptographic Architecture

### Asymmetric Encryption: ECDSA

**Algorithm:** Elliptic Curve Digital Signature Algorithm (ECDSA)

**Why ECDSA?**
- ✅ **Performance**: 10x faster than RSA (important for runtime verification)
- ✅ **Security**: 256-bit ECDSA = 3072-bit RSA strength
- ✅ **Key Size**: Smaller keys (easier to embed in code)
- ✅ **Standard**: NIST P-256 curve (FIPS 186-4 compliant)

**Components:**

| Component | Purpose | Location |
|-----------|---------|----------|
| **Private Key** | Signs code | HSM or secure storage (NEVER commit to git!) |
| **Public Key** | Verifies signatures | Embedded in runtime_verifier.py |
| **Signature** | Proof of integrity | Embedded in each .py file header |

---

### Signature Generation

```
┌─────────────────┐
│  Source Code    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SHA-256 Hash   │  ← Digest of source code
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ECDSA Sign     │  ← Sign hash with private key
│  (Private Key)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Signature      │  ← Digital signature (hex encoded)
│  (64-72 bytes)  │
└─────────────────┘
```

**Mathematical Details:**

1. **Hash Source Code:**
   ```python
   digest = SHA256(source_code)  # 32 bytes
   ```

2. **Sign Hash:**
   ```python
   signature = ECDSA_Sign(private_key, digest)  # 64-72 bytes (DER encoded)
   ```

3. **Encode Signature:**
   ```python
   signature_hex = signature.hex()  # 128-144 hex characters
   ```

---

### Signature Verification

```
┌─────────────────┐
│  Signed File    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Extract        │  ← Separate signature from code
│  Signature      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SHA-256 Hash   │  ← Hash source code (without signature)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ECDSA Verify   │  ← Verify with public key
│  (Public Key)   │
└────────┬────────┘
         │
         ▼
    ┌───┴───┐
    │ Valid │ Invalid
    ▼       ▼
  [OK]   [ERROR]
```

**Mathematical Details:**

1. **Extract Signature:**
   ```python
   signature_hex = extract_from_header(file)
   signature = bytes.fromhex(signature_hex)
   ```

2. **Hash Source Code:**
   ```python
   digest = SHA256(source_code_without_signature)
   ```

3. **Verify Signature:**
   ```python
   is_valid = ECDSA_Verify(public_key, signature, digest)
   # Returns: True (valid) or raises InvalidSignature exception
   ```

---

## Manifest Structure

### Inline Manifest Format

The manifest is embedded in the file header as a comment:

```python
# ==============================================================================
# VCC PROTECTED SOURCE CODE
# ==============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# License: Proprietary
# Contact: legal@vcc.local
#
# Module: my_module
# Description: Module description
# File Path: src/my_module.py
#
# Version: 1.0.0
# Semantic Version: 1.0.0
#
# Author: VCC Development Team
# Author Email: dev@vcc.local
#
# Build Date: 2025-10-13T18:30:00+00:00
# Release Channel: production
# Build Number: 20251013.001
# Git Commit: abc123def456
# Git Branch: main
#
# File UUID: 8e5707f2-12c3-4bff-8494-4016143b09f0
# Content Hash (SHA-256): 35e0d147b0231021931e76394fcdf76b8f29a50dfec9f86e21ee037e124b91eb
# Content Hash (SHA-512): d01902480c2553760c37a626a05ef0f16c1bb3f137ddf2a6a2cdaa6210ac644c...
# File Size: 15847 bytes
# Line Count: 542
# Created: 2025-10-13T18:30:00+00:00
# Modified: 2025-10-13T18:30:00+00:00
#
# Classification: CONFIDENTIAL
# DRM Protected: Yes
# Security Contact: security@vcc.local
# Allowed Domains: vcc.local
#
# Signature: 3045022100d8f7e9c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7...
# Signature Algorithm: ECDSA_SHA256
# Signer: VCC Code Signing System
# Signed At: 2025-10-13T18:30:00+00:00
#
# ==============================================================================

# Your Python code starts here
def my_function():
    pass
```

---

### Manifest Fields

#### 1. Copyright Information

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `Copyright` | String | `(c) 2025 VCC` | Legal ownership |
| `License` | String | `Proprietary` | License type |
| `Contact` | Email | `legal@vcc.local` | Legal contact |

#### 2. Versioning

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `Version` | SemVer | `1.2.3` | Semantic version |
| `Build Number` | String | `20251013.001` | Build identifier |
| `Git Commit` | SHA-1 | `abc123...` | Source commit |
| `Git Branch` | String | `main` | Source branch |
| `Git Tag` | String | `v1.2.3` | Release tag |

#### 3. File Identity (Tamper-Evident)

| Field | Type | Length | Purpose |
|-------|------|--------|---------|
| `File UUID` | UUID v4 | 36 chars | Unique file ID |
| `Content Hash (SHA-256)` | Hex | 64 chars | Integrity check (fast) |
| `Content Hash (SHA-512)` | Hex | 128 chars | Integrity check (strong) |
| `File Size` | Int | Variable | Size validation |
| `Line Count` | Int | Variable | Structure validation |

#### 4. Security

| Field | Type | Values | Purpose |
|-------|------|--------|---------|
| `Classification` | Enum | PUBLIC / INTERNAL / CONFIDENTIAL / SECRET | Security level |
| `DRM Protected` | Bool | Yes / No | DRM enforcement |
| `Allowed Domains` | String | `vcc.local` | Domain restriction |
| `Expiration Date` | ISO-8601 | `2026-01-01T00:00:00Z` | Time-bound access |

#### 5. Cryptographic Signature

| Field | Type | Length | Purpose |
|-------|------|--------|---------|
| `Signature` | Hex | 128-144 chars | ECDSA signature |
| `Signature Algorithm` | String | `ECDSA_SHA256` | Algorithm identifier |
| `Signer` | String | `VCC Code Signing System` | Signing entity |
| `Signed At` | ISO-8601 | `2025-10-13T18:30:00Z` | Signing timestamp |

---

## Signing Process

### Step-by-Step

1. **Read Source Code**
   ```python
   with open('my_module.py', 'r') as f:
       source_code = f.read()
   ```

2. **Remove Existing Header** (if present)
   ```python
   source_code_clean = remove_existing_header(source_code)
   ```

3. **Auto-Classify** (determine security level)
   ```python
   classification = classify_code(source_code_clean)
   # Returns: PUBLIC / INTERNAL / CONFIDENTIAL / SECRET
   ```

4. **Compute Content Hashes**
   ```python
   sha256_hash = hashlib.sha256(source_code_clean.encode()).hexdigest()
   sha512_hash = hashlib.sha512(source_code_clean.encode()).hexdigest()
   ```

5. **Generate UUID**
   ```python
   file_uuid = uuid.uuid4()
   ```

6. **Create Header Metadata**
   ```python
   header = HeaderBuilder()
       .copyright("VCC", 2025, "Proprietary")
       .version(1, 0, 0)
       .author("VCC Team")
       .classification(classification)
       .compute_identity(source_code_clean)
       .build()
   ```

7. **Compute Digital Signature**
   ```python
   # Hash the source code (without header)
   digest = hashlib.sha256(source_code_clean.encode()).digest()
   
   # Sign with ECDSA private key
   signature = private_key.sign(
       digest,
       ec.ECDSA(hashes.SHA256())
   )
   
   signature_hex = signature.hex()
   ```

8. **Add Signature to Header**
   ```python
   header.signature = signature_hex
   header.signature_algorithm = "ECDSA_SHA256"
   header.signed_at = datetime.now().isoformat()
   ```

9. **Combine Header + Source Code**
   ```python
   header_block = header.to_header_block()
   signed_code = header_block + '\n' + source_code_clean
   ```

10. **Write Signed File**
    ```python
    with open('my_module.py', 'w') as f:
        f.write(signed_code)
    ```

---

## Verification Process

### Runtime Verification (Import Hook)

```python
# When Python imports a module:
import my_module  # ← Triggers verification

# Verification steps:
1. Load file content
2. Extract signature from header
3. Extract source code (without header)
4. Compute SHA-256 hash of source code
5. Verify signature with public key
6. If valid: Allow import
7. If invalid: Raise ImportError (block execution)
```

### Manual Verification

```python
from code_manifest import CodeVerifier

verifier = CodeVerifier(public_key_path='public_key.pem')
success, error = verifier.verify_file('my_module.py')

if success:
    print("✓ Signature valid - code is authentic")
else:
    print(f"✗ Signature invalid: {error}")
```

---

## Key Management

### Key Generation

**Generate ECDSA Key Pair:**

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate private key (NIST P-256 curve)
private_key = ec.generate_private_key(ec.SECP256R1())

# Export private key (PEM format)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Export public key (PEM format)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save keys
with open('private_key.pem', 'wb') as f:
    f.write(private_pem)

with open('public_key.pem', 'wb') as f:
    f.write(public_pem)
```

---

### Key Storage

#### Private Key (⚠️ CRITICAL)

**Storage Options:**

1. **Hardware Security Module (HSM)** - BEST ⭐⭐⭐⭐⭐
   - Dedicated hardware device
   - Keys never leave HSM
   - FIPS 140-2 Level 3+ certified
   - Cost: €2,000 - €10,000
   - Examples: YubiHSM 2, AWS CloudHSM, Thales Luna

2. **TPM (Trusted Platform Module)** - GOOD ⭐⭐⭐⭐
   - Built into most modern PCs
   - Keys protected by hardware
   - Free (already in hardware)
   - Examples: Windows TPM, Linux tpm2-tools

3. **Encrypted File** - ACCEPTABLE ⭐⭐⭐
   - AES-256 encrypted PEM file
   - Passphrase required to unlock
   - Store on encrypted drive
   - Never commit to git!

4. **Environment Variable** - DEVELOPMENT ONLY ⭐⭐
   - OK for development/testing
   - DO NOT USE IN PRODUCTION
   - Easy to leak in logs/debugging

**Production Recommendation:**
```
HSM (primary) + TPM (backup) + Encrypted file (emergency)
```

---

#### Public Key (✅ Safe to Distribute)

**Storage Options:**

1. **Embedded in Code** - BEST ⭐⭐⭐⭐⭐
   ```python
   # runtime_verifier.py
   PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
   MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4iJVmvOlNprpTLFLUwLp...
   -----END PUBLIC KEY-----"""
   ```
   - ✅ Always available
   - ✅ No external dependencies
   - ✅ Fast verification

2. **Configuration File** - GOOD ⭐⭐⭐⭐
   ```
   config/public_key.pem
   ```
   - ✅ Easy to update
   - ✅ Separate from code
   - ⚠️ Must distribute with app

3. **Remote Server** - ACCEPTABLE ⭐⭐⭐
   ```
   https://pki.vcc.local/api/public-key
   ```
   - ✅ Centralized management
   - ⚠️ Network dependency
   - ⚠️ Availability risk

---

### Key Rotation

**When to Rotate:**
- 🔄 Annually (planned rotation)
- 🚨 Immediately if compromised
- 🔄 On major version releases

**Rotation Process:**

1. **Generate New Key Pair**
   ```bash
   python scripts/generate_keys.py --output keys/2026/
   ```

2. **Sign Code with New Key**
   ```bash
   python scripts/bulk_sign_vcc.py --private-key keys/2026/private_key.pem
   ```

3. **Update Public Key in Verifier**
   ```python
   # runtime_verifier.py
   PUBLIC_KEY_PEM = """..."""  # New public key
   ```

4. **Deploy New Version**
   - All users must update to new version
   - Old signatures become invalid

**Multi-Key Support** (for transition period):
```python
# Support both old and new keys during transition
PUBLIC_KEYS = [
    load_key("keys/2025/public_key.pem"),  # Old key
    load_key("keys/2026/public_key.pem"),  # New key
]

# Verify with any valid key
for public_key in PUBLIC_KEYS:
    if verify(public_key, signature):
        return True
```

---

## Security Model

### Threat Model

| Threat | Protection | Mechanism |
|--------|------------|-----------|
| **Code Tampering** | ✅ PROTECTED | Digital signature validation |
| **Malware Injection** | ✅ PROTECTED | Signature becomes invalid |
| **Supply Chain Attack** | ✅ PROTECTED | Only signed code executes |
| **Man-in-the-Middle** | ✅ PROTECTED | Signature tied to exact content |
| **Replay Attack** | ⚠️ PARTIAL | Use expiration dates |
| **Key Compromise** | ⚠️ CRITICAL | Rotate keys immediately |

---

### Attack Scenarios

#### Scenario 1: Attacker Modifies Code

```python
# Original (signed)
def withdraw(amount):
    balance -= amount  # ✓ Signature valid

# Modified by attacker
def withdraw(amount):
    balance -= 0  # ✗ Signature invalid!
    transfer_to_attacker(amount)
```

**Result:** Signature verification fails → Import blocked → Attack prevented ✅

---

#### Scenario 2: Attacker Removes Signature

```python
# Attacker removes entire header (including signature)
# File now has no manifest

def malicious_function():
    steal_data()
```

**Result:** No signature found → Import blocked (strict mode) → Attack prevented ✅

---

#### Scenario 3: Attacker Copies Signature

```python
# Attacker copies signature from legitimate file to malicious file

# malicious.py
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100d8f7e9c1a2b3...  ← Copied signature
def steal_data():
    send_to_attacker()
```

**Result:** Signature doesn't match content → Verification fails → Attack prevented ✅

---

#### Scenario 4: Key Compromise (🔥 CRITICAL)

```
Attacker obtains private key
→ Can sign malicious code
→ Signatures will verify as valid
→ GAME OVER
```

**Mitigation:**
1. **HSM Storage**: Keys never leave hardware
2. **Access Control**: Multi-person authorization
3. **Key Rotation**: Limit damage window
4. **Audit Logging**: Detect unauthorized signing
5. **Code Review**: Human verification before signing

---

## Usage Examples

### Example 1: Sign Single File

```bash
# Sign with auto-classification
python src/code_manifest.py sign --file my_module.py

# Sign with specific classification
python src/code_manifest.py sign --file my_module.py --classification CONFIDENTIAL

# Sign with custom key
python src/code_manifest.py sign --file my_module.py --private-key keys/private_key.pem
```

---

### Example 2: Bulk Sign Directory

```bash
# Sign all Python files in VCC directory
python scripts/bulk_sign_vcc.py --directory C:\VCC --recursive

# Sign only CONFIDENTIAL and SECRET files
python scripts/bulk_sign_vcc.py --directory C:\VCC --classification CONFIDENTIAL SECRET

# Dry run (preview without signing)
python scripts/bulk_sign_vcc.py --directory C:\VCC --dry-run

# Generate manifest database
python scripts/bulk_sign_vcc.py --directory C:\VCC --generate-manifest
```

---

### Example 3: Verify File

```bash
# Verify single file
python src/code_manifest.py verify --file my_module.py

# Verify all files in directory
python src/code_manifest.py verify --directory C:\VCC --recursive
```

---

### Example 4: Runtime Verification

```python
# Install import hook (in your application startup)
from runtime_verifier import install_verification_hook

install_verification_hook(
    strict_mode=True,  # Block unsigned code
    public_key_path='public_key.pem'
)

# Now all imports are automatically verified
import my_module  # ← Verified before execution
```

---

## Manifest Database

### JSON Structure

The manifest database (`vcc_code_manifest.json`) tracks all signed files:

```json
{
  "version": "1.0.0",
  "created_at": "2025-10-13T18:30:00Z",
  "last_updated": "2025-10-13T18:30:00Z",
  "total_files": 150,
  "files": {
    "C:\\VCC\\PKI\\src\\pki_server.py": {
      "classification": "CONFIDENTIAL",
      "signature": "3045022100d8f7e9c1a2b3c4d5e6f7a8b9c0d1e2f3...",
      "uuid": "8e5707f2-12c3-4bff-8494-4016143b09f0",
      "content_hash": "35e0d147b0231021931e76394fcdf76b...",
      "timestamp": "2025-10-13T18:30:00Z"
    },
    "C:\\VCC\\PKI\\src\\ca_manager.py": {
      "classification": "SECRET",
      "signature": "304502210098a7b6c5d4e3f2a1b0c9d8e7f6a5b4...",
      "uuid": "9f6808e3-23d4-5c0f-9505-5027254c10e1",
      "content_hash": "46f1e258c1342132a42e87f5a5fcde87...",
      "timestamp": "2025-10-13T18:30:00Z"
    }
  }
}
```

**Use Cases:**
- Central inventory of signed files
- Audit trail for compliance
- Signature verification without parsing files
- Detect unsigned files (compare filesystem vs manifest)

---

## Performance

### Signing Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Generate ECDSA key | ~10ms | One-time setup |
| Sign single file | ~5-20ms | Depends on file size |
| Sign 100 files | ~1-2s | Parallel signing possible |
| Sign 1000 files | ~10-20s | Bulk operation |

---

### Verification Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Verify single file | ~3-10ms | Fast enough for runtime |
| Verify 100 files | ~500ms-1s | Acceptable for startup |
| Verify 1000 files | ~5-10s | May need caching |

**Optimization:**
- Cache verified files (by UUID + hash)
- Lazy verification (verify on first import only)
- Parallel verification (multiprocessing)

---

## Comparison with Alternatives

### ECDSA vs RSA

| Feature | ECDSA (P-256) | RSA (3072-bit) |
|---------|---------------|----------------|
| **Security Level** | 128-bit | 128-bit |
| **Key Size (Private)** | 32 bytes | 384 bytes |
| **Key Size (Public)** | 64 bytes | 384 bytes |
| **Signature Size** | 64-72 bytes | 384 bytes |
| **Sign Speed** | 🟢 Fast | 🔴 Slow |
| **Verify Speed** | 🟢 Fast | 🟡 Medium |
| **Use Case** | Runtime verification ✅ | Large files ✅ |

**Verdict:** ECDSA is better for runtime verification (faster, smaller signatures)

---

### Inline vs External Manifest

| Aspect | Inline (VCC) | External (separate .sig file) |
|--------|--------------|-------------------------------|
| **Tamper Resistance** | 🟢 High | 🟡 Medium |
| **Usability** | 🟢 Easy | 🔴 Complex |
| **File Size** | +35 lines | +1 file per .py |
| **Distribution** | 🟢 Single file | 🔴 Multiple files |
| **Version Control** | 🟢 Single commit | 🟡 Separate commits |

**Verdict:** Inline manifest is more secure and easier to use

---

## Compliance

### Standards

- **FIPS 186-4**: Digital Signature Standard (ECDSA approved)
- **NIST SP 800-89**: Recommendation for Key Management
- **ISO 27001**: Information Security Management
- **SOC 2**: Security, Availability, Confidentiality

### Best Practices

1. ✅ **Use HSM for Production Keys**
2. ✅ **Rotate Keys Annually**
3. ✅ **Audit All Signing Operations**
4. ✅ **Multi-Person Authorization for Signing**
5. ✅ **Code Review Before Signing**
6. ✅ **Automated Verification in CI/CD**
7. ✅ **Monitor for Verification Failures**

---

## Troubleshooting

### Common Issues

#### Issue 1: Signature Verification Fails

**Symptoms:**
```
InvalidSignature: Signature does not match
```

**Causes:**
- Code was modified after signing
- Wrong public key used for verification
- File encoding changed (CRLF vs LF)

**Solution:**
```bash
# Re-sign file
python src/code_manifest.py sign --file my_module.py
```

---

#### Issue 2: Import Hook Not Working

**Symptoms:**
```
import my_module  # ← Not verified
```

**Causes:**
- Import hook not installed
- Hook installed too late (after imports)

**Solution:**
```python
# Install BEFORE any other imports
from runtime_verifier import install_verification_hook
install_verification_hook()

# Now import modules
import my_module  # ← Verified ✅
```

---

#### Issue 3: Performance Too Slow

**Symptoms:**
- App startup takes >10 seconds
- Every import is slow

**Causes:**
- Too many files to verify
- No caching

**Solution:**
```python
# Enable caching
verifier = CodeVerifier(cache_verified=True)

# Verify in parallel
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor() as executor:
    results = executor.map(verifier.verify_file, files)
```

---

## Summary

✅ **Asymmetric Encryption**: ECDSA (Elliptic Curve) with SHA-256  
✅ **Private Key**: Signs code (must be kept secure in HSM/TPM)  
✅ **Public Key**: Verifies signatures (embedded in runtime)  
✅ **Inline Manifest**: Signature embedded in file header  
✅ **Runtime Verification**: Import hooks verify before execution  
✅ **Central Database**: JSON manifest for tracking  
✅ **Bulk Signing**: Script to sign entire directory  

**Security Level:** 🔥 **HIGH** (128-bit security with ECDSA P-256)

---

**Documentation Version:** 1.0.0  
**Last Updated:** 2025-10-13  
**Author:** VCC Development Team
