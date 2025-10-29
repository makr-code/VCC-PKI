# VCC Code Header System - Examples & Usage Guide

**Enhanced Metadata & Copyright Protection for Python Source Code**

**Date:** 13. Oktober 2025  
**Version:** 1.0.0

---

## 📖 Table of Contents

1. [Quick Start](#quick-start)
2. [Header Components](#header-components)
3. [Usage Examples](#usage-examples)
4. [Integration with Code Signing](#integration-with-code-signing)
5. [Best Practices](#best-practices)

---

## 🚀 Quick Start

### Install

```bash
# Headers are part of VCC PKI system
cd C:\VCC\PKI\src
# No additional installation required
```

### Generate Basic Header

```bash
# Add header to single file
python code_header.py generate --file my_module.py --version 1.0.0

# With description
python code_header.py generate \
    --file my_service.py \
    --version 2.3.1 \
    --author "John Doe" \
    --description "Authentication service for VCC platform" \
    --classification CONFIDENTIAL
```

### Extract Header Metadata

```bash
# Extract as text
python code_header.py extract --file my_module.py

# Extract as JSON
python code_header.py extract --file my_module.py --format json
```

### Verify Header Integrity

```bash
# Verify content hashes match
python code_header.py verify --file my_module.py --verbose
```

---

## 📋 Header Components

### Complete Header Structure

```python
# ==============================================================================
# VCC PROTECTED SOURCE CODE
# ==============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# License: Proprietary
# Contact: legal@vcc.local
#
# Module: authentication_service
# Description: OAuth2 authentication and authorization service
# File Path: src/services/authentication_service.py
#
# Version: 2.3.1
# Semantic Version: 2.3.1
#
# Author: VCC Security Team
# Author Email: security@vcc.local
# Maintainer: John Doe
# Maintainer Email: john.doe@vcc.local
#
# Build Date: 2025-10-13T20:45:30.123456+00:00
# Release Channel: production
# Build Number: 20251013.142
# Builder: GitHub Actions CI/CD
# Git Commit: abc12345
# Git Branch: release/v2.3
# Git Tag: v2.3.1
#
# File UUID: 550e8400-e29b-41d4-a716-446655440000
# Content Hash (SHA-256): 3a4f5b2c1d6e8f9a0b1c2d3e4f5a6b7c...
# Content Hash (SHA-512): 1f2e3d4c5b6a7980f1e2d3c4b5a69788...
# File Size: 15847 bytes
# Line Count: 542
# Created: 2025-10-13T20:45:30.123456+00:00
# Modified: 2025-10-13T20:45:30.123456+00:00
#
# Classification: CONFIDENTIAL
# DRM Protected: Yes
# Security Contact: security@vcc.local
# Allowed Domains: vcc.local, vcc-prod.local
# Required Python: >=3.8
#
# ------------------------------------------------------------------------------
# DIGITAL SIGNATURE
# ------------------------------------------------------------------------------
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100ab12cd34ef56...
# Signed: 2025-10-13T20:45:35.789012+00:00
# Signer: VCC Code Signing System
# WARNING: This file is cryptographically signed.
# Any modification will invalidate the signature and may prevent execution.
#
# ==============================================================================

import sys
import os
# ... actual Python code starts here ...
```

---

## 🎯 Usage Examples

### Example 1: Basic Header Generation

```python
from code_header import HeaderBuilder, CodeHeader

# Read source code
with open('my_module.py', 'r') as f:
    source_code = f.read()

# Build header
builder = HeaderBuilder()
builder.copyright("VCC - Veritas Control Center", 2025, "Proprietary")
builder.version(1, 0, 0)
builder.author("VCC Development Team", "dev@vcc.local")
builder.module("my_module", "Example module with metadata")
builder.security("INTERNAL", drm_enabled=True)
builder.compute_identity(source_code)

header = builder.build()

# Generate header block
header_block = header.to_header_block(include_signature=False)

# Write file with header
with open('my_module_with_header.py', 'w') as f:
    f.write(header_block)
    f.write('\n')
    f.write(source_code)
```

**Output:**
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
# Description: Example module with metadata
# ...
```

---

### Example 2: Extract and Parse Header

```python
from code_header import HeaderExtractor

# Read file
with open('protected_module.py', 'r') as f:
    source_code = f.read()

# Extract header
result = HeaderExtractor.extract_header(source_code)

if result:
    header, source_without_header = result
    
    print(f"UUID: {header.file_identity.file_uuid}")
    print(f"Version: {header.version_info.version}")
    print(f"Author: {header.author_info.author}")
    print(f"Hash: {header.file_identity.content_hash_sha256[:32]}...")
    print(f"Classification: {header.security_info.classification}")
    
    # Access original source code (without header)
    print(f"\nSource code length: {len(source_without_header)} bytes")
else:
    print("No VCC header found")
```

**Output:**
```
UUID: 550e8400-e29b-41d4-a716-446655440000
Version: 2.3.1
Author: VCC Security Team
Hash: 3a4f5b2c1d6e8f9a0b1c2d3e4f5a6b7c...
Classification: CONFIDENTIAL

Source code length: 15847 bytes
```

---

### Example 3: Verify Header Integrity

```python
from code_header import HeaderExtractor, FileIdentity

# Read file
with open('protected_module.py', 'r') as f:
    source_code = f.read()

# Extract header
result = HeaderExtractor.extract_header(source_code)

if not result:
    print("ERROR: No VCC header found")
    exit(1)

header, source_without_header = result

# Compute current hashes
current_identity = FileIdentity()
current_identity.compute_hashes(source_without_header)

# Compare
stored_hash = header.file_identity.content_hash_sha256
current_hash = current_identity.content_hash_sha256

if stored_hash == current_hash:
    print("✓ Header integrity verified")
    print(f"  Hash: {current_hash[:32]}...")
else:
    print("✗ Header integrity FAILED")
    print(f"  Stored:  {stored_hash[:32]}...")
    print(f"  Current: {current_hash[:32]}...")
    print("  WARNING: File content has been modified!")
```

---

### Example 4: Export Header as JSON

```python
from code_header import HeaderExtractor
import json

# Extract header
with open('protected_module.py', 'r') as f:
    result = HeaderExtractor.extract_header(f.read())

if result:
    header, _ = result
    
    # Export as JSON
    json_metadata = header.to_json()
    
    # Save to external manifest (optional)
    with open('manifest.json', 'w') as f:
        f.write(json_metadata)
    
    # Pretty print
    metadata = json.loads(json_metadata)
    print(json.dumps(metadata, indent=2))
```

**Output:**
```json
{
  "copyright": {
    "holder": "VCC - Veritas Control Center",
    "year": 2025,
    "license": "Proprietary",
    "license_url": null,
    "contact": "legal@vcc.local"
  },
  "version": {
    "major": 2,
    "minor": 3,
    "patch": 1,
    "prerelease": null,
    "build_metadata": null
  },
  "identity": {
    "file_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "content_hash_sha256": "3a4f5b2c...",
    "content_hash_sha512": "1f2e3d4c...",
    "file_size": 15847,
    "line_count": 542,
    "created_at": "2025-10-13T20:45:30.123456+00:00",
    "modified_at": "2025-10-13T20:45:30.123456+00:00"
  },
  ...
}
```

---

## 🔐 Integration with Code Signing

### Combined: Enhanced Header + Digital Signature

```bash
# Sign file with enhanced header
python code_manifest.py sign \
    --file my_module.py \
    --enhanced-header \
    --version 2.3.1 \
    --author "Security Team" \
    --description "Secure authentication module" \
    --classification CONFIDENTIAL \
    --git-commit abc12345 \
    --build-number 20251013.142 \
    --channel production
```

**Result:**
```python
# ==============================================================================
# VCC PROTECTED SOURCE CODE
# ==============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# ... (full metadata) ...
#
# ------------------------------------------------------------------------------
# DIGITAL SIGNATURE
# ------------------------------------------------------------------------------
# VCC-MANIFEST: v1 ECDSA_SHA256 3045022100ab12cd34ef56...
# Signed: 2025-10-13T20:45:35.789012+00:00
# Signer: VCC Code Signing System
# WARNING: This file is cryptographically signed.
# Any modification will invalidate the signature and may prevent execution.
#
# ==============================================================================

import sys
# ... actual code ...
```

### Python API Integration

```python
from code_manifest import CodeSigner

# Create signer with enhanced headers
signer = CodeSigner(private_key_path='production_private.pem')

# Sign with metadata
signer.sign_file(
    'my_module.py',
    enhanced_header=True,
    version='2.3.1',
    author='Security Team',
    description='Secure authentication module',
    classification='CONFIDENTIAL',
    git_commit='abc12345',
    build_number='20251013.142',
    channel='production',
    signer_id='ci-cd@vcc.local'
)
```

---

## ✅ Best Practices

### DO's ✅

1. **Always use enhanced headers for production code**
   ```bash
   python code_manifest.py sign --file prod.py --enhanced-header
   ```

2. **Include build metadata in CI/CD**
   ```yaml
   # GitHub Actions
   - name: Sign code
     run: |
       python code_manifest.py sign \
         --file ${{ matrix.file }} \
         --enhanced-header \
         --git-commit ${{ github.sha }} \
         --build-number ${{ github.run_number }} \
         --channel production
   ```

3. **Use semantic versioning consistently**
   - Major version: Breaking changes
   - Minor version: New features
   - Patch version: Bug fixes
   ```bash
   --version 2.3.1  # major.minor.patch
   ```

4. **Set appropriate security classification**
   - `PUBLIC`: Open source, public APIs
   - `INTERNAL`: Internal use only
   - `CONFIDENTIAL`: Sensitive business logic
   - `SECRET`: Cryptographic keys, credentials
   ```bash
   --classification CONFIDENTIAL
   ```

5. **Track file identity with UUIDs**
   - Each file gets unique UUID
   - UUID persists across versions
   - Enables tracking and auditing

6. **Verify integrity before deployment**
   ```bash
   python code_header.py verify --file my_module.py --verbose
   ```

7. **Export metadata for compliance**
   ```bash
   # Generate manifest.json for audits
   python code_header.py extract --file my_module.py --format json > manifest.json
   ```

---

### DON'Ts ❌

1. **❌ Don't skip copyright information**
   - Required for legal protection
   - Include year and holder

2. **❌ Don't use generic descriptions**
   ```bash
   # Bad
   --description "Python module"
   
   # Good
   --description "OAuth2 authentication with JWT token validation"
   ```

3. **❌ Don't use wrong classification**
   ```bash
   # Bad: Public repo with CONFIDENTIAL tag
   # Bad: Production keys with PUBLIC tag
   ```

4. **❌ Don't modify headers manually**
   - Always use `code_header.py generate` or `code_manifest.py sign`
   - Manual changes break integrity checks

5. **❌ Don't forget to update version**
   ```bash
   # When fixing bugs:
   --version 1.2.4  # Increment patch
   
   # When adding features:
   --version 1.3.0  # Increment minor
   
   # When breaking compatibility:
   --version 2.0.0  # Increment major
   ```

---

## 📊 Metadata Fields Reference

### Copyright Information
- `holder`: Copyright holder name
- `year`: Copyright year
- `license`: License type (e.g., Proprietary, MIT, Apache-2.0)
- `license_url`: URL to license text
- `contact`: Legal contact email

### Version Information (Semantic Versioning)
- `major`: Breaking changes
- `minor`: New features (backward compatible)
- `patch`: Bug fixes
- `prerelease`: alpha, beta, rc (optional)
- `build_metadata`: Build number, commit hash (optional)

### File Identity
- `file_uuid`: Unique file identifier (UUID v4)
- `content_hash_sha256`: SHA-256 hash of content
- `content_hash_sha512`: SHA-512 hash of content
- `file_size`: File size in bytes
- `line_count`: Number of lines
- `created_at`: Creation timestamp (ISO 8601)
- `modified_at`: Last modification timestamp

### Build Information
- `build_number`: CI/CD build number
- `build_date`: Build timestamp
- `builder`: CI/CD system or developer
- `build_host`: Build machine hostname
- `git_commit`: Git commit hash (short)
- `git_branch`: Git branch name
- `git_tag`: Git tag (if release)
- `release_channel`: development, staging, production

### Author Information
- `author`: Primary author name
- `author_email`: Author email
- `maintainer`: Current maintainer
- `maintainer_email`: Maintainer email
- `contributors`: List of contributors

### Security Information
- `classification`: PUBLIC, INTERNAL, CONFIDENTIAL, SECRET
- `security_contact`: Security team email
- `drm_enabled`: DRM protection flag
- `allowed_domains`: Allowed execution domains
- `expiration_date`: Code expiration date (optional)
- `required_python_version`: Minimum Python version

---

## 🎓 Advanced Usage

### Custom Header Builder

```python
from code_header import (
    CodeHeader, CopyrightInfo, VersionInfo, FileIdentity,
    BuildInfo, AuthorInfo, SecurityInfo
)

# Create custom header
header = CodeHeader()

# Custom copyright
header.copyright_info = CopyrightInfo(
    holder="ACME Corporation",
    year=2025,
    license="MIT",
    license_url="https://opensource.org/licenses/MIT",
    contact="opensource@acme.com"
)

# Custom version
header.version_info = VersionInfo(
    major=3,
    minor=2,
    patch=1,
    prerelease="rc.1",
    build_metadata="20251013.ghactions.123"
)

# Custom authors
header.author_info = AuthorInfo(
    author="Jane Smith",
    author_email="jane@acme.com",
    maintainer="Bob Johnson",
    maintainer_email="bob@acme.com",
    contributors=["Alice", "Charlie", "David"]
)

# Generate header block
header_block = header.to_header_block(include_signature=False)
print(header_block)
```

---

## 🔍 Troubleshooting

### Issue: "No VCC header found"

**Cause:** File doesn't have enhanced header.

**Solution:**
```bash
python code_header.py generate --file my_module.py
```

### Issue: "Header integrity FAILED"

**Cause:** File content changed after header generation.

**Solution:**
```bash
# Re-generate header with current content
python code_header.py generate --file my_module.py --version 1.0.1
```

### Issue: "ImportError: cannot import code_header"

**Cause:** `code_header.py` not in Python path.

**Solution:**
```bash
cd C:\VCC\PKI\src
python code_manifest.py sign --file ../my_module.py --enhanced-header
```

---

## 📞 Support

**Documentation:**
- Header System: `docs/CODE_HEADER_EXAMPLES.md`
- Code Signing: `docs/CODE_SIGNING.md`
- Source Code: `src/code_header.py`, `src/code_manifest.py`

**Commands:**
```bash
python code_header.py --help
python code_header.py generate --help
python code_header.py extract --help
python code_header.py verify --help
```

---

**Last Updated:** 13. Oktober 2025  
**Version:** 1.0.0  
**Status:** Production Ready ✅
