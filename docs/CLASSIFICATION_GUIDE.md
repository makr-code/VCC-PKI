# VCC Code Classification Guide

**Security Classification Framework für Source Code**

**Version:** 1.0.0  
**Date:** 13. Oktober 2025  
**Status:** Production Ready

---

## 📋 Table of Contents

1. [Classification Levels](#classification-levels)
2. [Decision Tree](#decision-tree)
3. [Classification Criteria](#classification-criteria)
4. [Examples by Component](#examples-by-component)
5. [Auto-Classification Rules](#auto-classification-rules)
6. [Review & Reclassification](#review--reclassification)

---

## 🔒 Classification Levels

### Level 1: PUBLIC

**Definition:** Code der öffentlich zugänglich ist oder sein könnte.

**Kriterien:**
- ✅ Open Source Komponenten
- ✅ Public APIs (dokumentiert)
- ✅ Client-Side Code (Browser sichtbar)
- ✅ Example Code / Tutorials
- ✅ Public Libraries
- ✅ No sensitive logic or data

**Risiko bei Leak:** ⚠️ NIEDRIG - Ist bereits öffentlich

**Examples:**
```python
# Public API Client Library
# Classification: PUBLIC
class VCCPublicAPIClient:
    """Public client for VCC REST API."""
    
    def get_public_info(self):
        """Get public information."""
        return requests.get("https://api.vcc.local/public/info")
```

**Access Control:**
- Keine Zugriffsbeschränkungen
- Kann auf GitHub/GitLab veröffentlicht werden
- Darf in öffentliche Dokumentation
- Keine DRM Protection nötig

**License:** MIT, Apache-2.0, BSD, GPL (Open Source)

---

### Level 2: INTERNAL

**Definition:** Code für interne Verwendung, keine externen Geheimnisse.

**Kriterien:**
- ✅ Interne Tools & Scripts
- ✅ Internal APIs (nicht extern exponiert)
- ✅ Utility Functions
- ✅ Configuration Management
- ✅ Test Code
- ❌ KEINE Credentials/Keys
- ❌ KEINE Geschäftslogik mit Wettbewerbsvorteil

**Risiko bei Leak:** ⚠️ MITTEL - Zeigt interne Struktur

**Examples:**
```python
# Internal Admin Tool
# Classification: INTERNAL
class VCCAdminTool:
    """Internal administration tool for VCC services."""
    
    def restart_service(self, service_name):
        """Restart internal service."""
        # Internal implementation details
        pass
```

**Access Control:**
- Zugriff nur für VCC Mitarbeiter
- NICHT auf GitHub/GitLab
- Interne GitLab/Azure DevOps
- Standard DRM (Domain-Check)

**License:** Proprietary (Closed Source)

**Typical Components:**
- Admin Tools
- Deployment Scripts
- Internal Dashboards
- Log Analysis Tools
- Test Suites

---

### Level 3: CONFIDENTIAL

**Definition:** Code mit Geschäftsgeheimnissen oder sensiblen Algorithmen.

**Kriterien:**
- ✅ Business Logic mit Wettbewerbsvorteil
- ✅ Proprietäre Algorithmen
- ✅ Customer Data Processing
- ✅ Financial Calculations
- ✅ Security-kritische Komponenten
- ✅ Integration mit sensiblen Systemen
- ❌ KEINE Hard-Coded Credentials (verwende Vault!)

**Risiko bei Leak:** 🚨 HOCH - Geschäftsschaden möglich

**Examples:**
```python
# Proprietary ML Algorithm
# Classification: CONFIDENTIAL
class VCCMLPredictor:
    """
    Proprietary machine learning algorithm.
    Patent pending: DE102025XXXXX
    """
    
    def predict_risk_score(self, customer_data):
        """Calculate proprietary risk score."""
        # Secret algorithm
        # Competitive advantage
        pass
```

**Access Control:**
- Zugriff nur nach Need-to-Know
- Verschlüsselte Git Repositories
- Code Signing REQUIRED
- DRM mit Domain + Expiration
- Audit Logging bei Access

**License:** Proprietary with NDA

**Typical Components:**
- Core Business Logic
- Proprietary Algorithms
- Payment Processing
- Customer Data Analytics
- Security Modules (Authentication, Encryption)

---

### Level 4: SECRET

**Definition:** Höchste Sicherheitsstufe - kritische Infrastruktur.

**Kriterien:**
- ✅ Cryptographic Key Management
- ✅ Authentication/Authorization Core
- ✅ HSM Integration
- ✅ Security Audit Systems
- ✅ Certificate Authority Core
- ✅ Zero-Trust Infrastructure
- ⚠️ Access nur für Security Team

**Risiko bei Leak:** 🔥 KRITISCH - Systemkompromittierung möglich

**Examples:**
```python
# CA Private Key Management
# Classification: SECRET
class VCCCAKeyManager:
    """
    CRITICAL: Certificate Authority Key Management
    Access restricted to Security Team only.
    All access is logged and monitored.
    """
    
    def sign_certificate_with_ca_key(self, csr):
        """Sign CSR with CA private key (HSM-backed)."""
        # CRITICAL OPERATION
        # HSM access
        # Audit logged
        pass
```

**Access Control:**
- Multi-Factor Authentication REQUIRED
- HSM Storage für Keys
- Air-Gapped Development Environment
- Video Surveillance bei Access (optional)
- All access logged & monitored
- Regular Security Audits

**License:** Proprietary with Strict NDA

**Typical Components:**
- CA Private Key Operations
- HSM Integration
- Master Encryption Keys
- Authentication Backend
- Security Audit Core
- Zero-Day Exploit Mitigation

---

## 🌳 Decision Tree

```
START: Neue Datei klassifizieren

┌─────────────────────────────────────────────────────┐
│ Enthält die Datei Credentials, Keys, Tokens?       │
│ (Hard-coded Secrets)                                │
└─────────────────────────────────────────────────────┘
          │
          ├─ JA ──▶ ❌ STOP! Use Vault/Secrets Manager
          │         (Keine Hard-Coded Secrets in Code!)
          │
          └─ NEIN
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ Ist der Code Open Source oder soll er es werden?   │
└─────────────────────────────────────────────────────┘
          │
          ├─ JA ──▶ ✅ PUBLIC
          │
          └─ NEIN
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ Enthält der Code CA Private Key Operationen oder   │
│ HSM Integration?                                    │
└─────────────────────────────────────────────────────┘
          │
          ├─ JA ──▶ 🔥 SECRET
          │
          └─ NEIN
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ Enthält der Code proprietäre Algorithmen oder      │
│ Business Logic mit Wettbewerbsvorteil?             │
└─────────────────────────────────────────────────────┘
          │
          ├─ JA ──▶ 🚨 CONFIDENTIAL
          │
          └─ NEIN
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ Ist der Code für interne Verwendung?               │
└─────────────────────────────────────────────────────┘
          │
          ├─ JA ──▶ ⚠️ INTERNAL
          │
          └─ NEIN
                │
                ▼
          ✅ PUBLIC (Default)
```

---

## 📊 Classification Criteria Matrix

| Criteria | PUBLIC | INTERNAL | CONFIDENTIAL | SECRET |
|----------|--------|----------|--------------|--------|
| **Open Source** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **External API** | ✅ Yes | ⚠️ Internal | ❌ No | ❌ No |
| **Business Logic** | ❌ No | ⚠️ Simple | ✅ Core | ✅ Critical |
| **Customer Data** | ❌ No | ⚠️ Metadata | ✅ PII | ✅ Payment |
| **Credentials** | ❌ Never | ❌ Never | ❌ Never | ⚠️ Key Mgmt |
| **Access Control** | 🌍 Public | 🏢 All Staff | 👥 Need-to-Know | 🔐 Security Team |
| **Leak Impact** | ⚪ None | 🟡 Low | 🟠 High | 🔴 Critical |
| **Code Signing** | ⚪ Optional | 🟡 Recommended | 🟠 Required | 🔴 Mandatory |
| **DRM Protection** | ❌ No | ⚠️ Basic | ✅ Advanced | ✅ Maximum |
| **Audit Logging** | ❌ No | ⚪ Optional | 🟡 Recommended | 🔴 Mandatory |

---

## 🏗️ Examples by VCC Component

### VCC PKI System

```yaml
# pki_server.py - Main API Server
Classification: CONFIDENTIAL
Reason: Exposes CA operations, business logic
Access: Development + Operations Team
DRM: Domain-locked, Code-signed

# ca_manager.py - CA Certificate Management
Classification: SECRET
Reason: Interacts with CA private keys (via HSM)
Access: Security Team only
DRM: Domain-locked, Code-signed, Audit-logged

# certificate_api.py - Certificate CRUD
Classification: CONFIDENTIAL
Reason: Business logic, customer certificates
Access: Development Team
DRM: Domain-locked, Code-signed

# pki_client.py - Public Client Library
Classification: PUBLIC
Reason: Client-side library for external use
Access: Public (GitHub)
DRM: None
License: MIT

# deployment_scripts.py - Deployment Automation
Classification: INTERNAL
Reason: Internal tooling, no secrets
Access: Operations Team
DRM: Basic domain check

# test_pki_server.py - Unit Tests
Classification: INTERNAL
Reason: Test code, no production logic
Access: Development Team
DRM: None
```

### VCC Authentication Service

```yaml
# auth_api.py - Authentication API
Classification: CONFIDENTIAL
Reason: Security-critical, user authentication
Access: Security + Development Team
DRM: Domain-locked, Code-signed

# password_hasher.py - Password Hashing
Classification: CONFIDENTIAL
Reason: Security algorithm (bcrypt/argon2)
Access: Security Team
DRM: Code-signed

# jwt_manager.py - JWT Token Management
Classification: CONFIDENTIAL
Reason: Token generation/validation
Access: Development Team
DRM: Code-signed

# key_manager.py - Master Key Operations
Classification: SECRET
Reason: Manages encryption master keys
Access: Security Team only
DRM: HSM-backed, Audit-logged
```

### VCC Data Analytics

```yaml
# ml_predictor.py - Proprietary ML Model
Classification: CONFIDENTIAL
Reason: Proprietary algorithm, competitive advantage
Patent: Pending
Access: Data Science Team
DRM: Domain-locked, Code-signed

# data_loader.py - Data Loading Utils
Classification: INTERNAL
Reason: Utility functions, no business logic
Access: Data Science Team
DRM: Basic

# public_api_client.py - Public API Client
Classification: PUBLIC
Reason: Client library for external customers
Access: Public
License: Apache-2.0
```

---

## 🤖 Auto-Classification Rules

### Rule-Based Classification

```python
# Pseudo-Code für Auto-Classification

def auto_classify_file(file_path, content):
    """Automatically classify a file based on content analysis."""
    
    # Rule 1: Check for hard-coded secrets (BLOCK!)
    if contains_secrets(content):
        raise SecurityError("Hard-coded secrets detected! Use Vault!")
    
    # Rule 2: Check filename patterns
    if file_path.endswith("_test.py"):
        return "INTERNAL"  # Test files
    
    if file_path.startswith("scripts/"):
        return "INTERNAL"  # Deployment scripts
    
    # Rule 3: Check for SECRET indicators
    secret_keywords = [
        "private_key", "hsm", "master_key",
        "ca_sign", "root_certificate",
        "secret_key_base"
    ]
    if any_keyword_in_code(content, secret_keywords):
        return "SECRET"
    
    # Rule 4: Check for CONFIDENTIAL indicators
    confidential_keywords = [
        "proprietary", "patent", "competitive",
        "business_logic", "pricing_algorithm",
        "customer_data", "payment"
    ]
    if any_keyword_in_code(content, confidential_keywords):
        return "CONFIDENTIAL"
    
    # Rule 5: Check for PUBLIC indicators
    if has_open_source_license(content):
        return "PUBLIC"
    
    if is_in_public_api_folder(file_path):
        return "PUBLIC"
    
    # Default: INTERNAL
    return "INTERNAL"
```

### Automated Classification Tool

```bash
# CLI Tool für Auto-Classification
python classify_code.py --scan src/ --recursive

# Output:
# [SECRET]       src/ca_manager.py (HSM operations detected)
# [CONFIDENTIAL] src/ml_predictor.py (proprietary algorithm)
# [INTERNAL]     src/utils.py (utility functions)
# [PUBLIC]       src/api_client.py (open source license)
#
# Summary:
#   SECRET:       5 files
#   CONFIDENTIAL: 23 files
#   INTERNAL:     102 files
#   PUBLIC:       8 files
```

---

## 🔄 Review & Reclassification

### When to Review Classification

**Triggers für Review:**
1. ✅ **Code Changes:** Major refactoring
2. ✅ **New Features:** Business logic added
3. ✅ **Open Sourcing:** Decision to open source
4. ✅ **Security Audit:** Regular security reviews
5. ✅ **Compliance:** Regulatory changes
6. ✅ **Quarterly:** Scheduled reviews

### Reclassification Process

```yaml
# Example: Reclassification Workflow

1. Request:
   - Developer: "I want to open source api_client.py"
   - Current: INTERNAL
   - Proposed: PUBLIC

2. Security Review:
   - Check for secrets: ✅ PASS (no hard-coded secrets)
   - Check for business logic: ✅ PASS (generic client)
   - Check for dependencies: ✅ PASS (all public libraries)

3. Legal Review:
   - Copyright check: ✅ PASS (VCC owns code)
   - License compatibility: ✅ PASS (MIT compatible)
   - NDA implications: ✅ PASS (no NDA breach)

4. Approval:
   - Security Team: ✅ APPROVED
   - Legal Team: ✅ APPROVED
   - Management: ✅ APPROVED

5. Reclassify:
   python code_header.py generate \
       --file api_client.py \
       --classification PUBLIC \
       --license MIT

6. Publish:
   - Push to GitHub
   - Update documentation
   - Announce on blog
```

### Downgrade (CONFIDENTIAL → INTERNAL)

**Requirements:**
- Remove proprietary algorithms
- Generalize business logic
- Remove customer-specific code
- Security Team approval

**Example:**
```python
# BEFORE (CONFIDENTIAL)
def calculate_proprietary_risk_score(customer):
    """Secret algorithm with competitive advantage."""
    # Proprietary logic
    return score

# AFTER (INTERNAL)
def calculate_generic_risk_score(data):
    """Generic risk calculation."""
    # Standard algorithm (no secrets)
    return score
```

### Upgrade (INTERNAL → CONFIDENTIAL)

**Triggers:**
- Business logic added
- Customer data processing
- Competitive advantage gained

**Example:**
```python
# BEFORE (INTERNAL)
def send_email(to, subject, body):
    """Generic email sender."""
    smtp.send(to, subject, body)

# AFTER (CONFIDENTIAL)
def send_customer_invoice(customer, invoice_data):
    """Send invoice with pricing algorithm."""
    # Now contains proprietary pricing logic
    # Now processes customer PII
    pricing = calculate_proprietary_pricing(invoice_data)
    send_email(customer.email, "Invoice", pricing)
```

---

## ⚖️ Legal Considerations

### Copyright & Classification

**PUBLIC:**
- Copyright: VCC (or Open Source Contributors)
- License: MIT, Apache-2.0, etc.
- Warranty: AS-IS, No Warranty

**INTERNAL/CONFIDENTIAL/SECRET:**
- Copyright: VCC - Veritas Control Center
- License: Proprietary
- Warranty: Internal Use Only

### GDPR Implications

**If processing EU customer data:**
- Minimum: **CONFIDENTIAL**
- PII (Personal Identifiable Information): **CONFIDENTIAL**
- Financial Data: **CONFIDENTIAL** or **SECRET**
- Health Data: **SECRET**

### Export Control (EAR/ITAR)

**If encryption > 64-bit:**
- Check: US Export Administration Regulations
- May require: **SECRET** classification
- May require: Export license

---

## 📋 Classification Checklist

### Before Committing Code

```markdown
- [ ] Classification determined (PUBLIC/INTERNAL/CONFIDENTIAL/SECRET)
- [ ] No hard-coded secrets (checked with secret scanner)
- [ ] Header generated with correct classification
- [ ] Code signed (if CONFIDENTIAL or SECRET)
- [ ] Access control configured (if CONFIDENTIAL or SECRET)
- [ ] Audit logging enabled (if SECRET)
- [ ] Security Team review (if SECRET)
- [ ] Legal Team review (if PUBLIC)
```

### Classification Review Form

```yaml
File: src/my_module.py
Current Classification: INTERNAL
Proposed Classification: CONFIDENTIAL

Reasons for Reclassification:
  - Added proprietary ML algorithm
  - Processes customer payment data
  - Competitive advantage if leaked

Security Review:
  - Secrets scan: PASS (no hard-coded secrets)
  - Dependency scan: PASS (all internal dependencies)
  - Code review: PASS (no security issues)

Approval:
  - Requester: John Doe (2025-10-13)
  - Security Team: Jane Smith (2025-10-13)
  - Manager: Bob Johnson (2025-10-13)

Actions:
  - [x] Update header classification
  - [x] Enable code signing
  - [x] Configure access control
  - [x] Update documentation
```

---

## 🛠️ Tools & Integration

### CLI Tool for Classification

```bash
# Scan and suggest classification
python classify_code.py --file src/my_module.py --suggest

# Output:
# File: src/my_module.py
# Current: INTERNAL
# Suggested: CONFIDENTIAL
# Reason: Contains 'proprietary_algorithm' keyword
# Confidence: 85%
#
# Apply suggestion? [y/N]
```

### Git Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check classification for all modified .py files
for file in $(git diff --cached --name-only --diff-filter=ACM | grep '\.py$'); do
    # Check if file has VCC header
    if ! python code_header.py extract --file "$file" > /dev/null 2>&1; then
        echo "ERROR: $file missing VCC header!"
        echo "Run: python code_header.py generate --file $file"
        exit 1
    fi
    
    # Check for hard-coded secrets
    if python secret_scanner.py --file "$file" --strict; then
        echo "ERROR: $file contains hard-coded secrets!"
        exit 1
    fi
done
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Classification Scan

on: [push, pull_request]

jobs:
  classify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Check Classifications
        run: |
          python classify_code.py --scan src/ --recursive --report
          
      - name: Secret Scan
        run: |
          python secret_scanner.py --scan src/ --recursive --fail-on-error
          
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: classification-report
          path: classification_report.json
```

---

## 📞 Support & Questions

**Wer entscheidet bei Unklarheit?**

1. **Entwickler:** Initiale Klassifizierung
2. **Team Lead:** Review & Approval (INTERNAL/CONFIDENTIAL)
3. **Security Team:** Approval für SECRET
4. **Legal Team:** Approval für PUBLIC (Open Source)
5. **Management:** Final Decision bei Konflikt

**Kontakte:**
- Security Team: security@vcc.local
- Legal Team: legal@vcc.local
- Compliance: compliance@vcc.local

---

**Last Updated:** 13. Oktober 2025  
**Version:** 1.0.0  
**Status:** Production Ready ✅
