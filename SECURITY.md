# Security Policy and Best Practices

## 🔒 Security Overview

VCC-PKI is a critical security infrastructure component that requires careful configuration and deployment. This document outlines security best practices, known vulnerabilities, and security policies.

## 📋 Table of Contents

1. [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
2. [Security Best Practices](#security-best-practices)
3. [Cryptographic Standards](#cryptographic-standards)
4. [Key Management](#key-management)
5. [Authentication & Authorization](#authentication--authorization)
6. [Network Security](#network-security)
7. [Deployment Security](#deployment-security)
8. [Monitoring & Auditing](#monitoring--auditing)
9. [Compliance](#compliance)

## 🚨 Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it via:

- **Email:** security@vcc.local
- **PGP Key:** [Contact for PGP key]

**DO NOT** create public GitHub issues for security vulnerabilities.

### Response Timeline
- Initial response: Within 24 hours
- Status update: Within 72 hours
- Fix timeline: Based on severity (Critical: 7 days, High: 30 days)

## 🛡️ Security Best Practices

### 1. Environment Configuration

**CRITICAL:** Never use hardcoded passwords or default credentials.

```bash
# Copy and configure environment variables
cp .env.example .env
chmod 600 .env
# Edit .env with strong, unique passwords
```

**Password Requirements:**
- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, special characters
- Use a secure password generator
- Different passwords for dev, staging, production
- Rotate every 90 days

### 2. File Permissions

Restrict access to sensitive files:

```bash
# Private keys (read-only for owner)
chmod 400 ca_storage/*.key
chmod 400 service_certificates/**/*.key

# Certificates (readable by owner and group)
chmod 440 ca_storage/*.pem
chmod 440 service_certificates/**/*.pem

# Configuration files
chmod 600 .env
chmod 644 config/*.yaml

# Database
chmod 600 database/*.db
```

### 3. Private Key Protection

**All private keys MUST be encrypted with strong passwords:**

```python
# DO NOT DO THIS (unencrypted key)
ca_manager.initialize_root_ca()

# DO THIS (encrypted key)
ca_manager.initialize_root_ca(
    password="strong_password_from_vault",
    key_size=4096
)
```

**Key Storage:**
- Root CA keys: Hardware Security Module (HSM) or secure offline storage
- Intermediate CA keys: Encrypted with password from secure vault
- Service keys: Encrypted, stored with restricted permissions

### 4. Secret Management

**Production environments MUST use a secure secret management system:**

Supported systems:
- **Azure Key Vault** (recommended for Azure deployments)
- **AWS Secrets Manager** (recommended for AWS deployments)
- **HashiCorp Vault** (recommended for on-premise)
- **Google Secret Manager** (recommended for GCP deployments)

**Example with HashiCorp Vault:**

```bash
# Store password in Vault
vault kv put secret/vcc-pki/ca-password value="strong_password"

# Retrieve in application
export VCC_INTERMEDIATE_CA_PASSWORD=$(vault kv get -field=value secret/vcc-pki/ca-password)
```

## 🔐 Cryptographic Standards

### Supported Algorithms

**Key Generation:**
- RSA: 2048, 3072, or 4096 bits (4096 recommended for CA keys)
- Elliptic Curve: Not yet supported (planned for Phase 3)

**Hash Functions:**
- SHA-256 (default)
- SHA-384 (recommended for high security)
- SHA-512 (maximum security)

**Prohibited Algorithms (NEVER USE):**
- MD5 (broken)
- SHA-1 (deprecated)
- DES, 3DES (weak)
- RC4 (insecure)
- RSA < 2048 bits (too weak)

### Certificate Validity

**Recommended validity periods:**
- Root CA: 10 years (maximum)
- Intermediate CA: 5 years
- Service certificates: 1 year (recommended), maximum 2 years
- Code signing certificates: 1 year

**Auto-renewal:**
- Enable auto-renewal 30 days before expiration
- Monitor renewal status daily
- Alert on renewal failures

## 🔑 Key Management

### Key Lifecycle

1. **Generation**
   - Use cryptographically secure random number generator
   - Minimum key size: 2048 bits
   - Encrypt immediately with strong password

2. **Storage**
   - Root CA: Air-gapped HSM or secure offline storage
   - Intermediate CA: HSM or encrypted storage with vault-managed password
   - Service keys: Encrypted file storage with restricted permissions

3. **Usage**
   - Root CA: Sign intermediate CA only (keep offline)
   - Intermediate CA: Sign service certificates (online, protected)
   - Service keys: TLS and authentication only

4. **Rotation**
   - Root CA: Every 10 years (or when compromised)
   - Intermediate CA: Every 5 years (or when compromised)
   - Service certificates: Every 365 days (automatic)

5. **Revocation**
   - Immediate revocation on compromise
   - CRL distribution within 1 hour
   - OCSP responder update within 5 minutes

6. **Destruction**
   - Secure deletion (multiple overwrites)
   - Document destruction in audit log
   - Retain revocation information

### HSM Integration

For production deployments, use Hardware Security Modules:

```yaml
# config/pki_server.yaml
hsm:
  enabled: true
  type: "pkcs11"  # or "cloudhsm", "softhsm"
  library_path: "/usr/lib/libpkcs11.so"
  slot: 0
  pin: "${HSM_PIN}"  # From secure vault
```

## 🔐 Authentication & Authorization

### API Authentication

**Enable mTLS for production:**

```yaml
# config/pki_server.yaml
server:
  mtls:
    enabled: true
    verify_client: true
    client_ca_file: "../ca_storage/intermediate_ca.pem"
```

**API Key Authentication (development only):**

```python
# Not recommended for production
headers = {"Authorization": "Bearer <api-key>"}
```

### Role-Based Access Control

Planned for Phase 2:
- Admin: Full access (CA operations, certificate management)
- Operator: Certificate issuance and renewal
- Auditor: Read-only access to logs and certificates
- Service: Certificate requests for own service only

## 🌐 Network Security

### TLS Configuration

**Minimum TLS version: TLS 1.2** (TLS 1.3 recommended)

```yaml
server:
  ssl:
    enabled: true
    min_version: "TLS1.2"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_CHACHA20_POLY1305_SHA256"
```

### Firewall Rules

**Recommended firewall configuration:**

```bash
# Allow HTTPS only
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow only from trusted networks
iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# Block OCSP and CRL from external access (use CDN)
iptables -A INPUT -p tcp --dport 2560 -s 10.0.0.0/8 -j ACCEPT
```

### Rate Limiting

Enable rate limiting to prevent abuse:

```yaml
security:
  rate_limiting:
    enabled: true
    requests_per_minute: 60
    burst: 10
```

## 🚀 Deployment Security

### Production Deployment Checklist

- [ ] **Secrets Management**
  - [ ] All passwords in secure vault (no hardcoded passwords)
  - [ ] Environment variables from vault injection
  - [ ] No .env file in production (use runtime secrets)

- [ ] **Key Protection**
  - [ ] Root CA offline (air-gapped or secure HSM)
  - [ ] Intermediate CA in HSM or encrypted storage
  - [ ] All keys encrypted with strong passwords
  - [ ] File permissions: 400 for keys, 600 for database

- [ ] **Network Security**
  - [ ] mTLS enabled for all service-to-service communication
  - [ ] TLS 1.2+ only (disable TLS 1.0, 1.1)
  - [ ] Firewall rules configured
  - [ ] Rate limiting enabled

- [ ] **Monitoring**
  - [ ] Audit logging enabled
  - [ ] Certificate expiry alerts configured
  - [ ] Failed authentication monitoring
  - [ ] Intrusion detection system (IDS) in place

- [ ] **Access Control**
  - [ ] Principle of least privilege
  - [ ] Multi-factor authentication for admin access
  - [ ] Regular access reviews

- [ ] **Backup & Recovery**
  - [ ] Automated backups (daily)
  - [ ] Encrypted backup storage
  - [ ] Tested disaster recovery plan
  - [ ] Backup retention: 90 days minimum

- [ ] **Compliance**
  - [ ] DSGVO compliance verified
  - [ ] Audit trail complete
  - [ ] Security documentation current

### Container Security (Docker/Kubernetes)

```dockerfile
# Use minimal base image
FROM python:3.11-slim

# Run as non-root user
RUN useradd -m -u 1000 pki
USER pki

# Read-only root filesystem
# Mount secrets as volumes (not in image)
```

```yaml
# Kubernetes security context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

## 📊 Monitoring & Auditing

### Audit Logging

All critical operations are logged:
- Certificate issuance, renewal, revocation
- CA operations
- Failed authentication attempts
- Configuration changes
- Key access

**Audit log format:**
```json
{
  "timestamp": "2025-12-16T18:00:00Z",
  "action": "CERTIFICATE_ISSUED",
  "service_id": "covina-backend",
  "certificate_id": "cert-123",
  "user_id": "admin",
  "ip_address": "10.0.1.5",
  "success": true
}
```

### Security Monitoring

**Monitor for:**
- Failed authentication attempts (> 5 per minute)
- Certificate requests from unknown services
- Expired or expiring certificates (< 30 days)
- CRL/OCSP errors
- Unauthorized CA access attempts

**Alert thresholds:**
- Critical: Failed auth > 10/min, CA compromise, certificate revoked
- High: Certificate expiring < 7 days, OCSP failure
- Medium: Certificate expiring < 30 days, unusual request patterns
- Low: Configuration changes, backup failures

## ✅ Compliance

### DSGVO (GDPR)

- Audit logs contain minimal personal data
- Data retention: 90 days for audit logs
- Right to deletion: Documented process
- Data encryption at rest and in transit

### BSI (German Federal Office for Information Security)

- BSI TR-03116 (eID)
- BSI TR-02102 (Cryptographic Mechanisms)
- Minimum key sizes: RSA 2048, AES 256

### EU AI Act

- Transparency in automated certificate decisions
- Human oversight for critical operations
- Audit trail for compliance

## 🔄 Security Update Policy

### Dependency Updates

- **Critical security patches:** Within 24 hours
- **High security patches:** Within 7 days
- **Regular updates:** Monthly security review

**Update process:**
```bash
# Check for vulnerabilities
pip-audit

# Update dependencies
pip install -U -r requirements.txt

# Test thoroughly before production deployment
pytest tests/

# Deploy with rollback plan
```

### Vulnerability Scanning

**Regular scans:**
- Weekly: Dependency vulnerabilities
- Monthly: Container image scanning
- Quarterly: Penetration testing

**Tools:**
- `pip-audit` for Python dependencies
- `safety` for known vulnerabilities
- `bandit` for code security issues
- `trivy` for container scanning

## 📞 Security Contacts

- **Security Team:** security@vcc.local
- **Incident Response:** incident@vcc.local
- **General Support:** support@vcc.local

## 📚 References

- [RFC 5280 - X.509 Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [BSI TR-02102 - Cryptographic Mechanisms](https://www.bsi.bund.de/EN/Service-Navi/Publications/TechnicalGuidelines/tr02102/tr02102_node.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

**Last Updated:** 2025-12-16
**Version:** 1.0
**Next Review:** 2026-03-16
