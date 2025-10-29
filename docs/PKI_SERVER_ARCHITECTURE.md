# VCC Global PKI Server Architecture

**Version:** 1.0  
**Date:** 2025-10-13  
**Status:** 🔄 Design Phase  

---

## 🎯 Vision

Ein **zentraler PKI Server** für alle VCC Microservices mit:
- ✅ Root CA + Intermediate CA Hierarchie
- ✅ Automatische Zertifikatsgenerierung für Services
- ✅ mTLS-basierte Service-to-Service Kommunikation
- ✅ REST API für Certificate Management
- ✅ Certificate Revocation Lists (CRL)
- ✅ Automatic Certificate Rotation
- ✅ Service Discovery & Registration

---

## 🏗️ System Architecture

```
C:\VCC\PKI\                                 (Global PKI Server)
│
├─ Root CA                                  (10-year validity)
│  ├─ root_ca.pem                          (Public certificate)
│  ├─ root_ca_key.pem                      (Private key - SECURED)
│  └─ root_ca_config.json                  (CA configuration)
│
├─ Intermediate CA                          (5-year validity)
│  ├─ intermediate_ca.pem                  (Signed by Root CA)
│  ├─ intermediate_ca_key.pem              (Private key - SECURED)
│  └─ intermediate_ca_config.json          (CA configuration)
│
├─ Service Certificates/                    (1-year validity, auto-renew)
│  ├─ veritas-backend/
│  │  ├─ cert.pem
│  │  ├─ key.pem
│  │  └─ metadata.json
│  ├─ veritas-frontend/
│  │  ├─ cert.pem
│  │  ├─ key.pem
│  │  └─ metadata.json
│  ├─ covina-backend/
│  ├─ covina-ingestion/
│  ├─ vpb-backend/
│  ├─ clara-backend/
│  └─ monitoring-service/
│
├─ PKI Server/                              (FastAPI REST API)
│  ├─ pki_server.py                        (Main API)
│  ├─ ca_manager.py                        (CA operations)
│  ├─ cert_manager.py                      (Certificate CRUD)
│  ├─ crl_manager.py                       (Revocation lists)
│  ├─ service_registry.py                  (Service discovery)
│  └─ rotation_scheduler.py                (Auto-renewal)
│
├─ Database/                                (SQLite for metadata)
│  ├─ pki_server.db                        (Certificates, services, CRL)
│  └─ schema.sql                           (Database schema)
│
├─ Configuration/
│  ├─ pki_config.yaml                      (Global configuration)
│  ├─ service_whitelist.yaml               (Allowed services)
│  └─ rotation_policy.yaml                 (Renewal policies)
│
└─ Documentation/
   ├─ PKI_SERVER_ARCHITECTURE.md           (This file)
   ├─ PKI_API_DOCUMENTATION.md             (REST API docs)
   ├─ SERVICE_INTEGRATION_GUIDE.md         (How to integrate)
   └─ SECURITY_BEST_PRACTICES.md           (Security guidelines)
```

---

## 🔐 Certificate Hierarchy

```
Root CA (10 years)
└─ Intermediate CA (5 years)
   ├─ veritas-backend (1 year, auto-renew)
   ├─ veritas-frontend (1 year, auto-renew)
   ├─ covina-backend (1 year, auto-renew)
   ├─ covina-ingestion (1 year, auto-renew)
   ├─ vpb-backend (1 year, auto-renew)
   ├─ clara-backend (1 year, auto-renew)
   ├─ monitoring-service (1 year, auto-renew)
   └─ ... (future services)
```

**Why Intermediate CA?**
- Root CA stays offline (cold storage)
- Intermediate CA signs service certificates
- If Intermediate CA compromised → revoke + issue new (Root CA safe)
- Industry best practice (X.509 PKI standard)

---

## 🚀 PKI Server Features

### 1. Certificate Management API

**REST Endpoints:**
```
POST   /api/v1/certificates/request        # Request new certificate
GET    /api/v1/certificates/{service_id}   # Get certificate info
GET    /api/v1/certificates/{service_id}/download # Download cert
POST   /api/v1/certificates/{service_id}/renew # Renew certificate
DELETE /api/v1/certificates/{service_id}/revoke # Revoke certificate
GET    /api/v1/certificates/                # List all certificates
```

**Example Request:**
```json
POST /api/v1/certificates/request
{
  "service_name": "veritas-backend",
  "common_name": "veritas-backend.vcc.local",
  "san_dns": ["veritas-backend", "veritas-backend.vcc.local"],
  "san_ip": ["127.0.0.1", "192.168.178.94"],
  "validity_days": 365,
  "key_size": 2048,
  "metadata": {
    "owner": "VERITAS Team",
    "environment": "production",
    "contact": "admin@veritas.local"
  }
}
```

**Response:**
```json
{
  "certificate_id": "cert_veritas_backend_20251013_abc123",
  "service_name": "veritas-backend",
  "common_name": "veritas-backend.vcc.local",
  "serial_number": "1234567890123456789",
  "not_before": "2025-10-13T17:45:00Z",
  "not_after": "2026-10-13T17:45:00Z",
  "issuer": "VCC Intermediate CA",
  "download_url": "/api/v1/certificates/cert_veritas_backend_20251013_abc123/download",
  "status": "active"
}
```

### 2. Service Registry

**Track all registered services:**
```
GET /api/v1/services/              # List all services
POST /api/v1/services/register     # Register new service
GET /api/v1/services/{service_id}  # Get service info
PUT /api/v1/services/{service_id}  # Update service info
```

**Service Registry Entry:**
```json
{
  "service_id": "veritas-backend",
  "service_name": "VERITAS Backend API",
  "service_type": "backend",
  "endpoints": [
    "https://localhost:45678",
    "https://192.168.178.94:45678"
  ],
  "certificate_id": "cert_veritas_backend_20251013_abc123",
  "certificate_expiry": "2026-10-13T17:45:00Z",
  "auto_renew": true,
  "health_check_url": "https://localhost:45678/health",
  "status": "active",
  "last_seen": "2025-10-13T17:45:00Z"
}
```

### 3. Certificate Revocation

**CRL (Certificate Revocation List):**
```
GET  /api/v1/crl                  # Get current CRL
POST /api/v1/crl/revoke           # Revoke certificate
GET  /api/v1/crl/check/{serial}   # Check if cert revoked
```

**Revocation Reasons:**
- Key compromise
- Service decommissioned
- Certificate superseded
- Privilege change
- Security policy violation

### 4. Automatic Certificate Rotation

**Rotation Scheduler:**
```python
# Checks every 6 hours
# Renews certificates 30 days before expiry
# Notifies services via webhook
# Generates new certificate
# Updates service registry
# Archives old certificate
```

**Rotation Policy (configurable):**
```yaml
rotation_policy:
  check_interval_hours: 6
  renew_before_expiry_days: 30
  notification_days: [30, 7, 1]  # Days before expiry to notify
  max_retries: 3
  retry_delay_hours: 1
```

### 5. Service Discovery

**mTLS-based Service Discovery:**
```
GET /api/v1/discovery/services            # List all services
GET /api/v1/discovery/services/{type}     # Filter by type
GET /api/v1/discovery/services/{id}/cert  # Get service cert for mTLS
```

**Use Case:**
- Covina Ingestion needs to connect to VPB Backend
- Queries PKI Server: `GET /api/v1/discovery/services/vpb-backend`
- Gets VPB certificate + endpoint
- Establishes mTLS connection with VPB

---

## 🔒 Security Architecture

### 1. Root CA Security

**Root CA is COLD STORAGE:**
- Root CA private key stored offline (encrypted USB drive)
- Only used to:
  1. Sign Intermediate CA (once every 5 years)
  2. Revoke Intermediate CA (emergency only)
  3. Issue new Intermediate CA (if compromised)
- Root CA certificate publicly distributed (in all services)

**Root CA Access:**
- Air-gapped machine (no network)
- Hardware Security Module (HSM) recommended
- Multi-person authorization (2-of-3 key split)

### 2. Intermediate CA Security

**Intermediate CA is HOT STORAGE:**
- Private key stored on PKI Server (encrypted at rest)
- Used to sign service certificates
- Can be revoked by Root CA if compromised
- Automatically rotated every 5 years

**Intermediate CA Protection:**
- AES-256 encryption (key derived from master password)
- File permissions: 0400 (read-only by PKI Server user)
- Audit logging (all signing operations)
- Rate limiting (max 100 certs/hour)

### 3. Service Certificate Security

**Service Certificates:**
- Short-lived (1 year, auto-renewed)
- Private keys never leave service host
- CSR-based issuance (private key generated by service)
- mTLS required for all API calls to PKI Server

### 4. PKI Server Authentication

**All API calls require mTLS:**
```
Client → PKI Server:
1. Client sends CSR + mTLS client cert (existing cert)
2. PKI Server validates client certificate
3. PKI Server checks service whitelist
4. PKI Server signs CSR with Intermediate CA
5. Returns new certificate to client
```

**Bootstrap Problem:**
- First certificate: Manual issuance (admin CLI)
- Subsequent renewals: Automated via API

---

## 📊 Database Schema

```sql
-- Services table
CREATE TABLE services (
    service_id TEXT PRIMARY KEY,
    service_name TEXT NOT NULL,
    service_type TEXT,
    endpoints JSON,
    health_check_url TEXT,
    auto_renew BOOLEAN DEFAULT TRUE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP
);

-- Certificates table
CREATE TABLE certificates (
    certificate_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    common_name TEXT NOT NULL,
    serial_number TEXT UNIQUE NOT NULL,
    fingerprint_sha256 TEXT UNIQUE NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    issuer TEXT NOT NULL,
    status TEXT DEFAULT 'active',  -- active, expired, revoked
    revoked_at TIMESTAMP,
    revocation_reason TEXT,
    pem_certificate TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES services(service_id)
);

-- Certificate Revocation List
CREATE TABLE crl (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revocation_reason TEXT,
    FOREIGN KEY (certificate_id) REFERENCES certificates(certificate_id)
);

-- Audit Log
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service_id TEXT,
    action TEXT NOT NULL,  -- request, renew, revoke, download
    certificate_id TEXT,
    client_ip TEXT,
    client_cert_fingerprint TEXT,
    status TEXT,
    details JSON
);

-- Rotation Schedule
CREATE TABLE rotation_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id TEXT NOT NULL,
    scheduled_renewal_date DATE NOT NULL,
    notification_sent BOOLEAN DEFAULT FALSE,
    last_check TIMESTAMP,
    status TEXT DEFAULT 'pending',  -- pending, completed, failed
    FOREIGN KEY (certificate_id) REFERENCES certificates(certificate_id)
);
```

---

## 🚀 Deployment Architecture

### Option 1: Single PKI Server (Development)
```
C:\VCC\PKI\pki_server.py
├─ Runs on localhost:8443 (HTTPS)
├─ SQLite database (local file)
├─ All services connect to 127.0.0.1:8443
└─ Good for: Development, testing
```

### Option 2: High-Availability PKI Cluster (Production)
```
Load Balancer (HAProxy/NGINX)
├─ PKI Server 1 (Active)
├─ PKI Server 2 (Active)
├─ PKI Server 3 (Active)
└─ PostgreSQL Database (Shared)

Features:
- Multi-master replication
- Automatic failover
- Load balancing
- Geographic distribution
```

### Option 3: Cloud-Native (Kubernetes)
```
Kubernetes Cluster
├─ PKI Server Deployment (3 replicas)
├─ Persistent Volume (Intermediate CA key)
├─ PostgreSQL StatefulSet
├─ Ingress (TLS termination)
└─ Service Mesh (Istio/Linkerd)
```

---

## 📋 Service Integration Steps

### 1. Initial Setup (Manual, One-Time)

```bash
# Step 1: Admin generates first certificate for service
cd C:\VCC\PKI
python pki_admin_cli.py create-certificate \
  --service veritas-backend \
  --cn veritas-backend.vcc.local \
  --validity 365

# Step 2: Service receives certificate files
# - veritas-backend-cert.pem
# - veritas-backend-key.pem
# - root-ca.pem (chain of trust)

# Step 3: Service configures mTLS with PKI Server
# - Uses certificate to authenticate to PKI Server
# - Registers in service registry
# - Sets up auto-renewal
```

### 2. Service Code Integration

```python
# VERITAS Backend Example
from vcc_pki_client import PKIClient

# Initialize PKI client
pki_client = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="veritas-backend",
    cert_file="C:/VCC/PKI/service_certificates/veritas-backend/cert.pem",
    key_file="C:/VCC/PKI/service_certificates/veritas-backend/key.pem",
    ca_file="C:/VCC/PKI/root_ca.pem"
)

# Register service
pki_client.register_service(
    service_name="VERITAS Backend API",
    service_type="backend",
    endpoints=["https://localhost:45678"],
    health_check_url="https://localhost:45678/health"
)

# Enable auto-renewal (checks every 6 hours)
pki_client.enable_auto_renewal(
    renew_before_days=30,
    restart_callback=restart_service  # Function to restart service
)

# Get certificate for another service (for mTLS)
covina_cert = pki_client.get_service_certificate("covina-backend")

# Establish mTLS connection to Covina
import httpx
ssl_context = pki_client.create_ssl_context_for_service("covina-backend")
with httpx.Client(verify=ssl_context) as client:
    response = client.get("https://covina-backend:45679/api/v1/data")
```

### 3. Automatic Renewal

```python
# PKI Client handles renewal automatically
# 30 days before expiry:
#   1. Generates new CSR
#   2. Sends to PKI Server via mTLS
#   3. Receives new certificate
#   4. Backs up old certificate
#   5. Installs new certificate
#   6. Calls restart_callback (graceful restart)
#   7. Updates service registry

# Service experiences ~1s downtime during restart
# Load balancer redirects traffic to other instances
```

---

## 🔧 Configuration Files

### pki_config.yaml

```yaml
# Global PKI Server Configuration
pki_server:
  host: 0.0.0.0
  port: 8443
  ssl_enabled: true
  ssl_cert: ./pki_server_cert.pem
  ssl_key: ./pki_server_key.pem
  database: ./database/pki_server.db

root_ca:
  cert_file: ./root_ca.pem
  key_file: ./root_ca_key.pem  # ENCRYPTED
  key_encryption: aes256
  validity_years: 10
  organization: VCC Framework
  country: DE
  state: Bavaria
  locality: Munich

intermediate_ca:
  cert_file: ./intermediate_ca.pem
  key_file: ./intermediate_ca_key.pem  # ENCRYPTED
  key_encryption: aes256
  validity_years: 5
  auto_renew: true
  renew_before_months: 6

service_certificates:
  default_validity_days: 365
  default_key_size: 2048
  auto_renew_enabled: true
  renew_before_days: 30
  max_certificates_per_service: 5

security:
  rate_limit_certs_per_hour: 100
  require_mtls_for_api: true
  audit_logging_enabled: true
  crl_update_interval_hours: 6

rotation:
  check_interval_hours: 6
  notification_days: [30, 7, 1]
  max_retries: 3
  retry_delay_hours: 1
```

### service_whitelist.yaml

```yaml
# Allowed services (whitelist)
services:
  - service_id: veritas-backend
    max_certificates: 3
    allowed_operations: [request, renew, revoke, download]
    
  - service_id: veritas-frontend
    max_certificates: 3
    allowed_operations: [request, renew, revoke, download]
    
  - service_id: covina-backend
    max_certificates: 3
    allowed_operations: [request, renew, revoke, download]
    
  - service_id: covina-ingestion
    max_certificates: 5
    allowed_operations: [request, renew, revoke, download]
    
  - service_id: vpb-backend
    max_certificates: 3
    allowed_operations: [request, renew, revoke, download]
    
  - service_id: clara-backend
    max_certificates: 3
    allowed_operations: [request, renew, revoke, download]
    
  - service_id: monitoring-service
    max_certificates: 1
    allowed_operations: [request, renew, download]
    
  - service_id: admin-cli
    max_certificates: 1
    allowed_operations: [request, renew, revoke, download, admin]

# Wildcard patterns
patterns:
  - pattern: "test-*"
    max_certificates: 1
    allowed_operations: [request, renew, revoke]
```

---

## 📈 Performance Targets

### Certificate Operations
- **Request Certificate:** <500ms (including CSR signing)
- **Renew Certificate:** <300ms (CSR already validated)
- **Revoke Certificate:** <100ms (update CRL)
- **Download Certificate:** <50ms (static file)

### API Throughput
- **Concurrent Requests:** 100+ (per PKI Server instance)
- **Certificates/Hour:** 1000+ (rate-limited)
- **Database Queries:** <10ms (SQLite with indexes)

### Availability
- **Single Server:** 99.9% (8.76 hours downtime/year)
- **HA Cluster:** 99.99% (52 minutes downtime/year)
- **Multi-Region:** 99.999% (5 minutes downtime/year)

---

## 🎯 Rollout Plan

### Phase 1: PKI Server Implementation (Week 1-2)
- ✅ Root CA + Intermediate CA generation
- ✅ PKI Server REST API (FastAPI)
- ✅ Database schema + migrations
- ✅ Certificate management (request, renew, revoke)
- ✅ CRL generation
- ✅ Service registry
- ✅ Admin CLI tool

### Phase 2: Service Integration (Week 3-4)
- ✅ Python PKI Client library (`vcc_pki_client`)
- ✅ VERITAS Backend integration
- ✅ VERITAS Frontend integration
- ✅ Covina Backend integration
- ✅ Covina Ingestion integration
- ✅ VPB Backend integration

### Phase 3: Automation (Week 5-6)
- ✅ Automatic certificate rotation
- ✅ Health monitoring
- ✅ Webhook notifications
- ✅ Prometheus metrics
- ✅ Grafana dashboards

### Phase 4: Production Hardening (Week 7-8)
- ✅ High-availability cluster
- ✅ Load balancing
- ✅ Backup & disaster recovery
- ✅ Security audit
- ✅ Penetration testing

---

## 📚 Documentation Deliverables

1. **PKI_SERVER_ARCHITECTURE.md** (this file)
2. **PKI_API_DOCUMENTATION.md** - REST API reference
3. **SERVICE_INTEGRATION_GUIDE.md** - How to integrate services
4. **SECURITY_BEST_PRACTICES.md** - Security guidelines
5. **ADMIN_CLI_GUIDE.md** - Admin CLI tool usage
6. **TROUBLESHOOTING.md** - Common issues + solutions
7. **DEPLOYMENT_GUIDE.md** - Production deployment
8. **PKI_CLIENT_LIBRARY.md** - Python client library docs

---

## 🏆 Success Criteria

### Functionality
- ✅ Root CA + Intermediate CA operational
- ✅ REST API for certificate management
- ✅ Automatic certificate rotation
- ✅ Service discovery
- ✅ CRL generation

### Security
- ✅ mTLS required for all API calls
- ✅ Root CA private key secured (offline)
- ✅ Intermediate CA key encrypted at rest
- ✅ Audit logging for all operations
- ✅ Rate limiting + DoS protection

### Performance
- ✅ <500ms certificate issuance
- ✅ 99.9% availability
- ✅ 100+ concurrent requests
- ✅ <10ms database queries

### Integration
- ✅ All VCC services using PKI Server
- ✅ mTLS between all services
- ✅ Zero manual certificate management
- ✅ Automatic expiry notifications

---

**Status:** 🔄 Design Complete - Ready for Implementation  
**Next Step:** Create PKI Server implementation (Phase 1)  
**Estimated Time:** 2 weeks for complete system

