# VCC-PKI Future Technical Architecture
## Detaillierte technische Architektur für die Weiterentwicklung

**Version:** 1.0  
**Datum:** 23. November 2025  
**Status:** 📐 Technisches Architektur-Dokument

---

## 🎯 Überblick

Dieses Dokument ergänzt die [VCC-PKI Weiterentwicklungsstrategie](../VCC_PKI_WEITERENTWICKLUNGSSTRATEGIE.md) mit detaillierten technischen Spezifikationen, Architektur-Diagrammen und Implementierungs-Details.

---

## 🏗️ System-Architektur Evolution

### Current Architecture (2025)

```
┌─────────────────────────────────────────────────────┐
│              VCC-PKI Monolithic Service             │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │  CA Manager  │  │ Cert Manager │  │  REST    │ │
│  │              │  │              │  │  API     │ │
│  │ - Root CA    │  │ - Issue      │  │          │ │
│  │ - Inter. CA  │  │ - Renew      │  │ FastAPI  │ │
│  │              │  │ - Revoke     │  │          │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ Code Signing │  │   Service    │  │   CLI    │ │
│  │              │  │   Registry   │  │  Tools   │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
│                                                     │
│  ┌─────────────────────────────────────────────┐  │
│  │         SQLite Database (File-based)        │  │
│  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘

      ↓ File Storage ↓
┌─────────────────────────────────────┐
│  Local Filesystem                   │
│  - CA Keys (encrypted)              │
│  - Certificates                     │
│  - Service Registry (JSON)          │
└─────────────────────────────────────┘
```

### Target Architecture Phase 2 (Q2 2026) - Enhanced Monolith

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │   (nginx/HAProxy)│
                    └────────┬────────┘
                             │
         ┌──────────────────┼──────────────────┐
         ↓                  ↓                  ↓
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  PKI Server #1  │ │  PKI Server #2  │ │  PKI Server #3  │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│  FastAPI App    │ │  FastAPI App    │ │  FastAPI App    │
│                 │ │                 │ │                 │
│  - CA Manager   │ │  - CA Manager   │ │  - CA Manager   │
│  - Cert Manager │ │  - Cert Manager │ │  - Cert Manager │
│  - OCSP Service │ │  - OCSP Service │ │  - OCSP Service │
│  - TSA Service  │ │  - TSA Service  │ │  - TSA Service  │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         ↓                                       ↓
┌─────────────────────┐              ┌─────────────────────┐
│ PostgreSQL Cluster  │              │   Redis Cluster     │
│  (Primary/Standby)  │              │  (Session/Cache)    │
│                     │              │                     │
│  - Certificates DB  │              │  - OCSP Cache       │
│  - Audit Logs       │              │  - Rate Limiting    │
│  - Service Registry │              │  - Pub/Sub          │
└─────────────────────┘              └─────────────────────┘

         ↓ HSM Integration ↓
┌─────────────────────────────────────┐
│      Hardware Security Module       │
│    (Thales, Utimaco, SoftHSM)       │
│                                     │
│  - Root CA Private Key              │
│  - Intermediate CA Private Key      │
│  - Signing Operations               │
└─────────────────────────────────────┘
```

### Target Architecture Phase 3 (Q3 2026) - On-Premise Kubernetes Microservices

```
                    On-Premise Kubernetes Cluster
┌──────────────────────────────────────────────────────────┐
│                    Brandenburg Rechenzentrum             │
│  ┌────────────────────────────────────────────────┐     │
│  │          Ingress Controller (nginx)            │     │
│  │     cert-manager.io (Automatic Cert Mgmt)      │     │
│  └───────────────────┬────────────────────────────┘     │
│                      │                                   │
│  ┌───────────────────┴────────────────────────┐         │
│  │           API Gateway (Kong/Istio)         │         │
│  │  - Rate Limiting                           │         │
│  │  - Authentication (keine Vendor-Login)     │         │
│  │  - Request Routing                         │         │
│  └───────┬──────────────────────┬─────────────┘         │
│          │                      │                        │
│  ┌───────┴────────┐    ┌────────┴──────────┐           │
│  │  CA Service    │    │  Cert Service     │           │
│  │  (gRPC)        │    │  (gRPC)           │           │
│  │                │    │                   │           │
│  │ Pods: 3        │    │ Pods: 5           │           │
│  │ HPA: CPU>70%   │    │ HPA: CPU>70%      │           │
│  └────────┬───────┘    └────────┬──────────┘           │
│           │                     │                       │
│  ┌────────┴──────────┐  ┌───────┴────────────┐         │
│  │  OCSP Service     │  │   TSA Service      │         │
│  │  (gRPC)           │  │   (gRPC)           │         │
│  │                   │  │                    │         │
│  │ Pods: 3           │  │ Pods: 2            │         │
│  │ HPA: RPS>1000     │  │ HPA: CPU>60%       │         │
│  └────────┬──────────┘  └───────┬────────────┘         │
│           │                     │                       │
│  ┌────────┴─────────────────────┴──────────┐           │
│  │      Service Discovery Service          │           │
│  │      (Auto VCC-Service Detection)       │           │
│  │                                          │           │
│  │ Pods: 2                                  │           │
│  └──────────────────────────────────────────┘           │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Persistent Storage (Volumes)             │  │
│  │  - StatefulSets für Datenbank                    │  │
│  │  - PVCs für CA Keys (encrypted)                  │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘

On-Premise Infrastructure (Eigene RZ):
┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────┐
│ PostgreSQL (HA)     │  │   Redis (Cluster)   │  │  HSM         │
│ On-Premise          │  │   On-Premise        │  │  (Hardware)  │
└─────────────────────┘  └─────────────────────┘  └──────────────┘

Observability Stack (On-Premise):
┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────┐
│ Prometheus          │  │   Grafana           │  │  Jaeger      │
│ (Metrics)           │  │   (Dashboards)      │  │  (Tracing)   │
└─────────────────────┘  └─────────────────────┘  └──────────────┘

Hinweis: Alle Komponenten laufen auf eigener On-Premise-Infrastruktur.
         Keine Cloud-Provider (AWS/Azure/GCP), keine Vendor-Login erforderlich.
```

---

## 📊 Datenbank-Schema Evolution

### Current Schema (SQLite)

```sql
-- Simplified Current Schema
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    serial_number TEXT UNIQUE NOT NULL,
    common_name TEXT NOT NULL,
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    status TEXT CHECK(status IN ('valid', 'revoked', 'expired')),
    certificate_pem TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE service_registry (
    service_id TEXT PRIMARY KEY,
    service_name TEXT,
    endpoints JSON,
    last_seen TIMESTAMP,
    status TEXT
);
```

### Target Schema (PostgreSQL) - Phase 2

```sql
-- Enhanced Schema with Multi-Tenant Support

-- Organizations Table (Multi-Tenant)
CREATE TABLE organizations (
    org_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_name VARCHAR(255) NOT NULL UNIQUE,
    org_slug VARCHAR(100) NOT NULL UNIQUE,
    root_ca_id UUID REFERENCES certificate_authorities(ca_id),
    tenant_config JSONB DEFAULT '{}',
    isolation_level VARCHAR(50) CHECK (isolation_level IN ('strict', 'collaborative', 'federated')),
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Certificate Authorities Table
CREATE TABLE certificate_authorities (
    ca_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(org_id),
    ca_type VARCHAR(50) CHECK (ca_type IN ('root', 'intermediate', 'issuing')),
    parent_ca_id UUID REFERENCES certificate_authorities(ca_id),
    subject_dn VARCHAR(500) NOT NULL,
    serial_number VARCHAR(100) UNIQUE NOT NULL,
    certificate_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    key_algorithm VARCHAR(50) NOT NULL, -- 'RSA', 'ECDSA'
    key_size INTEGER,
    hsm_key_id VARCHAR(255), -- For HSM-stored keys
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    crl_distribution_points TEXT[],
    ocsp_responder_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_key_size CHECK (
        (key_algorithm = 'RSA' AND key_size >= 2048) OR
        (key_algorithm = 'ECDSA' AND key_size IN (256, 384, 521))
    )
);

-- Certificates Table (Enhanced)
CREATE TABLE certificates (
    cert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuing_ca_id UUID NOT NULL REFERENCES certificate_authorities(ca_id),
    org_id UUID NOT NULL REFERENCES organizations(org_id),
    service_id UUID REFERENCES vcc_services(service_id),
    
    serial_number VARCHAR(100) UNIQUE NOT NULL,
    subject_dn VARCHAR(500) NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    
    certificate_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    key_algorithm VARCHAR(50) NOT NULL,
    key_size INTEGER,
    
    purpose VARCHAR(100) CHECK (purpose IN (
        'vcc_service', 'mtls_service', 'code_signing', 
        'admin', 'external_integration', 'timestamp_authority'
    )),
    
    -- Subject Alternative Names
    san_dns TEXT[],
    san_ip INET[],
    san_email TEXT[],
    
    -- Validity
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    
    -- Status
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN (
        'active', 'revoked', 'expired', 'suspended'
    )),
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(100),
    
    -- Auto-Renewal
    auto_renewal BOOLEAN DEFAULT TRUE,
    renewal_threshold_days INTEGER DEFAULT 30,
    last_renewal_attempt TIMESTAMP,
    renewal_count INTEGER DEFAULT 0,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    tags TEXT[],
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_dates CHECK (not_after > not_before)
);

-- VCC Services Table (Service Discovery)
CREATE TABLE vcc_services (
    service_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(org_id),
    service_name VARCHAR(255) NOT NULL,
    service_slug VARCHAR(100) NOT NULL,
    service_type VARCHAR(100) CHECK (service_type IN (
        'api', 'orchestrator', 'processor', 'ui', 'gateway'
    )),
    
    -- Endpoints
    endpoints JSONB NOT NULL DEFAULT '[]',
    health_check_url VARCHAR(500),
    
    -- Certificate Binding
    active_cert_id UUID REFERENCES certificates(cert_id),
    
    -- Service Discovery
    discovery_method VARCHAR(50), -- 'manual', 'auto_scan', 'dns', 'k8s'
    last_discovered TIMESTAMP,
    last_health_check TIMESTAMP,
    health_status VARCHAR(50) DEFAULT 'unknown',
    
    -- Service Metadata
    version VARCHAR(50),
    environment VARCHAR(50) DEFAULT 'production',
    metadata JSONB DEFAULT '{}',
    
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(org_id, service_slug)
);

-- Certificate Revocation List Entries
CREATE TABLE crl_entries (
    crl_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id UUID NOT NULL REFERENCES certificates(cert_id),
    ca_id UUID NOT NULL REFERENCES certificate_authorities(ca_id),
    
    serial_number VARCHAR(100) NOT NULL,
    revocation_date TIMESTAMP NOT NULL,
    revocation_reason VARCHAR(100) NOT NULL CHECK (revocation_reason IN (
        'unspecified', 'key_compromise', 'ca_compromise',
        'affiliation_changed', 'superseded', 'cessation_of_operation',
        'certificate_hold', 'remove_from_crl', 'privilege_withdrawn',
        'aa_compromise'
    )),
    
    invalidity_date TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(ca_id, serial_number)
);

-- OCSP Responses Cache
CREATE TABLE ocsp_responses (
    ocsp_response_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id UUID NOT NULL REFERENCES certificates(cert_id),
    
    serial_number VARCHAR(100) NOT NULL,
    cert_status VARCHAR(50) NOT NULL CHECK (cert_status IN ('good', 'revoked', 'unknown')),
    
    response_data BYTEA NOT NULL, -- DER-encoded OCSP response
    this_update TIMESTAMP NOT NULL,
    next_update TIMESTAMP NOT NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(serial_number)
);

-- Code Signatures (VCC-specific)
CREATE TABLE vcc_code_signatures (
    signature_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id UUID NOT NULL REFERENCES certificates(cert_id),
    service_id UUID REFERENCES vcc_services(service_id),
    org_id UUID NOT NULL REFERENCES organizations(org_id),
    
    artifact_type VARCHAR(100) CHECK (artifact_type IN (
        'python_package', 'lora_adapter', 'pipeline_config', 
        'ui_bundle', 'docker_image', 'helm_chart'
    )),
    
    artifact_path VARCHAR(1000) NOT NULL,
    artifact_hash VARCHAR(128) NOT NULL, -- SHA-256/SHA-512
    hash_algorithm VARCHAR(50) DEFAULT 'sha256',
    
    signature_data BYTEA NOT NULL,
    signature_algorithm VARCHAR(100) NOT NULL,
    
    timestamp_token BYTEA, -- RFC 3161 Timestamp
    timestamp_authority_id UUID REFERENCES certificate_authorities(ca_id),
    
    vcc_metadata JSONB DEFAULT '{}',
    
    signed_at TIMESTAMP NOT NULL,
    verified_count INTEGER DEFAULT 0,
    last_verified_at TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(artifact_hash, cert_id)
);

-- Certificate Templates
CREATE TABLE certificate_templates (
    template_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(org_id),
    
    template_name VARCHAR(255) NOT NULL,
    template_slug VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Template Configuration
    purpose VARCHAR(100) NOT NULL,
    key_algorithm VARCHAR(50) NOT NULL,
    key_size INTEGER NOT NULL,
    validity_days INTEGER NOT NULL,
    
    auto_renewal BOOLEAN DEFAULT TRUE,
    renewal_threshold_days INTEGER DEFAULT 30,
    
    -- Certificate Extensions (JSONB for flexibility)
    extensions JSONB NOT NULL DEFAULT '{}',
    -- Example:
    -- {
    --   "keyUsage": ["digitalSignature", "keyEncipherment"],
    --   "extKeyUsage": ["serverAuth", "clientAuth"],
    --   "subjectAltName": {"dns": ["${service_name}.vcc.local"]}
    -- }
    
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(org_id, template_slug)
);

-- Audit Log (Immutable)
CREATE TABLE audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(org_id),
    
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) CHECK (event_category IN (
        'certificate', 'ca', 'service', 'authentication', 
        'authorization', 'configuration', 'compliance'
    )),
    
    actor_type VARCHAR(50) CHECK (actor_type IN ('user', 'service', 'system', 'api')),
    actor_id VARCHAR(255),
    actor_ip INET,
    
    resource_type VARCHAR(100),
    resource_id UUID,
    
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) CHECK (status IN ('success', 'failure', 'pending')),
    
    event_data JSONB DEFAULT '{}',
    error_message TEXT,
    
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Blockchain-inspired audit chain
    previous_audit_hash VARCHAR(128),
    audit_hash VARCHAR(128) GENERATED ALWAYS AS (
        encode(digest(
            audit_id::text || timestamp::text || event_type || action,
            'sha256'
        ), 'hex')
    ) STORED
);

-- Compliance Reports
CREATE TABLE compliance_reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(org_id),
    
    report_type VARCHAR(100) CHECK (report_type IN (
        'dsgvo_art30', 'eu_ai_act', 'bsi_grundschutz', 
        'soc2', 'iso27001', 'certificate_lifecycle'
    )),
    
    report_period_start DATE NOT NULL,
    report_period_end DATE NOT NULL,
    
    report_data JSONB NOT NULL,
    report_status VARCHAR(50) DEFAULT 'generated',
    
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    generated_by VARCHAR(255),
    
    file_path VARCHAR(1000), -- For PDF/HTML exports
    
    UNIQUE(org_id, report_type, report_period_start, report_period_end)
);

-- Indexes for Performance
CREATE INDEX idx_certificates_org_id ON certificates(org_id);
CREATE INDEX idx_certificates_service_id ON certificates(service_id);
CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);
CREATE INDEX idx_certificates_serial_number ON certificates(serial_number);

CREATE INDEX idx_vcc_services_org_id ON vcc_services(org_id);
CREATE INDEX idx_vcc_services_status ON vcc_services(status);
CREATE INDEX idx_vcc_services_health_status ON vcc_services(health_status);

CREATE INDEX idx_audit_log_org_id ON audit_log(org_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_resource_id ON audit_log(resource_id);

CREATE INDEX idx_crl_entries_ca_id ON crl_entries(ca_id);
CREATE INDEX idx_crl_entries_serial_number ON crl_entries(serial_number);

CREATE INDEX idx_ocsp_responses_serial_number ON ocsp_responses(serial_number);
CREATE INDEX idx_ocsp_responses_next_update ON ocsp_responses(next_update);

-- Partitioning for large tables (optional, for scale)
-- Partition audit_log by month
CREATE TABLE audit_log_2026_01 PARTITION OF audit_log
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
```

---

## 🔐 Security Architecture

### Authentication & Authorization Matrix

```yaml
# VCC-PKI RBAC Configuration

roles:
  pki_super_admin:
    description: "Full PKI system administration"
    permissions:
      - "ca:*"
      - "cert:*"
      - "service:*"
      - "organization:*"
      - "template:*"
      - "compliance:*"
      - "audit:read"
    
  pki_admin:
    description: "Organization PKI administrator"
    permissions:
      - "ca:read"
      - "ca:create_intermediate"
      - "cert:*"
      - "service:*"
      - "template:manage"
      - "compliance:read"
      - "audit:read_own_org"
    scope: "organization"
    
  cert_manager:
    description: "Certificate lifecycle management"
    permissions:
      - "cert:request"
      - "cert:renew"
      - "cert:revoke"
      - "cert:read"
      - "service:read"
      - "template:read"
    scope: "organization"
    
  service_account:
    description: "Automated service accounts"
    permissions:
      - "cert:request_own"
      - "cert:renew_own"
      - "cert:read_own"
      - "service:register_self"
      - "service:update_self"
    scope: "service"
    
  code_signer:
    description: "Code signing operations"
    permissions:
      - "signature:create"
      - "signature:verify"
      - "cert:read"
    scope: "organization"
    
  auditor:
    description: "Read-only audit access"
    permissions:
      - "audit:read"
      - "compliance:read"
      - "cert:read"
      - "service:read"
    scope: "organization"

# Service-to-Service Authentication Matrix
service_communication_policies:
  argus:
    can_call: [covina, clara, vpb]
    auth_method: mtls_certificate
    required_cert_purpose: vcc_service
    
  covina:
    can_call: [clara, veritas, "*_database"]
    auth_method: mtls_certificate
    required_cert_purpose: vcc_service
    special_permissions: [uds3_backend, registry_management]
    
  clara:
    can_call: [covina]
    auth_method: mtls_certificate
    required_cert_purpose: vcc_service
    isolation_level: high
    
  veritas:
    can_call: [covina, clara, "*_ingestion"]
    auth_method: mtls_certificate
    required_cert_purpose: vcc_service
    
  vpb:
    can_call: [argus, covina]
    auth_method: mtls_certificate
    required_cert_purpose: vcc_service
```

### HSM Integration Architecture

```python
# PKCS#11 HSM Integration

from pkcs11 import lib, KeyType, ObjectClass, Mechanism
from pkcs11.mechanisms import KeyCapability

class HSMCryptoProvider:
    """HSM-based cryptographic operations for CA keys"""
    
    def __init__(self, hsm_module_path: str, hsm_slot: int, hsm_pin: str):
        self.lib = lib(hsm_module_path)
        self.slot = self.lib.get_slots()[hsm_slot]
        self.session = self.slot.open(user_pin=hsm_pin)
        
    def generate_ca_keypair(
        self,
        key_label: str,
        key_size: int = 4096,
        key_type: KeyType = KeyType.RSA
    ) -> tuple:
        """Generate CA key pair in HSM"""
        
        public_key, private_key = self.session.generate_keypair(
            KeyType.RSA,
            key_size,
            label=key_label,
            store=True,
            capabilities=KeyCapability.SIGN | KeyCapability.VERIFY
        )
        
        return public_key, private_key
    
    def sign_certificate(
        self,
        private_key_label: str,
        data_to_sign: bytes,
        mechanism: Mechanism = Mechanism.SHA256_RSA_PKCS
    ) -> bytes:
        """Sign certificate using HSM private key"""
        
        private_key = self.session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label=private_key_label
        )
        
        signature = private_key.sign(data_to_sign, mechanism=mechanism)
        return signature
    
    def backup_key(self, key_label: str, backup_slot: int):
        """Backup HSM key to another HSM slot (for DR)"""
        # Implementation depends on HSM vendor
        pass

# Usage in CA Manager
class CAManager:
    def __init__(self, hsm_provider: HSMCryptoProvider):
        self.hsm = hsm_provider
        
    async def create_root_ca(
        self,
        subject_dn: str,
        validity_days: int = 3650
    ) -> Certificate:
        """Create Root CA with HSM-backed private key"""
        
        # Generate key pair in HSM
        public_key, private_key = self.hsm.generate_ca_keypair(
            key_label="vcc_root_ca_2026",
            key_size=4096
        )
        
        # Build certificate
        cert_builder = x509.CertificateBuilder()
        # ... configure certificate ...
        
        # Sign with HSM private key
        cert_der = cert_builder.public_bytes(serialization.Encoding.DER)
        signature = self.hsm.sign_certificate(
            private_key_label="vcc_root_ca_2026",
            data_to_sign=cert_der
        )
        
        return certificate
```

---

## 🚀 Kubernetes Deployment Architecture

### Helm Chart Structure

```
vcc-pki/
├── Chart.yaml
├── values.yaml
├── values-production.yaml
├── values-staging.yaml
├── templates/
│   ├── deployment-api.yaml
│   ├── deployment-ca-service.yaml
│   ├── deployment-cert-service.yaml
│   ├── deployment-ocsp.yaml
│   ├── deployment-tsa.yaml
│   ├── service-api.yaml
│   ├── service-ca.yaml
│   ├── service-cert.yaml
│   ├── service-ocsp.yaml
│   ├── service-tsa.yaml
│   ├── ingress.yaml
│   ├── hpa-api.yaml
│   ├── hpa-cert.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── pvc-ca-keys.yaml
│   ├── pvc-certificates.yaml
│   ├── servicemonitor.yaml
│   └── networkpolicy.yaml
└── charts/
    ├── postgresql/
    └── redis/
```

### Example Deployment YAML

```yaml
# templates/deployment-api.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "vcc-pki.fullname" . }}-api
  labels:
    {{- include "vcc-pki.labels" . | nindent 4 }}
    component: api
spec:
  replicas: {{ .Values.api.replicas }}
  selector:
    matchLabels:
      {{- include "vcc-pki.selectorLabels" . | nindent 6 }}
      component: api
  template:
    metadata:
      annotations:
        checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
      labels:
        {{- include "vcc-pki.selectorLabels" . | nindent 8 }}
        component: api
    spec:
      serviceAccountName: {{ include "vcc-pki.serviceAccountName" . }}
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: api
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        ports:
        - name: https
          containerPort: 8443
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: {{ include "vcc-pki.fullname" . }}-db
              key: url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: {{ include "vcc-pki.fullname" . }}-redis
              key: url
        - name: HSM_MODULE_PATH
          value: {{ .Values.hsm.modulePath }}
        - name: HSM_SLOT
          value: "{{ .Values.hsm.slot }}"
        - name: HSM_PIN
          valueFrom:
            secretKeyRef:
              name: {{ include "vcc-pki.fullname" . }}-hsm
              key: pin
        livenessProbe:
          httpGet:
            path: /health
            port: https
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: https
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          {{- toYaml .Values.api.resources | nindent 12 }}
        volumeMounts:
        - name: ca-keys
          mountPath: /app/ca_storage
          readOnly: true
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: ca-keys
        persistentVolumeClaim:
          claimName: {{ include "vcc-pki.fullname" . }}-ca-keys
      - name: config
        configMap:
          name: {{ include "vcc-pki.fullname" . }}-config
      - name: tmp
        emptyDir: {}
```

### HPA Configuration

```yaml
# templates/hpa-api.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "vcc-pki.fullname" . }}-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "vcc-pki.fullname" . }}-api
  minReplicas: {{ .Values.api.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.api.autoscaling.maxReplicas }}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: {{ .Values.api.autoscaling.targetCPUUtilizationPercentage }}
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: {{ .Values.api.autoscaling.targetMemoryUtilizationPercentage }}
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

---

## 📊 Monitoring & Observability

### Prometheus Metrics

```python
from prometheus_client import Counter, Gauge, Histogram, Info

# Certificate Metrics
CERT_REQUESTS_TOTAL = Counter(
    'pki_cert_requests_total',
    'Total certificate requests',
    ['org_id', 'purpose', 'status']
)

CERT_ISSUANCE_DURATION = Histogram(
    'pki_cert_issuance_duration_seconds',
    'Certificate issuance duration',
    ['org_id', 'purpose'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
)

CERT_EXPIRY_DAYS = Gauge(
    'pki_cert_expiry_days',
    'Days until certificate expiry',
    ['cert_id', 'service_id', 'common_name']
)

ACTIVE_CERTIFICATES = Gauge(
    'pki_active_certificates',
    'Number of active certificates',
    ['org_id', 'purpose']
)

# CA Metrics
CA_SIGNING_OPERATIONS = Counter(
    'pki_ca_signing_operations_total',
    'Total CA signing operations',
    ['ca_id', 'operation_type', 'status']
)

CA_KEY_USAGE = Counter(
    'pki_ca_key_usage_total',
    'CA key usage counter',
    ['ca_id', 'hsm_backed']
)

# OCSP Metrics
OCSP_REQUESTS_TOTAL = Counter(
    'pki_ocsp_requests_total',
    'Total OCSP requests',
    ['status']
)

OCSP_CACHE_HITS = Counter(
    'pki_ocsp_cache_hits_total',
    'OCSP cache hits'
)

OCSP_RESPONSE_TIME = Histogram(
    'pki_ocsp_response_duration_seconds',
    'OCSP response time',
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
)

# Service Discovery Metrics
VCC_SERVICES_DISCOVERED = Gauge(
    'pki_vcc_services_discovered',
    'Number of VCC services discovered',
    ['org_id', 'service_type', 'status']
)

# Auto-Renewal Metrics
AUTO_RENEWAL_ATTEMPTS = Counter(
    'pki_auto_renewal_attempts_total',
    'Auto-renewal attempts',
    ['service_id', 'status']
)

# System Metrics
PKI_INFO = Info('pki_system', 'PKI system information')
PKI_INFO.info({
    'version': '2.0.0',
    'deployment': 'kubernetes',
    'hsm_enabled': 'true'
})
```

### Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "VCC-PKI Overview",
    "panels": [
      {
        "title": "Certificate Expiry Timeline",
        "type": "graph",
        "targets": [
          {
            "expr": "pki_cert_expiry_days",
            "legendFormat": "{{common_name}}"
          }
        ],
        "alert": {
          "conditions": [
            {
              "evaluator": {"params": [30], "type": "lt"},
              "query": {"params": ["A", "5m", "now"]},
              "type": "query"
            }
          ]
        }
      },
      {
        "title": "Certificate Issuance Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(pki_cert_requests_total[5m])",
            "legendFormat": "{{org_id}} - {{purpose}}"
          }
        ]
      },
      {
        "title": "OCSP Response Time (p95)",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, pki_ocsp_response_duration_seconds_bucket)",
            "legendFormat": "p95"
          }
        ]
      },
      {
        "title": "Active Certificates by Purpose",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by(purpose) (pki_active_certificates)"
          }
        ]
      }
    ]
  }
}
```

---

## 🔄 CI/CD Pipeline

### GitOps with ArgoCD

```yaml
# argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: vcc-pki
  namespace: argocd
spec:
  project: vcc-infrastructure
  
  source:
    repoURL: https://github.com/makr-code/VCC-PKI
    targetRevision: main
    path: helm/vcc-pki
    helm:
      valueFiles:
        - values-production.yaml
      parameters:
        - name: image.tag
          value: "2.0.0"
        - name: api.replicas
          value: "3"
  
  destination:
    server: https://kubernetes.default.svc
    namespace: vcc-pki
  
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

### GitHub Actions CI Pipeline

```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Run tests
        run: pytest --cov=src --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Snyk Security Scan
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'

  build:
    needs: [test, security-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: |
          docker build -t ghcr.io/makr-code/vcc-pki:${{ github.sha }} .
      
      - name: Push to GitHub Container Registry
        if: github.ref == 'refs/heads/main'
        run: |
          echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker push ghcr.io/makr-code/vcc-pki:${{ github.sha }}
          docker tag ghcr.io/makr-code/vcc-pki:${{ github.sha }} ghcr.io/makr-code/vcc-pki:latest
          docker push ghcr.io/makr-code/vcc-pki:latest

  deploy:
    needs: build
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Update ArgoCD Image Tag
        run: |
          # Update Helm values or kustomize overlay
          # ArgoCD will automatically sync
```

---

## 🧪 Testing Strategy

### Test Pyramid

```
         ┌─────────────┐
         │   E2E Tests │  (10%)
         │  - Full PKI │
         │  - Multi-Org│
         └─────────────┘
       ┌─────────────────┐
       │Integration Tests│  (30%)
       │  - API Tests    │
       │  - DB Tests     │
       │  - HSM Tests    │
       └─────────────────┘
   ┌───────────────────────┐
   │     Unit Tests        │  (60%)
   │  - Crypto Functions   │
   │  - Business Logic     │
   │  - Utilities          │
   └───────────────────────┘
```

### Example Test Cases

```python
# tests/integration/test_certificate_lifecycle.py

import pytest
from vcc_pki import PKIServer, CAManager, CertificateManager

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_certificate_lifecycle():
    """Test complete certificate lifecycle"""
    
    # Setup
    pki = PKIServer(config=test_config)
    ca_manager = pki.ca_manager
    cert_manager = pki.cert_manager
    
    # 1. Create Root CA
    root_ca = await ca_manager.create_root_ca(
        subject_dn="CN=VCC Root CA Test,O=VCC,C=DE"
    )
    assert root_ca.is_ca
    assert root_ca.key_size == 4096
    
    # 2. Create Intermediate CA
    inter_ca = await ca_manager.create_intermediate_ca(
        parent_ca=root_ca,
        subject_dn="CN=VCC Intermediate CA Test,O=VCC,C=DE"
    )
    assert inter_ca.issuer == root_ca.subject
    
    # 3. Issue Service Certificate
    cert = await cert_manager.issue_certificate(
        issuing_ca=inter_ca,
        service_id="test-service",
        common_name="test-service.vcc.local",
        san_dns=["test-service", "localhost"],
        validity_days=365
    )
    assert cert.issuer == inter_ca.subject
    assert "test-service.vcc.local" in cert.san_dns
    
    # 4. Auto-Renewal
    # Fast-forward to renewal threshold
    await cert_manager.check_renewal_needed(cert.id)
    renewed_cert = await cert_manager.renew_certificate(cert.id)
    assert renewed_cert.serial_number != cert.serial_number
    assert renewed_cert.subject == cert.subject
    
    # 5. Revocation
    await cert_manager.revoke_certificate(
        cert_id=renewed_cert.id,
        reason="test_revocation"
    )
    status = await cert_manager.get_certificate_status(renewed_cert.id)
    assert status == "revoked"
    
    # 6. OCSP Check
    ocsp_response = await pki.ocsp_service.check_status(renewed_cert.serial_number)
    assert ocsp_response.status == "revoked"

@pytest.mark.integration
@pytest.mark.hsm
async def test_hsm_signing():
    """Test HSM-backed certificate signing"""
    
    hsm = HSMCryptoProvider(
        hsm_module_path="/usr/lib/softhsm/libsofthsm2.so",
        hsm_slot=0,
        hsm_pin="1234"
    )
    
    # Generate key in HSM
    pub_key, priv_key = hsm.generate_ca_keypair(
        key_label="test_ca_key",
        key_size=4096
    )
    
    # Sign certificate
    cert_data = b"test certificate data"
    signature = hsm.sign_certificate(
        private_key_label="test_ca_key",
        data_to_sign=cert_data
    )
    
    assert len(signature) == 512  # 4096-bit RSA signature
    
@pytest.mark.e2e
@pytest.mark.slow
async def test_multi_org_isolation():
    """Test multi-tenant organization isolation"""
    
    pki = PKIServer(config=test_config)
    
    # Create two organizations
    org1 = await pki.create_organization(
        org_name="Brandenburg",
        isolation_level="strict"
    )
    org2 = await pki.create_organization(
        org_name="Bayern",
        isolation_level="strict"
    )
    
    # Issue certificates for both orgs
    cert1 = await pki.issue_certificate(
        org_id=org1.id,
        service_id="service-bb",
        common_name="service.brandenburg.de"
    )
    cert2 = await pki.issue_certificate(
        org_id=org2.id,
        service_id="service-by",
        common_name="service.bayern.de"
    )
    
    # Verify isolation
    # Service from org1 should not see org2's certificates
    with pytest.raises(PermissionError):
        await pki.get_certificate(
            org_id=org1.id,
            cert_id=cert2.id
        )
```

---

## 📖 Summary

Dieses Dokument definiert die technische Architektur für die Weiterentwicklung von VCC-PKI mit:

- **On-Premise First**: Primäres Deployment auf eigener Infrastruktur (Brandenburg RZ)
- **Vendor-Unabhängigkeit**: Keine externen Authentifizierungs- oder CA-Services erforderlich
- **Moderne Datenbank-Architektur** mit PostgreSQL, Multi-Tenant Support (on-premise)
- **Kubernetes Deployment** auf eigener On-Premise-Infrastruktur mit Helm
- **HSM-Integration** für höchste Schlüsselsicherheit (on-premise HSM)
- **Umfassende Observability** mit Prometheus, Grafana, OpenTelemetry (on-premise)
- **Skalierbare Microservices-Architektur** für zukünftiges Wachstum
- **Robuste CI/CD-Pipeline** mit GitOps und automatisierten Tests

Die Architektur ist designed für:
- ✅ 99.99% Verfügbarkeit (on-premise)
- ✅ Horizontale Skalierung (on-premise)
- ✅ Multi-Tenant/Multi-Organization Support
- ✅ Enterprise-Grade Security
- ✅ Compliance-Readiness (DSGVO, EU AI Act, BSI)
- ✅ Digitale Souveränität (vollständige Kontrolle)

---

*Letzte Aktualisierung: 23. November 2025*
