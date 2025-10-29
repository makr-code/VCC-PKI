# VCC PKI System - Production Deployment Guide
# Comprehensive Production Deployment für Brandenburg Government PKI

## 📋 **Deployment Overview**

Das VCC PKI System Production Deployment umfasst die vollständige Bereitstellung einer produktionsreifen Public Key Infrastructure für die Regierung Brandenburg mit Integration aller VCC-Services (Clara, Covina, Argus, Veritas, VPB).

## 🎯 **Deployment Ziele**

### **Primary Objectives**
- **Zero-Downtime Deployment** - Nahtlose Updates ohne Service-Unterbrechung
- **HSM Integration** - Hardware Security Module für Production Keys
- **Multi-Environment Support** - Development, Testing, Staging, Production, DR
- **Automated Backup & Recovery** - Comprehensive Disaster Recovery Procedures
- **Monitoring & Alerting** - Production-grade Observability

### **Business Requirements**
- **99.9% Uptime SLA** für kritische VCC-Services
- **<5 Minuten Recovery Time** bei System-Ausfällen
- **Automated Operations** - Minimaler manueller Eingriff erforderlich  
- **Compliance Ready** - GDPR, AI Act, BSI TR-03116 konform

## 🏗️ **Production Architecture**

### **Infrastructure Components**
```
┌────────────────────────────────────────────────────────────────┐
│                    VCC PKI Production Environment               │
├────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │Load Balancer│   │   Firewall  │   │   VPN Gateway       │   │
│  │  (HAProxy)  │◄─►│   (iptables)│◄─►│  (Brandenburg Gov)  │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
│         │                   │                     │            │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │  PKI API    │   │ Web Admin   │   │    Monitoring       │   │
│  │ Cluster     │   │ Interface   │   │   (Prometheus)      │   │
│  │ (4 Nodes)   │   │  (React)    │   │                     │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
│         │                   │                     │            │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │ PostgreSQL  │   │    Redis    │   │      HSM            │   │
│  │ Cluster     │   │  Cluster    │   │   (Thales nShield)  │   │
│  │ (Primary+   │   │ (4 Nodes)   │   │                     │   │
│  │  Standby)   │   │             │   │                     │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
├────────────────────────────────────────────────────────────────┤
│                      VCC Service Integration                    │
│  Clara │ Covina │ Argus │ Veritas │ VPB │ External Services   │
└────────────────────────────────────────────────────────────────┘
```

### **Network Security Architecture**
```
Internet ──► Brandenburg Gov Firewall ──► VPN Gateway ──► DMZ
                     │
                     ▼
              Internal Network (10.0.0.0/8)
                     │
                     ▼
              VCC PKI Security Zone
                     │
         ┌───────────┼───────────┐
         │           │           │
   Web Tier     API Tier    Data Tier
  (React UI)   (FastAPI)   (PostgreSQL)
         │           │           │
         └───────────┼───────────┘
                     │
              HSM Security Zone
              (Hardware Isolation)
```

## 🚀 **Deployment Process**

### **1. Pre-Deployment Preparation**

#### **Environment Setup**
```bash
# Set deployment environment
export VCC_PKI_ENVIRONMENT=production
export VCC_PKI_VERSION=v1.0.0

# Configure deployment credentials
export PROD_DB_PASSWORD="$(vault kv get -field=password secret/vcc-pki/production/database)"
export PROD_REDIS_PASSWORD="$(vault kv get -field=password secret/vcc-pki/production/redis)" 
export PROD_JWT_SECRET="$(vault kv get -field=secret secret/vcc-pki/production/jwt)"
export HSM_ROOT_CA_PIN="$(vault kv get -field=pin secret/vcc-pki/production/hsm/root)"
```

#### **Infrastructure Validation**
```bash
# Run pre-deployment checks
./production/deploy_production.py --environment production --validate-only

# Expected Output:
# ✅ Database connectivity: PASS
# ✅ HSM availability: PASS  
# ✅ VCC service connectivity: PASS
# ✅ Disk space: PASS (50GB available)
# ✅ Network configuration: PASS
# ✅ SSL certificates: PASS (expires in 180 days)
```

### **2. HSM Integration Setup**

#### **Thales nShield Configuration**
```bash
# Initialize HSM slots for production
/opt/nfast/bin/enquiry

# Expected HSM Status:
# Module #1: nShield Edge (ESN: 12345)
# State: Operational
# Slot 0: VCC_ROOT_CA (Authenticated)
# Slot 1: VCC_INTERMEDIATE_CA (Ready)
# Slot 2: VCC_TSA_SIGNING (Ready)

# Test HSM connectivity
python3 -c "from production.hsm_config import get_hsm_manager; 
manager = get_hsm_manager('thales_primary'); 
print('HSM Status:', manager.generate_hsm_report())"
```

#### **HSM Key Initialization**
```python
# Initialize Root CA Keys in HSM
from app.services.hsm_service import HSMService

hsm_service = HSMService()

# Generate Root CA Key in HSM Slot 0
root_ca_key = await hsm_service.generate_key_pair(
    slot_type=HSMSlotType.ROOT_CA,
    key_size=4096,
    key_label="VCC_ROOT_CA_2025"
)

# Generate Intermediate CA Key in HSM Slot 1  
intermediate_key = await hsm_service.generate_key_pair(
    slot_type=HSMSlotType.INTERMEDIATE_CA,
    key_size=2048,
    key_label="VCC_INTERMEDIATE_CA_2025"
)
```

### **3. Database Deployment**

#### **PostgreSQL Cluster Setup**
```bash
# Primary database setup
sudo -u postgres psql -c "CREATE DATABASE vcc_pki;"
sudo -u postgres psql -c "CREATE USER vcc_pki_user WITH ENCRYPTED PASSWORD '$PROD_DB_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE vcc_pki TO vcc_pki_user;"

# Run database migrations
cd /opt/vcc-pki
alembic upgrade head

# Verify database schema
psql -h prod-db-cluster.vcc.internal -U vcc_pki_user -d vcc_pki -c "\dt"

# Expected Tables:
# certificates, users, permissions, roles, audit_logs, 
# hsm_keys, certificate_templates, tsa_requests
```

#### **Database Backup Configuration**
```bash
# Setup automated backups
cat > /etc/cron.d/vcc-pki-backup << EOF
# VCC PKI Database Backup
0 1,13 * * * postgres /opt/vcc-pki/scripts/backup_database.sh
EOF

# Test backup procedure
sudo -u postgres /opt/vcc-pki/scripts/backup_database.sh

# Verify backup
ls -la /var/backups/vcc-pki/database/
# Expected: database_backup_20251002_010000.sql.gz
```

### **4. Application Deployment**

#### **Automated Deployment Script**
```bash
# Full production deployment
./production/deploy_production.py \
    --environment production \
    --backup-before-deploy \
    --validate-all

# Deployment Steps:
# 1. Pre-deployment validation ✅
# 2. Create backup ✅ 
# 3. Stop services ✅
# 4. Deploy application ✅
# 5. Update database ✅
# 6. Configure HSM ✅
# 7. Start services ✅
# 8. Health checks ✅
# 9. Initialize data ✅
# 10. Configure monitoring ✅

# Deployment Result:
# 🎉 VCC PKI Production Deployment Successful!
# Deployment ID: deploy_20251002_140000
# Duration: 12.5 minutes
# Backup ID: pre_deploy_20251002_140000
```

#### **Service Configuration**
```bash
# Systemd service files
sudo systemctl enable vcc-pki-api
sudo systemctl enable vcc-pki-worker  
sudo systemctl enable vcc-pki-scheduler

# Start services in order
sudo systemctl start postgresql
sudo systemctl start redis-server
sudo systemctl start vcc-pki-worker
sudo systemctl start vcc-pki-api
sudo systemctl start vcc-pki-scheduler
sudo systemctl start nginx

# Verify service status
systemctl status vcc-pki-*

# Expected: All services active (running)
```

### **5. Load Balancer & Reverse Proxy Setup**

#### **HAProxy Configuration**
```haproxy
# /etc/haproxy/haproxy.cfg
global
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    log global
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend vcc_pki_frontend
    bind *:443 ssl crt /etc/ssl/certs/vcc-pki-production.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options DENY
    
    default_backend vcc_pki_backend

backend vcc_pki_backend
    balance roundrobin
    option httpchk GET /health
    
    server pki1 prod-pki-1.vcc.internal:8000 check
    server pki2 prod-pki-2.vcc.internal:8000 check  
    server pki3 prod-pki-3.vcc.internal:8000 check
    server pki4 prod-pki-4.vcc.internal:8000 check
```

#### **Nginx Reverse Proxy** 
```nginx
# /etc/nginx/sites-available/vcc-pki-production
server {
    listen 443 ssl http2;
    server_name pki.vcc.brandenburg.de;

    ssl_certificate /etc/ssl/certs/vcc-pki-production.crt;
    ssl_certificate_key /etc/ssl/private/vcc-pki-production.key;
    
    # SSL Security Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # API Proxy
    location /api/ {
        proxy_pass http://localhost:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting
        limit_req zone=api burst=10 nodelay;
    }
    
    # Admin Interface
    location / {
        proxy_pass http://localhost:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### **6. Monitoring & Alerting Setup**

#### **Prometheus Configuration**
```yaml
# /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/rules/vcc-pki-alerts.yml"

scrape_configs:
  - job_name: 'vcc-pki-api'
    static_configs:
      - targets: 
        - 'prod-pki-1.vcc.internal:9090'
        - 'prod-pki-2.vcc.internal:9090' 
        - 'prod-pki-3.vcc.internal:9090'
        - 'prod-pki-4.vcc.internal:9090'
    
  - job_name: 'vcc-pki-hsm'
    static_configs:
      - targets: ['hsm-monitor.vcc.internal:9091']
        
  - job_name: 'vcc-pki-database'
    static_configs:
      - targets: ['prod-db-cluster.vcc.internal:9187']

alerting:
  alertmanagers:
    - static_configs:
        - targets: 
          - 'alertmanager.vcc.internal:9093'
```

#### **Alert Rules**
```yaml
# /etc/prometheus/rules/vcc-pki-alerts.yml
groups:
  - name: vcc-pki-critical
    rules:
      - alert: VCCPKIAPIDown
        expr: up{job="vcc-pki-api"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "VCC PKI API is down"
          description: "VCC PKI API instance {{ $labels.instance }} has been down for more than 1 minute"
          
      - alert: HSMNotAvailable 
        expr: hsm_availability{job="vcc-pki-hsm"} == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "HSM not available"
          description: "Hardware Security Module is not responding"
          
      - alert: CertificateExpiryWarning
        expr: certificate_expiry_days < 30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring soon"
          description: "Certificate {{ $labels.cert_id }} expires in {{ $value }} days"

      - alert: DatabaseConnectionHigh
        expr: database_active_connections > 80
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High database connection usage"
          description: "Database has {{ $value }} active connections"
```

### **7. Initial Data Setup**

#### **Create Root CA Certificate**
```python
# Initialize Root CA in production HSM
from app.services.certificate_service import CertificateService
from app.models.certificate_templates import VCC_CERTIFICATE_TEMPLATES

cert_service = CertificateService()

# Create Root CA Certificate
root_ca = await cert_service.create_root_ca(
    subject="CN=VCC Root CA 2025,O=Brandenburg Government,C=DE",
    validity_days=7300,  # 20 years
    key_slot="root_ca",
    hsm_protected=True
)

print(f"Root CA created: {root_ca.cert_id}")
print(f"Serial: {root_ca.serial_number}")
print(f"Expires: {root_ca.expires_at}")
```

#### **Create VCC Service Certificates**
```python
# Generate certificates for VCC services
vcc_services = ["clara", "covina", "argus", "veritas", "vpb"]

for service in vcc_services:
    service_cert = await cert_service.issue_certificate(
        subject=f"CN={service}.vcc.brandenburg.de,O=VCC,C=DE",
        cert_type="service_auth",
        validity_days=730,  # 2 years
        service_name=service
    )
    
    print(f"Service certificate created: {service} - {service_cert.cert_id}")
```

## 📊 **Post-Deployment Validation**

### **Health Check Endpoints**
```bash
# API Health Check
curl -k https://pki.vcc.brandenburg.de/api/v1/health
# Expected: {"status": "healthy", "version": "1.0.0", "timestamp": "2025-10-02T14:00:00Z"}

# Database Health
curl -k https://pki.vcc.brandenburg.de/api/v1/health/database  
# Expected: {"status": "healthy", "connection_pool": "ok", "query_time_ms": 15}

# HSM Health  
curl -k https://pki.vcc.brandenburg.de/api/v1/health/hsm
# Expected: {"status": "healthy", "slots_available": 5, "keys_loaded": 12}
```

### **Certificate Operations Test**
```bash
# Test certificate issuance
curl -X POST https://pki.vcc.brandenburg.de/api/v1/certificates \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "CN=test-certificate.vcc.internal",
    "cert_type": "service_auth",
    "validity_days": 365
  }'

# Expected: HTTP 201 Created with certificate details
```

### **Performance Benchmarks**
```bash
# Certificate issuance performance test
ab -n 100 -c 10 -H "Authorization: Bearer $JWT_TOKEN" \
   -p certificate_request.json \
   https://pki.vcc.brandenburg.de/api/v1/certificates

# Expected Results:
# Requests per second: > 50
# Mean response time: < 500ms
# 95th percentile: < 1000ms
```

## 🔒 **Security Hardening**

### **Network Security**
- **Firewall Rules** - Only essential ports open (443, 22 for admin)  
- **VPN Access** - All admin access through Brandenburg Gov VPN
- **Network Segmentation** - DMZ isolation for web tier
- **DDoS Protection** - Rate limiting and traffic analysis

### **Application Security**
- **TLS 1.3 Only** - Latest encryption standards
- **HSTS Enabled** - Force HTTPS connections
- **Security Headers** - XSS, CSRF, Content-Type protection
- **Input Validation** - Comprehensive request sanitization

### **HSM Security**
- **Dual Authentication** - Two-person control for critical operations
- **Tamper Detection** - Hardware tamper monitoring
- **Key Escrow** - Secure key backup procedures  
- **Audit Logging** - All HSM operations logged

## 📈 **Performance Optimization**

### **Database Optimization**
```sql
-- Production database tuning
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';  
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '64MB';

-- Connection pooling
ALTER SYSTEM SET max_connections = 200;
```

### **Redis Caching Configuration**
```redis
# /etc/redis/redis.conf
maxmemory 4gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10  
save 60 10000

# Cluster configuration
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 15000
```

### **Application Tuning**
```python
# FastAPI production settings
from fastapi import FastAPI
import uvicorn

app = FastAPI(
    title="VCC PKI API",
    docs_url=None,  # Disable docs in production
    redoc_url=None,
    openapi_url=None
)

# Production server configuration
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        workers=4,  # CPU cores
        access_log=False,  # Disable access logs for performance
        server_header=False,  # Security
        date_header=False
    )
```

## 🔄 **Backup & Disaster Recovery**

### **Automated Backup Schedule**
```bash
# /etc/cron.d/vcc-pki-backup
# Full backup weekly (Sunday 2 AM)  
0 2 * * 0 root /opt/vcc-pki/production/backup_full.sh

# Incremental backup daily (Monday-Saturday 2 AM)
0 2 * * 1-6 root /opt/vcc-pki/production/backup_incremental.sh

# Database backup every 6 hours
0 */6 * * * postgres /opt/vcc-pki/production/backup_database.sh

# HSM metadata backup daily
0 3 * * * root /opt/vcc-pki/production/backup_hsm_metadata.sh
```

### **Disaster Recovery Site**
```yaml
# DR site configuration
dr_site:
  location: "Brandenburg Backup Datacenter" 
  rto: "4 hours"  # Recovery Time Objective
  rpo: "1 hour"   # Recovery Point Objective
  
  infrastructure:
    - "2x Application Servers (reduced capacity)"
    - "1x Database Server (standby replica)"  
    - "1x HSM Unit (Utimaco backup)"
    - "Network connectivity to primary site"
    
  activation_triggers:
    - "Primary site unavailable > 30 minutes"
    - "Database corruption detected"
    - "HSM hardware failure"
    - "Security breach containment"
```

## 📋 **Maintenance Procedures**

### **Regular Maintenance Tasks**

#### **Weekly Tasks**
- **Certificate Expiry Review** - Check certificates expiring in next 30 days
- **HSM Health Check** - Verify all slots operational
- **Backup Verification** - Test restore from recent backup
- **Security Log Review** - Analyze audit logs for anomalies

#### **Monthly Tasks**  
- **Performance Analysis** - Review metrics and optimize
- **Capacity Planning** - Monitor resource usage trends
- **Security Updates** - Apply OS and application patches
- **DR Testing** - Validate disaster recovery procedures

#### **Quarterly Tasks**
- **Penetration Testing** - External security assessment
- **Compliance Audit** - GDPR, AI Act compliance review
- **Business Continuity Test** - Full DR site activation
- **Key Rotation Planning** - Schedule key lifecycle events

Das VCC PKI Production Deployment ist jetzt vollständig dokumentiert und bereit für den Einsatz in der Brandenburg Government Infrastructure! 🚀🔐

**Production Readiness**: ✅ **Comprehensive deployment procedures completed**