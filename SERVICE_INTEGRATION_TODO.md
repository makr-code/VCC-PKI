# VCC PKI Service Integration - Todo List

**Status:** 🎯 **READY TO START**  
**PKI Server:** ✅ 100% Complete  
**Client Library:** ✅ Ready (`vcc-pki-client`)  
**Admin CLI:** ✅ Ready (`pki_admin_cli.py`)  
**Date:** 13. Oktober 2025

---

## 📋 Service Integration Roadmap

### Overview

| System | Backend | Frontend | Priority | Est. Time | Status |
|--------|---------|----------|----------|-----------|--------|
| **VERITAS** | Backend API | LiveView GUI | 🔴 HIGH | 20 min | ⏳ Pending |
| **Covina** | Main Backend | LiveView Dashboard | 🔴 HIGH | 20 min | ⏳ Pending |
| **Covina** | Ingestion Backend | - | 🔴 HIGH | 10 min | ⏳ Pending |
| **Clara** | Backend | Frontend | 🟡 MEDIUM | 20 min | ⏳ Pending |
| **VPB** | Backend | Frontend | 🟡 MEDIUM | 20 min | ⏳ Pending |
| **Argus** | Backend | Frontend | 🟢 LOW | 20 min | ⏳ Pending |
| **PKI Server** | Self-signed → PKI | - | 🟡 MEDIUM | 10 min | ⏳ Pending |

**Total Estimated Time:** ~2.5 hours for all systems

---

## 🎯 Integration Tasks

---

### 1. VERITAS System Integration

**Priority:** 🔴 **HIGH** (Critical system)  
**Estimated Time:** 20 minutes (Backend + Frontend)

#### Backend Integration (10 minutes)

**File:** `C:\VCC\veritas\backend\api\main_mtls.py` (or create new)

**Tasks:**
- [ ] Install PKI Client Library
  ```powershell
  cd C:\VCC\veritas
  pip install C:\VCC\PKI\client
  ```

- [ ] Import PKI Client
  ```python
  from vcc_pki_client import PKIClient
  import os
  ```

- [ ] Initialize PKI Client
  ```python
  pki = PKIClient(
      pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
      service_id="veritas-backend",
      ca_password=os.getenv("VCC_CA_PASSWORD")
  )
  ```

- [ ] Add Startup Handler
  ```python
  @app.on_event("startup")
  async def startup():
      # Request certificate (first time only)
      try:
          cert_info = pki.get_certificate_info()
          print(f"Certificate found, expires in {cert_info['days_until_expiry']} days")
      except:
          print("Requesting new certificate...")
          pki.request_certificate(
              common_name="veritas-backend.vcc.local",
              san_dns=["veritas-backend", "localhost"],
              san_ip=["127.0.0.1"]
          )
      
      # Register service
      pki.register_service(
          service_name="VERITAS Backend API",
          endpoints=["https://veritas-backend.vcc.local:8001"],
          health_check_url="https://veritas-backend.vcc.local:8001/health",
          metadata={"version": "1.0.0", "environment": "production"}
      )
      
      # Enable auto-renewal
      pki.enable_auto_renewal()
  ```

- [ ] Add Shutdown Handler
  ```python
  @app.on_event("shutdown")
  async def shutdown():
      pki.disable_auto_renewal()
  ```

- [ ] Update uvicorn.run() for HTTPS
  ```python
  if __name__ == "__main__":
      ssl_context = pki.get_ssl_context(client_auth=False)
      
      uvicorn.run(
          app,
          host="0.0.0.0",
          port=8001,
          ssl_context=ssl_context
      )
  ```

- [ ] Add Environment Variables (`.env`)
  ```bash
  PKI_SERVER_URL=https://localhost:8443
  VCC_CA_PASSWORD=your-ca-password
  ```

#### Frontend Integration (10 minutes)

**File:** `C:\VCC\veritas\frontend\main.py` (or relevant GUI file)

**Tasks:**
- [ ] Update API Client URLs to HTTPS
  ```python
  # Before: http://localhost:8001
  # After:  https://veritas-backend.vcc.local:8001
  API_BASE_URL = "https://veritas-backend.vcc.local:8001"
  ```

- [ ] Add SSL Verification (if using requests)
  ```python
  import requests
  
  # Download CA bundle from PKI server
  response = requests.get(
      "https://localhost:8443/api/ca/bundle",
      verify=False  # Only for PKI server itself
  )
  with open("ca_chain.pem", "wb") as f:
      f.write(response.content)
  
  # Use CA bundle for API requests
  session = requests.Session()
  session.verify = "ca_chain.pem"
  ```

- [ ] Or use PKI Client for Frontend (if needed)
  ```python
  from vcc_pki_client import PKIClient
  
  pki = PKIClient(
      pki_server_url="https://localhost:8443",
      service_id="veritas-frontend"
  )
  
  verify, cert = pki.get_requests_config()
  session.verify = verify
  ```

**Testing:**
- [ ] Start PKI Server
- [ ] Start VERITAS Backend (should request certificate automatically)
- [ ] Verify certificate in `pki_client/veritas-backend/`
- [ ] Test HTTPS endpoint: `https://localhost:8001/health`
- [ ] Start VERITAS Frontend (should connect via HTTPS)
- [ ] Verify end-to-end communication

**Expected Result:**
- ✅ VERITAS Backend runs with HTTPS
- ✅ Certificate auto-requested on first startup
- ✅ Auto-renewal enabled (checks every 6 hours)
- ✅ Frontend connects securely via HTTPS

---

### 2. Covina Main Backend Integration

**Priority:** 🔴 **HIGH** (Critical system)  
**Estimated Time:** 20 minutes (Backend + Frontend)

#### Backend Integration (10 minutes)

**File:** `C:\VCC\Covina\backend.py`

**Tasks:**
- [ ] Install PKI Client Library
  ```powershell
  cd C:\VCC\Covina
  pip install C:\VCC\PKI\client
  ```

- [ ] Import PKI Client (add at top of file)
  ```python
  from vcc_pki_client import PKIClient
  import os
  ```

- [ ] Initialize PKI Client (before app creation)
  ```python
  # Initialize PKI client
  pki = PKIClient(
      pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
      service_id="covina-backend",
      ca_password=os.getenv("VCC_CA_PASSWORD")
  )
  ```

- [ ] Add Startup Handler
  ```python
  @app.on_event("startup")
  async def startup():
      # Request certificate if not exists
      try:
          cert_info = pki.get_certificate_info()
          logger.info(f"Certificate expires in {cert_info['days_until_expiry']} days")
      except:
          logger.info("Requesting new certificate...")
          pki.request_certificate(
              common_name="covina-backend.vcc.local",
              san_dns=["covina-backend", "localhost"],
              san_ip=["127.0.0.1"]
          )
      
      # Register service
      pki.register_service(
          service_name="Covina Main Backend",
          endpoints=["https://covina-backend.vcc.local:45678"],
          health_check_url="https://covina-backend.vcc.local:45678/health",
          metadata={"version": "3.4.4", "type": "main-backend"}
      )
      
      # Enable auto-renewal
      pki.enable_auto_renewal()
      logger.info("PKI auto-renewal enabled")
  ```

- [ ] Add Shutdown Handler
  ```python
  @app.on_event("shutdown")
  async def shutdown():
      pki.disable_auto_renewal()
      logger.info("PKI auto-renewal disabled")
  ```

- [ ] Update uvicorn.run() (at end of file)
  ```python
  if __name__ == "__main__":
      # Get SSL context from PKI client
      ssl_context = pki.get_ssl_context(client_auth=False)
      
      uvicorn.run(
          "backend:app",
          host="0.0.0.0",
          port=45678,
          ssl_context=ssl_context,  # Add this
          log_level="info"
      )
  ```

- [ ] Add Environment Variables (`.env.production`)
  ```bash
  PKI_SERVER_URL=https://localhost:8443
  VCC_CA_PASSWORD=your-ca-password
  ```

#### Frontend Integration (10 minutes)

**File:** `C:\VCC\Covina\frontend\main.py`

**Tasks:**
- [ ] Update API Client to use HTTPS
  ```python
  # In IngestionAPIClient.__init__()
  # Before: self.base_url = "http://127.0.0.1:45678"
  # After:
  self.base_url = "https://covina-backend.vcc.local:45678"
  
  # Download CA bundle
  import urllib.request
  ca_bundle_url = "https://localhost:8443/api/ca/bundle"
  ca_bundle_path = "ca_chain.pem"
  
  ctx = ssl._create_unverified_context()
  with urllib.request.urlopen(ca_bundle_url, context=ctx) as response:
      with open(ca_bundle_path, "wb") as f:
          f.write(response.read())
  
  # Use CA bundle for requests
  self.session = requests.Session()
  self.session.verify = ca_bundle_path
  ```

- [ ] Update WebSocket Client (if applicable)
  ```python
  # In IngestionWebSocketClient
  # Before: ws://127.0.0.1:45679/ws/jobs
  # After:  wss://covina-backend.vcc.local:45679/ws/jobs
  
  ws_url = "wss://covina-backend.vcc.local:45679/ws/jobs"
  
  # Add SSL options
  sslopt = {"ca_certs": "ca_chain.pem"}
  ws = websocket.WebSocketApp(ws_url, ..., sslopt=sslopt)
  ```

**Testing:**
- [ ] Start PKI Server
- [ ] Start Covina Main Backend (should request certificate)
- [ ] Verify certificate in `pki_client/covina-backend/`
- [ ] Test HTTPS: `https://localhost:45678/health`
- [ ] Start Frontend (should connect via HTTPS)
- [ ] Test queries, DSGVO, Review Queue

**Expected Result:**
- ✅ Covina Backend runs with HTTPS (Port 45678)
- ✅ Certificate auto-requested
- ✅ Auto-renewal enabled
- ✅ Frontend connects securely

---

### 3. Covina Ingestion Backend Integration

**Priority:** 🔴 **HIGH** (Critical system)  
**Estimated Time:** 10 minutes (Backend only)

#### Backend Integration

**File:** `C:\VCC\Covina\ingestion_backend.py`

**Tasks:**
- [ ] Import PKI Client
  ```python
  from vcc_pki_client import PKIClient
  import os
  ```

- [ ] Initialize PKI Client
  ```python
  # Initialize PKI client
  pki = PKIClient(
      pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
      service_id="covina-ingestion",
      ca_password=os.getenv("VCC_CA_PASSWORD")
  )
  ```

- [ ] Add Startup Handler
  ```python
  @app.on_event("startup")
  async def startup():
      # Request certificate
      try:
          cert_info = pki.get_certificate_info()
          logger.info(f"Ingestion: Certificate expires in {cert_info['days_until_expiry']} days")
      except:
          logger.info("Ingestion: Requesting new certificate...")
          pki.request_certificate(
              common_name="covina-ingestion.vcc.local",
              san_dns=["covina-ingestion", "localhost"],
              san_ip=["127.0.0.1"]
          )
      
      # Register service
      pki.register_service(
          service_name="Covina Ingestion Backend",
          endpoints=[
              "https://covina-ingestion.vcc.local:45679",
              "wss://covina-ingestion.vcc.local:45679/ws/jobs"
          ],
          health_check_url="https://covina-ingestion.vcc.local:45679/health",
          metadata={
              "version": "3.4.4",
              "type": "ingestion-backend",
              "workers": {"io": 36, "cpu": 36}
          }
      )
      
      # Enable auto-renewal
      pki.enable_auto_renewal()
      logger.info("Ingestion: PKI auto-renewal enabled")
  ```

- [ ] Add Shutdown Handler
  ```python
  @app.on_event("shutdown")
  async def shutdown():
      pki.disable_auto_renewal()
      logger.info("Ingestion: PKI auto-renewal disabled")
  ```

- [ ] Update uvicorn.run()
  ```python
  if __name__ == "__main__":
      ssl_context = pki.get_ssl_context(client_auth=False)
      
      uvicorn.run(
          "ingestion_backend:app",
          host="0.0.0.0",
          port=45679,
          ssl_context=ssl_context,  # Add this
          log_level="info"
      )
  ```

**Testing:**
- [ ] Start Covina Ingestion Backend
- [ ] Verify certificate in `pki_client/covina-ingestion/`
- [ ] Test HTTPS: `https://localhost:45679/health`
- [ ] Test WebSocket: `wss://localhost:45679/ws/jobs`
- [ ] Upload test document (verify HTTPS upload)

**Expected Result:**
- ✅ Ingestion Backend runs with HTTPS (Port 45679)
- ✅ WebSocket over TLS (wss://)
- ✅ Certificate auto-requested
- ✅ Auto-renewal enabled

---

### 4. Clara System Integration

**Priority:** 🟡 **MEDIUM** (If exists)  
**Estimated Time:** 20 minutes (Backend + Frontend)

#### Backend Integration (10 minutes)

**File:** `C:\VCC\Clara\backend.py` (or main backend file)

**Tasks:**
- [ ] Check if Clara system exists at `C:\VCC\Clara`
  ```powershell
  cd C:\VCC\Clara
  ls
  ```

- [ ] If exists: Install PKI Client
  ```powershell
  pip install C:\VCC\PKI\client
  ```

- [ ] Import PKI Client
  ```python
  from vcc_pki_client import PKIClient
  import os
  ```

- [ ] Initialize PKI Client
  ```python
  pki = PKIClient(
      pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
      service_id="clara-backend",
      ca_password=os.getenv("VCC_CA_PASSWORD")
  )
  ```

- [ ] Add Startup Handler
  ```python
  @app.on_event("startup")
  async def startup():
      try:
          cert_info = pki.get_certificate_info()
          print(f"Clara: Certificate expires in {cert_info['days_until_expiry']} days")
      except:
          print("Clara: Requesting new certificate...")
          pki.request_certificate(
              common_name="clara-backend.vcc.local",
              san_dns=["clara-backend", "localhost"]
          )
      
      pki.register_service(
          service_name="Clara Backend",
          endpoints=["https://clara-backend.vcc.local:8002"],  # Adjust port
          health_check_url="https://clara-backend.vcc.local:8002/health"
      )
      
      pki.enable_auto_renewal()
  ```

- [ ] Add Shutdown Handler
  ```python
  @app.on_event("shutdown")
  async def shutdown():
      pki.disable_auto_renewal()
  ```

- [ ] Update uvicorn.run()
  ```python
  if __name__ == "__main__":
      ssl_context = pki.get_ssl_context()
      uvicorn.run(app, host="0.0.0.0", port=8002, ssl_context=ssl_context)
  ```

#### Frontend Integration (10 minutes)

**Tasks:**
- [ ] Update API URLs to HTTPS
- [ ] Add CA bundle verification
- [ ] Test end-to-end HTTPS communication

**Testing:**
- [ ] Start Clara Backend
- [ ] Verify certificate creation
- [ ] Test HTTPS endpoint
- [ ] Verify frontend connection

---

### 5. VPB System Integration

**Priority:** 🟡 **MEDIUM** (If exists)  
**Estimated Time:** 20 minutes (Backend + Frontend)

#### Backend Integration (10 minutes)

**File:** `C:\VCC\VPB\backend.py` (or main backend file)

**Tasks:**
- [ ] Check if VPB system exists
  ```powershell
  cd C:\VCC\VPB
  ls
  ```

- [ ] If exists: Install PKI Client
  ```powershell
  pip install C:\VCC\PKI\client
  ```

- [ ] Import PKI Client
  ```python
  from vcc_pki_client import PKIClient
  import os
  ```

- [ ] Initialize PKI Client
  ```python
  pki = PKIClient(
      pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
      service_id="vpb-backend",
      ca_password=os.getenv("VCC_CA_PASSWORD")
  )
  ```

- [ ] Add Startup Handler
  ```python
  @app.on_event("startup")
  async def startup():
      try:
          cert_info = pki.get_certificate_info()
          print(f"VPB: Certificate expires in {cert_info['days_until_expiry']} days")
      except:
          print("VPB: Requesting new certificate...")
          pki.request_certificate(
              common_name="vpb-backend.vcc.local",
              san_dns=["vpb-backend", "localhost"]
          )
      
      pki.register_service(
          service_name="VPB Backend",
          endpoints=["https://vpb-backend.vcc.local:8003"],  # Adjust port
          health_check_url="https://vpb-backend.vcc.local:8003/health"
      )
      
      pki.enable_auto_renewal()
  ```

- [ ] Add Shutdown Handler
  ```python
  @app.on_event("shutdown")
  async def shutdown():
      pki.disable_auto_renewal()
  ```

- [ ] Update uvicorn.run()
  ```python
  if __name__ == "__main__":
      ssl_context = pki.get_ssl_context()
      uvicorn.run(app, host="0.0.0.0", port=8003, ssl_context=ssl_context)
  ```

#### Frontend Integration (10 minutes)

**Tasks:**
- [ ] Update API URLs to HTTPS
- [ ] Add CA bundle verification
- [ ] Test end-to-end HTTPS communication

**Testing:**
- [ ] Start VPB Backend
- [ ] Verify certificate creation
- [ ] Test HTTPS endpoint
- [ ] Verify frontend connection

---

### 6. Argus System Integration

**Priority:** 🟢 **LOW** (If exists)  
**Estimated Time:** 20 minutes (Backend + Frontend)

#### Backend Integration (10 minutes)

**File:** `C:\VCC\Argus\backend.py` (or main backend file)

**Tasks:**
- [ ] Check if Argus system exists
  ```powershell
  cd C:\VCC\Argus
  ls
  ```

- [ ] If exists: Install PKI Client
  ```powershell
  pip install C:\VCC\PKI\client
  ```

- [ ] Import and Initialize PKI Client
  ```python
  from vcc_pki_client import PKIClient
  import os
  
  pki = PKIClient(
      pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
      service_id="argus-backend",
      ca_password=os.getenv("VCC_CA_PASSWORD")
  )
  ```

- [ ] Add Startup/Shutdown Handlers
  ```python
  @app.on_event("startup")
  async def startup():
      try:
          cert_info = pki.get_certificate_info()
      except:
          pki.request_certificate(
              common_name="argus-backend.vcc.local",
              san_dns=["argus-backend", "localhost"]
          )
      
      pki.register_service(
          service_name="Argus Monitoring Backend",
          endpoints=["https://argus-backend.vcc.local:8004"],
          health_check_url="https://argus-backend.vcc.local:8004/health"
      )
      pki.enable_auto_renewal()
  
  @app.on_event("shutdown")
  async def shutdown():
      pki.disable_auto_renewal()
  ```

- [ ] Update uvicorn.run()
  ```python
  if __name__ == "__main__":
      ssl_context = pki.get_ssl_context()
      uvicorn.run(app, host="0.0.0.0", port=8004, ssl_context=ssl_context)
  ```

#### Frontend Integration (10 minutes)

**Tasks:**
- [ ] Update API URLs to HTTPS
- [ ] Add CA bundle verification
- [ ] Test end-to-end HTTPS communication

---

### 7. PKI Server Self-Integration

**Priority:** 🟡 **MEDIUM** (Bootstrap problem)  
**Estimated Time:** 10 minutes

**Current:** PKI Server uses self-signed certificate  
**Goal:** PKI Server uses certificate from its own CA

#### Tasks

**File:** `C:\VCC\PKI\src\pki_server.py`

- [ ] Option A: Use existing certificate manager
  ```python
  # At startup, issue certificate for pki-server
  from service_cert_manager import ServiceCertificateManager
  
  cert_manager = ServiceCertificateManager(ca_manager)
  
  # Check if pki-server certificate exists
  if not os.path.exists("service_certificates/pki-server/cert.pem"):
      cert_manager.issue_certificate(
          service_id="pki-server",
          common_name="pki-server.vcc.local",
          san_dns=["pki-server", "localhost"],
          san_ip=["127.0.0.1"],
          validity_days=365
      )
  
  # Use this certificate for HTTPS
  ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  ssl_context.load_cert_chain(
      "service_certificates/pki-server/cert.pem",
      "service_certificates/pki-server/key.pem"
  )
  ```

- [ ] Option B: Keep self-signed (simpler)
  ```python
  # No changes needed
  # Self-signed is acceptable for PKI server itself
  # Clients use --no-verify-ssl when connecting to PKI server
  ```

**Recommendation:** Option B (keep self-signed) is simpler and acceptable.

---

## 📊 Integration Summary

### Quick Reference Table

| System | Service ID | Port | Common Name | Priority | Status |
|--------|------------|------|-------------|----------|--------|
| VERITAS Backend | `veritas-backend` | 8001 | `veritas-backend.vcc.local` | 🔴 HIGH | ⏳ |
| VERITAS Frontend | `veritas-frontend` | - | - | 🔴 HIGH | ⏳ |
| Covina Backend | `covina-backend` | 45678 | `covina-backend.vcc.local` | 🔴 HIGH | ⏳ |
| Covina Ingestion | `covina-ingestion` | 45679 | `covina-ingestion.vcc.local` | 🔴 HIGH | ⏳ |
| Covina Frontend | - | - | - | 🔴 HIGH | ⏳ |
| Clara Backend | `clara-backend` | 8002 | `clara-backend.vcc.local` | 🟡 MEDIUM | ⏳ |
| Clara Frontend | - | - | - | 🟡 MEDIUM | ⏳ |
| VPB Backend | `vpb-backend` | 8003 | `vpb-backend.vcc.local` | 🟡 MEDIUM | ⏳ |
| VPB Frontend | - | - | - | 🟡 MEDIUM | ⏳ |
| Argus Backend | `argus-backend` | 8004 | `argus-backend.vcc.local` | 🟢 LOW | ⏳ |
| Argus Frontend | - | - | - | 🟢 LOW | ⏳ |

---

## 🎯 Recommended Integration Order

### Phase 1: Critical Systems (HIGH Priority) - 1 hour

1. **Covina Main Backend** (10 min)
   - Most critical, highest traffic
   - Microservices architecture benefits most

2. **Covina Ingestion Backend** (10 min)
   - High throughput, needs mTLS
   - WebSocket security

3. **Covina Frontend** (10 min)
   - Update API client to HTTPS
   - LiveView Dashboard

4. **VERITAS Backend** (10 min)
   - Second critical system
   - API security

5. **VERITAS Frontend** (10 min)
   - Update API client
   - LiveView GUI

**Total Phase 1:** ~1 hour, 5 services integrated

### Phase 2: Medium Priority - 1 hour

6. **Clara Backend** (10 min) - If exists
7. **Clara Frontend** (10 min) - If exists
8. **VPB Backend** (10 min) - If exists
9. **VPB Frontend** (10 min) - If exists
10. **PKI Server Self-Integration** (10 min) - Optional

**Total Phase 2:** ~1 hour, 4-5 services

### Phase 3: Low Priority - 30 minutes

11. **Argus Backend** (10 min) - If exists
12. **Argus Frontend** (10 min) - If exists

**Total Phase 3:** ~30 minutes, 2 services

**Grand Total:** ~2.5 hours for all VCC systems!

---

## 🧪 Testing Checklist

### For Each Service Integration

**Before Integration:**
- [ ] PKI Server is running (`python pki_server.py --port 8443`)
- [ ] PKI Client Library is installed (`pip install C:\VCC\PKI\client`)
- [ ] CA is initialized (Root + Intermediate)

**After Backend Integration:**
- [ ] Service starts without errors
- [ ] Certificate is automatically requested
- [ ] Certificate files exist in `pki_client/{service-id}/`
  - [ ] `cert.pem`
  - [ ] `key.pem`
  - [ ] `ca_chain.pem`
- [ ] Service is registered in PKI server
- [ ] Auto-renewal is enabled
- [ ] HTTPS endpoint responds: `https://localhost:{port}/health`
- [ ] Check PKI Admin CLI: `python pki_admin_cli.py cert info {service-id}`

**After Frontend Integration:**
- [ ] Frontend can connect to backend via HTTPS
- [ ] No SSL verification errors
- [ ] All API calls work (queries, uploads, etc.)
- [ ] WebSocket connections work (if applicable)

**Verification Commands:**
```powershell
# List all certificates
python pki_admin_cli.py cert list

# Check specific service
python pki_admin_cli.py cert info {service-id}

# List registered services
python pki_admin_cli.py service list

# Health check
python pki_admin_cli.py health check

# Test HTTPS endpoint
curl -k https://localhost:{port}/health
```

---

## 📝 Environment Variables

### Global PKI Configuration

**Create/Update:** `.env` in each project root

```bash
# PKI Server Configuration
PKI_SERVER_URL=https://localhost:8443

# CA Password (same for all services)
VCC_CA_PASSWORD=your-ca-password-here

# Optional: Service-specific overrides
# SERVICE_ID=custom-service-id
# CERT_VALIDITY_DAYS=365
# AUTO_RENEWAL_CHECK_HOURS=6
# AUTO_RENEWAL_THRESHOLD_DAYS=30
```

**Security Note:** Never commit `.env` files with passwords!

---

## 🔧 Troubleshooting

### Common Issues

**Issue 1: Certificate Request Fails**
```
✗ HTTP Error 400: service_id must match pattern ^[a-z0-9-]+$
```
**Solution:** Use lowercase, numbers, and hyphens only in service_id.

---

**Issue 2: SSL Verification Error**
```
SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```
**Solution:** Download CA bundle from PKI server:
```python
response = requests.get("https://localhost:8443/api/ca/bundle", verify=False)
with open("ca_chain.pem", "wb") as f:
    f.write(response.content)
```

---

**Issue 3: Connection Refused**
```
✗ Connection Error: [Errno 10061] No connection could be made
```
**Solution:** Start PKI Server first:
```powershell
cd C:\VCC\PKI\src
python pki_server.py --port 8443
```

---

**Issue 4: Auto-Renewal Not Working**
```
# Certificate expires but doesn't renew
```
**Solution:** Check auto-renewal is enabled:
```python
# In startup handler
pki.enable_auto_renewal()

# Verify in logs
print(f"Auto-renewal enabled: check every 6h, renew at 30 days")
```

---

## 📈 Benefits After Integration

### Per Service

**Before Integration:**
- ❌ HTTP only (no encryption)
- ❌ Manual certificate management
- ❌ No certificate expiry monitoring
- ❌ No central certificate authority
- ❌ Complex SSL configuration

**After Integration:**
- ✅ **HTTPS** (encrypted communication)
- ✅ **Zero manual work** (auto-renewal)
- ✅ **Monitoring** (expiry tracking)
- ✅ **Central CA** (PKI Server)
- ✅ **5-minute setup** (PKI Client Library)

### System-Wide

**Security:**
- ✅ End-to-end encryption (all VCC services)
- ✅ Mutual TLS (mTLS) support
- ✅ Certificate revocation (CRL)
- ✅ Zero-trust architecture ready

**Operations:**
- ✅ Automated certificate lifecycle
- ✅ Central monitoring (PKI Admin CLI)
- ✅ Audit logging (all operations tracked)
- ✅ Health checks (certificate expiry)

**Development:**
- ✅ Consistent SSL configuration
- ✅ No certificate management code
- ✅ Type hints and IDE support
- ✅ Comprehensive documentation

---

## 🎉 Success Criteria

### Integration Complete When:

- [ ] All HIGH priority systems integrated (VERITAS, Covina)
- [ ] All backends run with HTTPS
- [ ] All frontends connect via HTTPS
- [ ] Certificates auto-renew (tested)
- [ ] Health checks pass for all services
- [ ] No manual certificate operations needed
- [ ] PKI Admin CLI shows all services registered
- [ ] End-to-end testing successful (user workflows)

### Metrics to Track:

- **Integration Time:** Target < 3 hours total
- **Certificate Count:** 6-12 certificates (depending on systems)
- **Auto-Renewal:** 100% success rate
- **Uptime:** No service downtime during integration
- **Security:** 100% HTTPS communication

---

## 📞 Support

### If Issues Occur:

1. **Check PKI Server Status:**
   ```powershell
   python pki_admin_cli.py health check
   ```

2. **View Certificate Status:**
   ```powershell
   python pki_admin_cli.py cert list
   python pki_admin_cli.py cert info {service-id}
   ```

3. **Check Logs:**
   - PKI Server: `C:\VCC\PKI\logs\pki_server.log`
   - Service logs: Check application logs

4. **Test Manually:**
   ```powershell
   # Test certificate request
   python -c "from vcc_pki_client import PKIClient; pki = PKIClient('https://localhost:8443', 'test-service'); pki.request_certificate('test.vcc.local')"
   ```

5. **Documentation:**
   - Client Library: `C:\VCC\PKI\client\README.md`
   - Admin CLI: `C:\VCC\PKI\docs\PKI_ADMIN_CLI.md`
   - Project Overview: `C:\VCC\PKI\docs\PKI_PROJECT_COMPLETE.md`

---

**Status:** 🎯 **READY TO START**  
**Last Updated:** 13. Oktober 2025  
**Estimated Total Time:** 2.5 hours for all VCC systems  
**Priority Order:** Covina → VERITAS → Clara → VPB → Argus

**Let's secure all VCC services with PKI! 🔒**
