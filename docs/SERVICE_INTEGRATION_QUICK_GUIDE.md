# VCC PKI - Service Integration Quick Guide

**How to integrate your microservice with VCC Global PKI**

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Get Your Certificate (1 minute)

```bash
cd C:\VCC\PKI
python src\service_cert_manager.py issue \
  --service-id YOUR-SERVICE-NAME \
  --cn YOUR-SERVICE-NAME.vcc.local \
  --san-dns YOUR-SERVICE-NAME localhost \
  --san-ip 127.0.0.1 192.168.178.94 \
  --ca-password vcc_intermediate_pw_2025
```

**Example:** For a new service "clara-backend":
```bash
python src\service_cert_manager.py issue \
  --service-id clara-backend \
  --cn clara-backend.vcc.local \
  --san-dns clara-backend localhost \
  --san-ip 127.0.0.1 192.168.178.94 \
  --ca-password vcc_intermediate_pw_2025
```

**Result:**
```
✅ Certificate issued successfully!
   Certificate: service_certificates\clara-backend\cert.pem
   Private Key: service_certificates\clara-backend\key.pem
```

---

### Step 2: Copy Root CA Certificate (1 minute)

```bash
# Copy Root CA to your project
Copy-Item C:\VCC\PKI\ca_storage\root_ca.pem C:\VCC\YourProject\ca_root.pem
```

---

### Step 3: Configure mTLS in Your Service (3 minutes)

**Option A: Python (FastAPI/uvicorn)**

```python
# your_service.py
import uvicorn
from fastapi import FastAPI

app = FastAPI()

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=YOUR_PORT,
        ssl_keyfile="C:/VCC/PKI/service_certificates/YOUR-SERVICE/key.pem",
        ssl_certfile="C:/VCC/PKI/service_certificates/YOUR-SERVICE/cert.pem",
        ssl_ca_certs="C:/VCC/PKI/ca_storage/root_ca.pem",
        ssl_cert_reqs=2  # Require client certificate
    )
```

**Option B: Python (httpx client for mTLS requests)**

```python
import httpx
import ssl

# Create SSL context for mTLS client
ssl_context = ssl.create_default_context(
    cafile="C:/VCC/PKI/ca_storage/root_ca.pem"
)
ssl_context.load_cert_chain(
    certfile="C:/VCC/PKI/service_certificates/YOUR-SERVICE/cert.pem",
    keyfile="C:/VCC/PKI/service_certificates/YOUR-SERVICE/key.pem"
)

# Make mTLS request to another service
with httpx.Client(verify=ssl_context) as client:
    response = client.get("https://other-service.vcc.local:PORT/api/endpoint")
    print(response.json())
```

---

## 📋 Complete Integration Examples

### Example 1: VERITAS Backend (Existing Service)

**1. Get Certificate:**
```bash
cd C:\VCC\PKI
python src\service_cert_manager.py issue \
  --service-id veritas-backend \
  --cn veritas-backend.vcc.local \
  --san-dns veritas-backend localhost \
  --san-ip 127.0.0.1 192.168.178.94 \
  --ca-password vcc_intermediate_pw_2025
```

**2. Update VERITAS Backend:**
```python
# C:\VCC\veritas\backend\api\main_mtls.py
import uvicorn
from fastapi import FastAPI

app = FastAPI()

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=45678,
        ssl_keyfile="C:/VCC/PKI/service_certificates/veritas-backend/key.pem",
        ssl_certfile="C:/VCC/PKI/service_certificates/veritas-backend/cert.pem",
        ssl_ca_certs="C:/VCC/PKI/ca_storage/root_ca.pem",
        ssl_cert_reqs=2  # mTLS required
    )
```

**3. Update mTLS Middleware:**
```python
# C:\VCC\veritas\backend\api\mtls_middleware.py
from backend.pki.ssl_context import create_mtls_ssl_context

# Use VCC PKI certificates instead of local ca_storage
ssl_context = create_mtls_ssl_context(
    server_cert="C:/VCC/PKI/service_certificates/veritas-backend/cert.pem",
    server_key="C:/VCC/PKI/service_certificates/veritas-backend/key.pem",
    ca_cert="C:/VCC/PKI/ca_storage/root_ca.pem"
)
```

---

### Example 2: Covina Backend

**1. Get Certificate:**
```bash
cd C:\VCC\PKI
python src\service_cert_manager.py issue \
  --service-id covina-backend \
  --cn covina-backend.vcc.local \
  --san-dns covina-backend localhost \
  --san-ip 127.0.0.1 192.168.178.94 \
  --ca-password vcc_intermediate_pw_2025
```

**2. Update Covina Backend:**
```python
# C:\VCC\Covina\backend.py
import uvicorn
from fastapi import FastAPI

app = FastAPI()

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=45678,
        ssl_keyfile="C:/VCC/PKI/service_certificates/covina-backend/key.pem",
        ssl_certfile="C:/VCC/PKI/service_certificates/covina-backend/cert.pem",
        ssl_ca_certs="C:/VCC/PKI/ca_storage/root_ca.pem",
        ssl_cert_reqs=2
    )
```

**3. Connect Covina Ingestion to Covina Backend (mTLS):**
```python
# C:\VCC\Covina\ingestion_backend.py
import httpx
import ssl

# Create SSL context for covina-ingestion
ssl_context = ssl.create_default_context(
    cafile="C:/VCC/PKI/ca_storage/root_ca.pem"
)
ssl_context.load_cert_chain(
    certfile="C:/VCC/PKI/service_certificates/covina-ingestion/cert.pem",
    keyfile="C:/VCC/PKI/service_certificates/covina-ingestion/key.pem"
)

# Make mTLS request to Covina Backend
with httpx.Client(verify=ssl_context) as client:
    response = client.post(
        "https://covina-backend.vcc.local:45678/api/v1/documents",
        json={"document": "data"}
    )
    print(response.json())
```

---

### Example 3: Service-to-Service Communication

**Scenario:** VERITAS Backend wants to query Covina Backend

**VERITAS Backend Code:**
```python
# C:\VCC\veritas\backend\services\covina_client.py
import httpx
import ssl
from typing import Dict, Any

class CovinaClient:
    """Client for secure mTLS communication with Covina Backend"""
    
    def __init__(self):
        self.base_url = "https://covina-backend.vcc.local:45678"
        self.ssl_context = self._create_ssl_context()
        self.client = httpx.Client(verify=self.ssl_context, timeout=30.0)
    
    def _create_ssl_context(self):
        """Create SSL context with VERITAS credentials"""
        ssl_context = ssl.create_default_context(
            cafile="C:/VCC/PKI/ca_storage/root_ca.pem"
        )
        ssl_context.load_cert_chain(
            certfile="C:/VCC/PKI/service_certificates/veritas-backend/cert.pem",
            keyfile="C:/VCC/PKI/service_certificates/veritas-backend/key.pem"
        )
        return ssl_context
    
    def search_documents(self, query: str) -> Dict[str, Any]:
        """Search documents in Covina"""
        response = self.client.post(
            f"{self.base_url}/api/v1/search",
            json={"query": query}
        )
        response.raise_for_status()
        return response.json()
    
    def get_document(self, doc_id: str) -> Dict[str, Any]:
        """Get document from Covina"""
        response = self.client.get(
            f"{self.base_url}/api/v1/documents/{doc_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def close(self):
        """Close client connection"""
        self.client.close()

# Usage
covina_client = CovinaClient()
results = covina_client.search_documents("AI agents")
print(results)
covina_client.close()
```

---

## 🔄 Certificate Renewal

### Manual Renewal
```bash
cd C:\VCC\PKI
python src\service_cert_manager.py renew \
  --service-id YOUR-SERVICE \
  --ca-password vcc_intermediate_pw_2025
```

### Automatic Renewal (Coming Soon in Phase 2)
```python
# Will be provided by vcc_pki_client library
from vcc_pki_client import PKIClient

pki_client = PKIClient(
    service_id="YOUR-SERVICE",
    auto_renew=True,
    renew_before_days=30
)

# Automatic renewal runs in background
# Service restarts gracefully when certificate is renewed
```

---

## 🔐 Security Best Practices

### 1. Private Key Protection
```bash
# Private keys should have restrictive permissions
# Windows: Right-click → Properties → Security → Remove all except SYSTEM and your user
# Unix: chmod 400 service_certificates/YOUR-SERVICE/key.pem
```

### 2. Certificate Validation
```python
# Always validate certificates in mTLS
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED
```

### 3. Error Handling
```python
import httpx
import ssl

try:
    with httpx.Client(verify=ssl_context) as client:
        response = client.get("https://other-service.vcc.local/api/endpoint")
        response.raise_for_status()
except httpx.ConnectError:
    print("❌ Connection failed - check mTLS configuration")
except httpx.HTTPStatusError as e:
    print(f"❌ HTTP error: {e.response.status_code}")
except ssl.SSLError as e:
    print(f"❌ SSL error: {e}")
```

### 4. Certificate Expiry Monitoring
```bash
# Check certificate expiry
python src\service_cert_manager.py info --service-id YOUR-SERVICE

# Output shows:
# Valid Until: 2026-10-13T15:58:44+00:00
```

---

## 📚 Reference

### Service IDs (Current)
- `veritas-backend` - VERITAS Backend API
- `veritas-frontend` - VERITAS Frontend (planned)
- `covina-backend` - Covina Backend API
- `covina-ingestion` - Covina Ingestion Service
- `vpb-backend` - VPB Backend (planned)
- `clara-backend` - Clara Backend (planned)

### Ports (Standard)
- VERITAS Backend: 45678
- VERITAS Frontend: 8080
- Covina Backend: 45678
- Covina Ingestion: 45679
- VPB Backend: 45680
- Clara Backend: 45681

### File Locations
- **Root CA:** `C:\VCC\PKI\ca_storage\root_ca.pem`
- **Intermediate CA:** `C:\VCC\PKI\ca_storage\intermediate_ca.pem`
- **Service Certs:** `C:\VCC\PKI\service_certificates\{service-id}\`

---

## 🆘 Troubleshooting

### Issue 1: Certificate Not Found
```
❌ FileNotFoundError: [Errno 2] No such file or directory
```
**Solution:** Request certificate first with `issue` command

### Issue 2: SSL Error - Certificate Verification Failed
```
❌ ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```
**Solution:** Ensure Root CA certificate path is correct

### Issue 3: Connection Refused
```
❌ httpx.ConnectError: [Errno 111] Connection refused
```
**Solution:** Ensure target service is running with mTLS enabled

### Issue 4: Private Key Encrypted
```
❌ ValueError: Intermediate CA private key is encrypted. Provide password.
```
**Solution:** Add `--ca-password` parameter

---

## 📞 Support

### Commands
```bash
# List all certificates
python src\service_cert_manager.py list

# Certificate info
python src\service_cert_manager.py info --service-id YOUR-SERVICE

# CA status
python src\ca_manager.py info
```

### Documentation
- Architecture: `C:\VCC\PKI\docs\PKI_SERVER_ARCHITECTURE.md`
- Implementation Status: `C:\VCC\PKI\docs\IMPLEMENTATION_STATUS.md`
- This Guide: `C:\VCC\PKI\docs\SERVICE_INTEGRATION_QUICK_GUIDE.md`

---

**Version:** 1.0  
**Last Updated:** 2025-10-13  
**Author:** VCC Development Team

