# VCC PKI Client Library

Easy-to-use Python client library for integrating services with the VCC PKI Server.

## Features

- ✅ **Certificate Request & Renewal** - Simple API for certificate lifecycle
- ✅ **Automatic Renewal** - Background thread renews certificates before expiry
- ✅ **SSL Context Creation** - Ready-to-use SSL contexts for httpx, requests, FastAPI
- ✅ **Service Registration** - Register services in PKI server registry
- ✅ **No Hard Dependencies** - Works with standard library (httpx optional)
- ✅ **Type Hints** - Full type annotations for IDE support
- ✅ **Context Manager** - Clean resource management with `with` statement

## Installation

```bash
# Basic installation (uses urllib - no dependencies)
pip install vcc-pki-client

# With httpx (recommended for better performance)
pip install vcc-pki-client[httpx]

# Development installation
cd C:\VCC\PKI\client
pip install -e .
```

## Quick Start

### 1. Basic Usage

```python
from vcc_pki_client import PKIClient

# Initialize client
pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-service",
    ca_password="secret"  # Or set VCC_CA_PASSWORD env var
)

# Request certificate (first time)
pki.request_certificate(
    common_name="my-service.vcc.local",
    san_dns=["my-service", "localhost"],
    san_ip=["127.0.0.1"],
    validity_days=365
)

# Get certificate info
cert_info = pki.get_certificate_info()
print(f"Certificate expires in {cert_info['days_until_expiry']} days")
```

### 2. Automatic Renewal

```python
from vcc_pki_client import PKIClient

pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-service"
)

# Enable auto-renewal
# Checks every 6 hours, renews 30 days before expiry
pki.enable_auto_renewal(
    check_interval_hours=6,
    renew_before_days=30
)

# Auto-renewal runs in background thread
# Your application continues normally

# Disable when shutting down
pki.disable_auto_renewal()
```

### 3. FastAPI / uvicorn Integration

```python
from fastapi import FastAPI
from vcc_pki_client import PKIClient
import uvicorn

app = FastAPI()

# Initialize PKI client
pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-api"
)

# Request certificate (if not exists)
try:
    pki.get_certificate_info()
except:
    pki.request_certificate(
        common_name="my-api.vcc.local",
        san_dns=["my-api", "localhost"]
    )

# Enable auto-renewal
pki.enable_auto_renewal()

# Get SSL context
ssl_context = pki.get_ssl_context()

# Run FastAPI with mTLS
uvicorn.run(
    app,
    host="0.0.0.0",
    port=8000,
    ssl_context=ssl_context
)
```

### 4. httpx Client (Service-to-Service)

```python
import httpx
from vcc_pki_client import PKIClient

# Initialize PKI client
pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-client"
)

# Get SSL configuration
verify, cert = pki.get_httpx_config()

# Create httpx client with mTLS
client = httpx.Client(
    verify=verify,  # CA bundle for server verification
    cert=cert       # (cert.pem, key.pem) for client authentication
)

# Make mTLS requests
response = client.get("https://other-service.vcc.local/api/data")
print(response.json())
```

### 5. requests Session

```python
import requests
from vcc_pki_client import PKIClient

pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-client"
)

# Get SSL configuration
verify, cert = pki.get_requests_config()

# Create requests session
session = requests.Session()
session.verify = verify
session.cert = cert

# Make mTLS requests
response = session.get("https://other-service.vcc.local/api/data")
print(response.json())
```

### 6. Service Registration

```python
from vcc_pki_client import PKIClient

pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-service"
)

# Register service in PKI registry
pki.register_service(
    service_name="My Awesome Service",
    endpoints=[
        "https://my-service.vcc.local:8000",
        "https://my-service.vcc.local:8443"
    ],
    health_check_url="https://my-service.vcc.local:8000/health",
    metadata={
        "version": "1.0.0",
        "environment": "production"
    }
)
```

### 7. Context Manager

```python
from vcc_pki_client import PKIClient

# Use context manager for automatic cleanup
with PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-service"
) as pki:
    pki.request_certificate(
        common_name="my-service.vcc.local"
    )
    pki.enable_auto_renewal()
    
    # Do work...
    
    # Auto-renewal automatically stopped on exit
```

## API Reference

### PKIClient

#### `__init__(pki_server_url, service_id, ca_password=None, storage_path=None, verify_ssl=True)`

Initialize PKI client.

**Parameters:**
- `pki_server_url` (str): URL of PKI server (e.g., https://localhost:8443)
- `service_id` (str): Service identifier (pattern: `^[a-z0-9-]+$`)
- `ca_password` (str, optional): CA password (or set `VCC_CA_PASSWORD` env var)
- `storage_path` (str, optional): Path to store certificates (default: `./pki_client/{service_id}`)
- `verify_ssl` (bool): Verify PKI server SSL certificate (default: True)

#### `request_certificate(common_name, san_dns=None, san_ip=None, validity_days=365)`

Request new certificate from PKI server.

**Returns:** `dict` with `certificate_id` and `expires_at`

#### `renew_certificate(validity_days=365)`

Renew existing certificate.

**Returns:** `dict` with new certificate info

#### `get_certificate_info()`

Get certificate information from PKI server.

**Returns:** `dict` with certificate details (status, expiry, etc.)

#### `register_service(service_name, endpoints=None, health_check_url=None, metadata=None)`

Register service in PKI server registry.

**Returns:** `dict` with registration result

#### `enable_auto_renewal(check_interval_hours=6, renew_before_days=30)`

Enable automatic certificate renewal (background thread).

- Checks certificate expiry every `check_interval_hours` hours
- Renews certificate when expiry < `renew_before_days` days

#### `disable_auto_renewal()`

Stop automatic certificate renewal.

#### `get_ssl_context(client_auth=False)`

Get SSL context for FastAPI/uvicorn server.

**Returns:** `ssl.SSLContext`

#### `get_client_ssl_context()`

Get SSL context for client connections.

**Returns:** `ssl.SSLContext`

#### `get_httpx_config()`

Get SSL configuration for httpx.Client.

**Returns:** `tuple` of `(verify, cert)`

#### `get_requests_config()`

Get SSL configuration for requests.Session.

**Returns:** `tuple` of `(verify, cert)`

## Environment Variables

- `VCC_CA_PASSWORD`: CA password for certificate operations (alternative to constructor parameter)

## File Structure

After initialization, certificates are stored in:

```
pki_client/
└── {service_id}/
    ├── cert.pem          # Service certificate
    ├── key.pem           # Private key
    └── ca_chain.pem      # CA bundle (Root + Intermediate)
```

## Error Handling

```python
from vcc_pki_client import (
    PKIClient,
    PKIClientError,
    CertificateNotFoundError,
    CertificateExpiredError,
    ServerConnectionError,
    InvalidResponseError
)

try:
    pki = PKIClient(
        pki_server_url="https://localhost:8443",
        service_id="my-service"
    )
    pki.request_certificate(common_name="my-service.vcc.local")
    
except CertificateNotFoundError:
    print("Certificate not found - requesting new one")
    
except ServerConnectionError as e:
    print(f"Failed to connect to PKI server: {e}")
    
except PKIClientError as e:
    print(f"PKI error: {e}")
```

## Complete Example: FastAPI Service with Auto-Renewal

```python
from fastapi import FastAPI, Depends, HTTPException
from vcc_pki_client import PKIClient
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="My Secure Service")

# Initialize PKI client
pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-secure-service",
    ca_password="secret"
)

@app.on_event("startup")
async def startup():
    """Initialize certificates and auto-renewal on startup"""
    try:
        # Check if certificate exists
        cert_info = pki.get_certificate_info()
        logger.info(f"Certificate found, expires in {cert_info['days_until_expiry']} days")
        
    except Exception:
        # Request new certificate
        logger.info("No certificate found, requesting new one...")
        pki.request_certificate(
            common_name="my-secure-service.vcc.local",
            san_dns=["my-secure-service", "localhost"],
            san_ip=["127.0.0.1"]
        )
        logger.info("Certificate obtained successfully")
    
    # Register service
    pki.register_service(
        service_name="My Secure Service",
        endpoints=["https://my-secure-service.vcc.local:8000"],
        health_check_url="https://my-secure-service.vcc.local:8000/health"
    )
    
    # Enable auto-renewal
    pki.enable_auto_renewal(check_interval_hours=6, renew_before_days=30)
    logger.info("Auto-renewal enabled")

@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    pki.disable_auto_renewal()
    logger.info("Auto-renewal stopped")

@app.get("/health")
async def health():
    """Health check endpoint"""
    try:
        cert_info = pki.get_certificate_info()
        return {
            "status": "healthy",
            "certificate": {
                "days_until_expiry": cert_info["days_until_expiry"],
                "needs_renewal": cert_info["days_until_expiry"] < 30
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/data")
async def get_data():
    """Example API endpoint"""
    return {"message": "Hello from secure service!"}

if __name__ == "__main__":
    # Get SSL context
    ssl_context = pki.get_ssl_context()
    
    # Run with mTLS
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_context=ssl_context,
        log_level="info"
    )
```

## License

MIT License - VCC Team © 2025

## Support

For issues and questions:
- GitHub Issues: https://github.com/vcc/pki-client/issues
- Documentation: https://github.com/vcc/pki-client/docs
