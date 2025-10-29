"""
VCC PKI Client Library
======================

Easy-to-use Python client library for integrating services with the VCC PKI Server.

Features:
- Certificate request and renewal
- Automatic certificate renewal (background thread)
- SSL context creation for httpx, requests, FastAPI
- Service registration
- Certificate download and validation

Example Usage:
--------------
```python
from vcc_pki_client import PKIClient

# Initialize client
pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-service",
    ca_password="secret"  # Optional, can use env var VCC_CA_PASSWORD
)

# Request certificate (first time)
pki.request_certificate(
    common_name="my-service.vcc.local",
    san_dns=["my-service", "localhost"],
    san_ip=["127.0.0.1"]
)

# Enable auto-renewal (renews 30 days before expiry)
pki.enable_auto_renewal(check_interval_hours=6)

# Get SSL context for FastAPI/uvicorn
ssl_context = pki.get_ssl_context()
uvicorn.run(app, ssl_context=ssl_context)

# Get SSL context for httpx client
import httpx
client = httpx.Client(
    verify=pki.ca_bundle,
    cert=(pki.cert_file, pki.key_file)
)
```

Author: VCC Team
Date: 2025-10-13
Version: 1.0.0
"""

from .client import PKIClient
from .exceptions import (
    PKIClientError,
    CertificateNotFoundError,
    CertificateExpiredError,
    ServerConnectionError,
    InvalidResponseError
)

__version__ = "1.0.0"
__all__ = [
    "PKIClient",
    "PKIClientError",
    "CertificateNotFoundError",
    "CertificateExpiredError",
    "ServerConnectionError",
    "InvalidResponseError"
]
