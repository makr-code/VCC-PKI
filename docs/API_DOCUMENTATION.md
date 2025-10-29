# VCC PKI Server - REST API Documentation

**Version:** 1.0.0  
**Base URL:** `https://localhost:8443/api/v1`  
**Date:** 2025-10-13

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
   - [Health & Info](#health--info)
   - [Certificate Management](#certificate-management)
   - [Service Registry](#service-registry)
   - [CA Operations](#ca-operations)
   - [CRL Operations](#crl-operations)
4. [Request/Response Examples](#requestresponse-examples)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Best Practices](#best-practices)

---

## 🌟 Overview

The VCC PKI Server REST API provides comprehensive certificate management for all VCC microservices. It enables:

- **Automated Certificate Issuance**: Request and download service certificates
- **Certificate Lifecycle Management**: Renewal, revocation, and status tracking
- **Service Registry**: Register services and manage service discovery
- **CA Distribution**: Download Root CA and Intermediate CA certificates
- **CRL Management**: Certificate Revocation List operations

**Technology Stack:**
- FastAPI (async Python web framework)
- Pydantic (data validation)
- cryptography (X.509 certificate operations)
- uvicorn (ASGI server)

---

## 🔐 Authentication

### Current Implementation (Development)

```http
Authorization: Bearer <service_id>
```

**Example:**
```bash
curl -H "Authorization: Bearer veritas-backend" \
     https://localhost:8443/api/v1/certificates/veritas-backend
```

### Production Implementation (Planned)

**mTLS (Mutual TLS) Authentication:**
- Client certificate required for all API requests
- Certificate validated against VCC Intermediate CA
- Service ID extracted from certificate Common Name (CN)
- Zero-trust architecture

**Benefits:**
- ✅ Strong authentication (certificate-based)
- ✅ No bearer tokens to manage
- ✅ Automatic client identity verification
- ✅ Protection against man-in-the-middle attacks

---

## 📡 API Endpoints

### Health & Info

#### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-13T16:30:00.000000",
  "version": "1.0.0"
}
```

#### `GET /api/v1/info`

Get PKI server information.

**Response:**
```json
{
  "server": "VCC PKI Server",
  "version": "1.0.0",
  "ca_status": "operational",
  "total_services": 5,
  "total_certificates": 8
}
```

---

### Certificate Management

#### `POST /api/v1/certificates/request`

Request a new service certificate.

**Headers:**
- `Authorization: Bearer <service_id>`
- `X-CA-Password: <intermediate_ca_password>` (optional, uses env var if not provided)

**Request Body:**
```json
{
  "service_id": "veritas-backend",
  "common_name": "veritas-backend.vcc.local",
  "san_dns": ["veritas-backend", "localhost"],
  "san_ip": ["127.0.0.1", "192.168.178.94"],
  "validity_days": 365
}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate issued successfully for veritas-backend",
  "data": {
    "certificate_id": "cert_veritas-backend_20251013_163000",
    "service_id": "veritas-backend",
    "expires_at": "2026-10-13T16:30:00.000000+00:00"
  }
}
```

**Status Codes:**
- `200 OK` - Certificate issued successfully
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Missing or invalid authentication
- `500 Internal Server Error` - Certificate issuance failed

---

#### `GET /api/v1/certificates/{service_id}`

Get certificate information for a service.

**Response:**
```json
{
  "certificate_id": "cert_veritas-backend_20251013_163000",
  "service_id": "veritas-backend",
  "common_name": "veritas-backend.vcc.local",
  "serial_number": "273043850637616436189921058267755906311470697859",
  "fingerprint": "SHA256:A1:B2:C3:...",
  "not_before": "2025-10-13T16:30:00+00:00",
  "not_after": "2026-10-13T16:30:00+00:00",
  "status": "active",
  "san_dns": ["veritas-backend", "localhost"],
  "san_ip": ["127.0.0.1", "192.168.178.94"],
  "issuer": "VCC Intermediate CA",
  "days_until_expiry": 365
}
```

**Status Codes:**
- `200 OK` - Certificate found
- `404 Not Found` - Certificate not found for service

---

#### `GET /api/v1/certificates/{service_id}/download`

Download certificate or private key.

**Query Parameters:**
- `file_type` - Type of file to download:
  - `cert` - Service certificate (default)
  - `key` - Private key
  - `ca` - CA chain (Intermediate + Root)

**Example:**
```bash
# Download certificate
curl https://localhost:8443/api/v1/certificates/veritas-backend/download?file_type=cert \
     -o veritas-backend_cert.pem

# Download private key
curl https://localhost:8443/api/v1/certificates/veritas-backend/download?file_type=key \
     -o veritas-backend_key.pem

# Download CA chain
curl https://localhost:8443/api/v1/certificates/veritas-backend/download?file_type=ca \
     -o ca_chain.pem
```

**Response:**
- File download (PEM format)

**Status Codes:**
- `200 OK` - File downloaded successfully
- `400 Bad Request` - Invalid file_type
- `404 Not Found` - Certificate or file not found

---

#### `POST /api/v1/certificates/{service_id}/renew`

Renew an existing certificate.

**Headers:**
- `X-CA-Password: <intermediate_ca_password>`

**Request Body:**
```json
{
  "validity_days": 365
}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate renewed successfully for veritas-backend",
  "data": {
    "certificate_id": "cert_veritas-backend_20251014_100000",
    "service_id": "veritas-backend",
    "expires_at": "2026-10-14T10:00:00.000000+00:00"
  }
}
```

**Status Codes:**
- `200 OK` - Certificate renewed successfully
- `404 Not Found` - Certificate not found
- `500 Internal Server Error` - Renewal failed

---

#### `DELETE /api/v1/certificates/{service_id}/revoke`

Revoke a certificate.

**Headers:**
- `X-CA-Password: <intermediate_ca_password>`

**Request Body:**
```json
{
  "reason": "key_compromise"
}
```

**Revocation Reasons (RFC 5280):**
- `unspecified`
- `key_compromise`
- `ca_compromise`
- `affiliation_changed`
- `superseded`
- `cessation_of_operation`
- `certificate_hold`
- `remove_from_crl`
- `privilege_withdrawn`
- `aa_compromise`

**Response:**
```json
{
  "success": true,
  "message": "Certificate revoked successfully for veritas-backend",
  "data": {
    "service_id": "veritas-backend",
    "reason": "key_compromise",
    "revoked_at": "2025-10-13T16:45:00.000000"
  }
}
```

**Status Codes:**
- `200 OK` - Certificate revoked successfully
- `404 Not Found` - Certificate not found
- `500 Internal Server Error` - Revocation failed

---

#### `GET /api/v1/certificates`

List all issued certificates.

**Response:**
```json
{
  "total": 3,
  "certificates": [
    {
      "certificate_id": "cert_veritas-backend_20251013_163000",
      "service_id": "veritas-backend",
      "common_name": "veritas-backend.vcc.local",
      "status": "active",
      "not_after": "2026-10-13T16:30:00+00:00",
      "days_until_expiry": 365,
      "needs_renewal": false
    },
    {
      "certificate_id": "cert_covina-backend_20251013_163100",
      "service_id": "covina-backend",
      "common_name": "covina-backend.vcc.local",
      "status": "active",
      "not_after": "2026-10-13T16:31:00+00:00",
      "days_until_expiry": 365,
      "needs_renewal": false
    },
    {
      "certificate_id": "cert_old-service_20240101_120000",
      "service_id": "old-service",
      "common_name": "old-service.vcc.local",
      "status": "active",
      "not_after": "2025-11-13T12:00:00+00:00",
      "days_until_expiry": 25,
      "needs_renewal": true
    }
  ]
}
```

**Status Codes:**
- `200 OK` - Certificates listed successfully

---

### Service Registry

#### `POST /api/v1/services/register`

Register a new service in the registry.

**Request Body:**
```json
{
  "service_id": "veritas-backend",
  "service_name": "VERITAS Backend API",
  "endpoints": [
    "https://localhost:45678/api"
  ],
  "metadata": {
    "version": "1.0.0",
    "team": "VCC Core Team",
    "contact": "team@vcc.local"
  },
  "health_check_url": "https://localhost:45678/health"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Service registered successfully: veritas-backend",
  "data": {
    "service_id": "veritas-backend",
    "service_name": "VERITAS Backend API",
    "endpoints": ["https://localhost:45678/api"],
    "metadata": {...},
    "health_check_url": "https://localhost:45678/health",
    "registered_at": "2025-10-13T16:30:00.000000",
    "last_seen": "2025-10-13T16:30:00.000000"
  }
}
```

**Status Codes:**
- `200 OK` - Service registered successfully
- `409 Conflict` - Service already registered
- `400 Bad Request` - Invalid request data

---

#### `GET /api/v1/services`

List all registered services.

**Response:**
```json
{
  "total": 2,
  "services": [
    {
      "service_id": "veritas-backend",
      "service_name": "VERITAS Backend API",
      "endpoints": ["https://localhost:45678/api"],
      "certificate_status": "active",
      "certificate_expiry": "2026-10-13T16:30:00+00:00",
      "certificate_needs_renewal": false,
      "registered_at": "2025-10-13T16:30:00.000000"
    },
    {
      "service_id": "covina-backend",
      "service_name": "Covina Backend API",
      "endpoints": ["https://localhost:45679/api"],
      "certificate_status": "not_issued",
      "certificate_expiry": null,
      "registered_at": "2025-10-13T16:31:00.000000"
    }
  ]
}
```

**Status Codes:**
- `200 OK` - Services listed successfully

---

#### `GET /api/v1/services/{service_id}`

Get detailed information about a service.

**Response:**
```json
{
  "service_id": "veritas-backend",
  "service_name": "VERITAS Backend API",
  "endpoints": ["https://localhost:45678/api"],
  "metadata": {
    "version": "1.0.0",
    "team": "VCC Core Team"
  },
  "health_check_url": "https://localhost:45678/health",
  "registered_at": "2025-10-13T16:30:00.000000",
  "certificate": {
    "certificate_id": "cert_veritas-backend_20251013_163000",
    "common_name": "veritas-backend.vcc.local",
    "serial_number": "273043850637616436189921058267755906311470697859",
    "status": "active",
    "not_before": "2025-10-13T16:30:00+00:00",
    "not_after": "2026-10-13T16:30:00+00:00"
  }
}
```

**Status Codes:**
- `200 OK` - Service found
- `404 Not Found` - Service not found

---

### CA Operations

#### `GET /api/v1/ca/root`

Download Root CA certificate.

**Response:**
- File download: `vcc_root_ca.pem`

**Example:**
```bash
curl https://localhost:8443/api/v1/ca/root -o root_ca.pem
```

---

#### `GET /api/v1/ca/intermediate`

Download Intermediate CA certificate.

**Response:**
- File download: `vcc_intermediate_ca.pem`

**Example:**
```bash
curl https://localhost:8443/api/v1/ca/intermediate -o intermediate_ca.pem
```

---

#### `GET /api/v1/ca/chain`

Download complete CA chain (Intermediate + Root).

**Response:**
- File download: `vcc_ca_chain.pem`

**Example:**
```bash
curl https://localhost:8443/api/v1/ca/chain -o ca_chain.pem
```

**Use Case:**
Use this CA chain to configure SSL context in client applications for mTLS.

---

### CRL Operations

#### `GET /api/v1/crl`

Get Certificate Revocation List.

**Response:**
```json
{
  "version": "1.0",
  "issuer": "VCC Intermediate CA",
  "this_update": "2025-10-13T16:30:00.000000",
  "next_update": "2025-10-20T16:30:00.000000",
  "revoked_certificates": [
    {
      "serial_number": "123456789",
      "revocation_date": "2025-10-10T12:00:00.000000",
      "reason": "key_compromise"
    }
  ]
}
```

**Status Codes:**
- `200 OK` - CRL retrieved successfully

---

## 💻 Request/Response Examples

### Example 1: Request Certificate via API

```python
import requests

# API endpoint
url = "https://localhost:8443/api/v1/certificates/request"

# Request data
data = {
    "service_id": "my-service",
    "common_name": "my-service.vcc.local",
    "san_dns": ["my-service", "localhost"],
    "san_ip": ["127.0.0.1"],
    "validity_days": 365
}

# Headers
headers = {
    "Authorization": "Bearer my-service",
    "X-CA-Password": "vcc_intermediate_pw_2025",
    "Content-Type": "application/json"
}

# Request certificate
response = requests.post(url, json=data, headers=headers, verify=False)

if response.status_code == 200:
    result = response.json()
    print(f"✅ Certificate issued: {result['data']['certificate_id']}")
    print(f"   Expires: {result['data']['expires_at']}")
else:
    print(f"❌ Error: {response.json()['detail']}")
```

---

### Example 2: Download Certificate and Key

```python
import requests

service_id = "my-service"
base_url = "https://localhost:8443/api/v1"

# Download certificate
cert_response = requests.get(
    f"{base_url}/certificates/{service_id}/download?file_type=cert",
    verify=False
)

with open("my_service_cert.pem", "wb") as f:
    f.write(cert_response.content)

# Download private key
key_response = requests.get(
    f"{base_url}/certificates/{service_id}/download?file_type=key",
    verify=False
)

with open("my_service_key.pem", "wb") as f:
    f.write(key_response.content)

# Download CA chain
ca_response = requests.get(
    f"{base_url}/certificates/{service_id}/download?file_type=ca",
    verify=False
)

with open("ca_chain.pem", "wb") as f:
    f.write(ca_response.content)

print("✅ Downloaded: cert, key, CA chain")
```

---

### Example 3: List Certificates Needing Renewal

```python
import requests

url = "https://localhost:8443/api/v1/certificates"
response = requests.get(url, verify=False)

if response.status_code == 200:
    data = response.json()
    
    # Filter certificates needing renewal
    expiring_soon = [
        cert for cert in data["certificates"]
        if cert["needs_renewal"]
    ]
    
    print(f"⚠️  {len(expiring_soon)} certificates need renewal:")
    for cert in expiring_soon:
        print(f"   - {cert['service_id']}: {cert['days_until_expiry']} days")
```

---

### Example 4: Register Service

```python
import requests

url = "https://localhost:8443/api/v1/services/register"

data = {
    "service_id": "my-service",
    "service_name": "My Awesome Service",
    "endpoints": [
        "https://localhost:8080/api"
    ],
    "metadata": {
        "version": "1.0.0",
        "team": "My Team"
    },
    "health_check_url": "https://localhost:8080/health"
}

response = requests.post(url, json=data, verify=False)

if response.status_code == 200:
    result = response.json()
    print(f"✅ Service registered: {result['data']['service_id']}")
```

---

## ⚠️ Error Handling

### Standard Error Response

```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Request succeeded |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Missing or invalid authentication |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server-side error |

### Common Error Scenarios

#### 1. Invalid Service ID Format

```json
{
  "detail": [
    {
      "loc": ["body", "service_id"],
      "msg": "service_id must contain only lowercase letters, numbers, and hyphens",
      "type": "value_error"
    }
  ]
}
```

#### 2. Certificate Not Found

```json
{
  "detail": "Certificate not found for service: unknown-service"
}
```

#### 3. CA Password Required

```json
{
  "detail": "Intermediate CA private key is encrypted. Provide password via X-CA-Password header"
}
```

---

## 🚦 Rate Limiting

**Current Limits:**
- 60 requests per minute per IP
- Burst: 10 requests

**Rate Limit Headers:**
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 55
X-RateLimit-Reset: 1634139600
```

**Rate Limit Exceeded Response:**
```json
{
  "detail": "Rate limit exceeded. Try again in 30 seconds."
}
```

---

## ✅ Best Practices

### 1. Certificate Management

**DO:**
- ✅ Request certificates with proper SANs (DNS + IP)
- ✅ Renew certificates 30 days before expiry
- ✅ Store private keys securely (encrypted, 0400 permissions)
- ✅ Use CA chain for client SSL context
- ✅ Implement automatic renewal

**DON'T:**
- ❌ Hardcode CA passwords in code
- ❌ Share private keys between services
- ❌ Use wildcard certificates for individual services
- ❌ Ignore certificate expiry warnings

---

### 2. API Integration

**DO:**
- ✅ Use HTTPS (never HTTP in production)
- ✅ Implement retry logic with exponential backoff
- ✅ Cache CA certificates locally
- ✅ Verify server certificate in production
- ✅ Log all certificate operations for audit

**DON'T:**
- ❌ Disable SSL verification (`verify=False`) in production
- ❌ Store API credentials in code
- ❌ Make synchronous API calls in hot paths
- ❌ Ignore error responses

---

### 3. Service Registration

**DO:**
- ✅ Register services on startup
- ✅ Provide accurate health check URLs
- ✅ Include version in metadata
- ✅ Update endpoints when they change

**DON'T:**
- ❌ Register duplicate services
- ❌ Use generic service IDs
- ❌ Forget to update service metadata

---

### 4. Security

**DO:**
- ✅ Use mTLS for production authentication
- ✅ Rotate certificates regularly
- ✅ Monitor certificate expiry
- ✅ Implement proper access controls
- ✅ Use secure password storage (Azure Key Vault, AWS Secrets Manager)

**DON'T:**
- ❌ Use bearer token auth in production
- ❌ Expose private keys via API
- ❌ Allow unauthenticated certificate issuance
- ❌ Store CA passwords in environment variables (use secure vault!)

---

## 🔗 Additional Resources

- **Architecture**: `docs/PKI_SERVER_ARCHITECTURE.md`
- **Implementation Status**: `docs/IMPLEMENTATION_STATUS.md`
- **Service Integration**: `docs/SERVICE_INTEGRATION_QUICK_GUIDE.md`
- **mTLS Setup**: `C:\VCC\veritas\docs\MTLS_SESSION_SUMMARY.md`

---

## 📞 Support

- **PKI Server Logs**: `C:\VCC\PKI\logs\pki_server.log`
- **Audit Logs**: `C:\VCC\PKI\logs\audit.log`
- **API Documentation**: `https://localhost:8443/api/docs` (Swagger UI)

---

**Last Updated:** 2025-10-13  
**Version:** 1.0.0
