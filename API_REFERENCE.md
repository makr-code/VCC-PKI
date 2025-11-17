# VCC PKI Server - API Reference

**Version:** 1.0.0  
**Base URL:** `https://localhost:8443`  
**Last Updated:** 17.11.2025

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Health & Info Endpoints](#health--info-endpoints)
4. [Certificate Management](#certificate-management)
5. [Service Management](#service-management)
6. [CA Operations](#ca-operations)
7. [CRL Operations](#crl-operations)
8. [Error Handling](#error-handling)
9. [Data Models](#data-models)

---

## Overview

The VCC PKI Server provides a REST API for managing certificates, services, and Certificate Authority operations within the VCC ecosystem.

**API Documentation:**
- Swagger UI: `https://localhost:8443/api/docs`
- ReDoc: `https://localhost:8443/api/redoc`
- OpenAPI JSON: `https://localhost:8443/api/openapi.json`

---

## Authentication

### Current Implementation

The API currently uses Bearer token authentication (development mode):

```bash
Authorization: Bearer <service-id>
```

### Production Recommendation

For production, implement mTLS (mutual TLS) authentication:
- Client certificate verification
- Service identity extracted from certificate CN
- Certificate validation against VCC CA

---

## Health & Info Endpoints

### GET /health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-17T10:30:00.000000",
  "version": "1.0.0"
}
```

**cURL Example:**
```bash
curl https://localhost:8443/health
```

---

### GET /api/v1/info

Get PKI server information and statistics.

**Response:**
```json
{
  "server": "VCC PKI Server",
  "version": "1.0.0",
  "ca_status": "operational",
  "total_services": 5,
  "total_certificates": 12
}
```

**cURL Example:**
```bash
curl https://localhost:8443/api/v1/info
```

---

## Certificate Management

### POST /api/v1/certificates/request

Request a new service certificate.

**Headers:**
- `X-CA-Password` (optional): CA password for signing

**Request Body:**
```json
{
  "service_id": "covina-backend",
  "common_name": "covina-backend.vcc.local",
  "san_dns": ["covina-backend", "localhost"],
  "san_ip": ["127.0.0.1"],
  "validity_days": 365
}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate issued successfully for covina-backend",
  "data": {
    "certificate_id": "cert_abc123...",
    "service_id": "covina-backend",
    "expires_at": "2026-11-17T10:30:00Z"
  }
}
```

**Validation Rules:**
- `service_id`: 3-64 chars, lowercase letters, numbers, hyphens only
- `common_name`: 3-64 chars
- `validity_days`: 1-730 days

**cURL Example:**
```bash
curl -X POST https://localhost:8443/api/v1/certificates/request \
  -H "Content-Type: application/json" \
  -H "X-CA-Password: your_ca_password" \
  -d '{
    "service_id": "my-service",
    "common_name": "my-service.vcc.local",
    "san_dns": ["my-service", "localhost"],
    "validity_days": 365
  }'
```

---

### GET /api/v1/certificates/{service_id}

Get certificate information for a specific service.

**Path Parameters:**
- `service_id`: Service identifier

**Response:**
```json
{
  "certificate_id": "cert_abc123...",
  "service_id": "covina-backend",
  "common_name": "covina-backend.vcc.local",
  "serial_number": "123456789",
  "fingerprint": "SHA256:abc123...",
  "not_before": "2025-11-17T10:30:00",
  "not_after": "2026-11-17T10:30:00",
  "status": "active",
  "san_dns": ["covina-backend", "localhost"],
  "san_ip": ["127.0.0.1"],
  "issuer": "VCC Intermediate CA",
  "days_until_expiry": 365
}
```

**Status Codes:**
- `200 OK`: Certificate found
- `404 Not Found`: No certificate for service

**cURL Example:**
```bash
curl https://localhost:8443/api/v1/certificates/my-service
```

---

### GET /api/v1/certificates/{service_id}/download

Download certificate files for a service.

**Path Parameters:**
- `service_id`: Service identifier

**Response:**
Returns a ZIP file containing:
- `cert.pem`: Service certificate
- `key.pem`: Private key
- `ca_bundle.pem`: CA certificate chain

**Content-Type:** `application/zip`

**cURL Example:**
```bash
curl -o certs.zip https://localhost:8443/api/v1/certificates/my-service/download
```

---

### POST /api/v1/certificates/{service_id}/renew

Renew an existing certificate.

**Path Parameters:**
- `service_id`: Service identifier

**Headers:**
- `X-CA-Password` (optional): CA password for signing

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
  "message": "Certificate renewed successfully for my-service",
  "data": {
    "certificate_id": "cert_new123...",
    "service_id": "my-service",
    "expires_at": "2026-11-17T10:30:00Z"
  }
}
```

**cURL Example:**
```bash
curl -X POST https://localhost:8443/api/v1/certificates/my-service/renew \
  -H "Content-Type: application/json" \
  -H "X-CA-Password: your_ca_password" \
  -d '{"validity_days": 365}'
```

---

### DELETE /api/v1/certificates/{service_id}/revoke

Revoke a certificate.

**Path Parameters:**
- `service_id`: Service identifier

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
  "message": "Certificate revoked successfully for my-service",
  "data": {
    "service_id": "my-service",
    "revoked_at": "2025-11-17T10:30:00Z",
    "reason": "key_compromise"
  }
}
```

**cURL Example:**
```bash
curl -X DELETE https://localhost:8443/api/v1/certificates/my-service/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "key_compromise"}'
```

---

### GET /api/v1/certificates

List all certificates.

**Query Parameters:**
- `status` (optional): Filter by status (`active`, `revoked`, `expired`)

**Response:**
```json
{
  "certificates": [
    {
      "certificate_id": "cert_abc123...",
      "service_id": "covina-backend",
      "common_name": "covina-backend.vcc.local",
      "status": "active",
      "not_after": "2026-11-17T10:30:00",
      "days_until_expiry": 365
    },
    {
      "certificate_id": "cert_def456...",
      "service_id": "veritas-backend",
      "common_name": "veritas-backend.vcc.local",
      "status": "active",
      "not_after": "2026-10-15T08:20:00",
      "days_until_expiry": 332
    }
  ],
  "total": 2
}
```

**cURL Example:**
```bash
curl https://localhost:8443/api/v1/certificates?status=active
```

---

## Service Management

### POST /api/v1/services/register

Register a new service in the PKI system.

**Request Body:**
```json
{
  "service_id": "my-service",
  "service_name": "My Service",
  "endpoints": ["https://my-service.vcc.local:8080"],
  "health_check_url": "https://my-service.vcc.local:8080/health",
  "metadata": {
    "department": "Engineering",
    "owner": "team@vcc.local"
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Service registered successfully",
  "data": {
    "service_id": "my-service",
    "registered_at": "2025-11-17T10:30:00Z"
  }
}
```

**cURL Example:**
```bash
curl -X POST https://localhost:8443/api/v1/services/register \
  -H "Content-Type: application/json" \
  -d '{
    "service_id": "my-service",
    "service_name": "My Service",
    "endpoints": ["https://my-service.vcc.local:8080"],
    "health_check_url": "https://my-service.vcc.local:8080/health"
  }'
```

---

### GET /api/v1/services

List all registered services.

**Query Parameters:**
- `status` (optional): Filter by certificate status

**Response:**
```json
{
  "services": [
    {
      "service_id": "covina-backend",
      "service_name": "Covina Backend",
      "certificate_status": "active",
      "certificate_expiry": "2026-11-17T10:30:00",
      "endpoints": ["https://covina.vcc.local:8001"],
      "health_status": "healthy"
    }
  ],
  "total": 1
}
```

**cURL Example:**
```bash
curl https://localhost:8443/api/v1/services
```

---

### GET /api/v1/services/{service_id}

Get detailed information about a specific service.

**Path Parameters:**
- `service_id`: Service identifier

**Response:**
```json
{
  "service_id": "my-service",
  "service_name": "My Service",
  "certificate_status": "active",
  "certificate_expiry": "2026-11-17T10:30:00",
  "endpoints": ["https://my-service.vcc.local:8080"],
  "health_check_url": "https://my-service.vcc.local:8080/health",
  "metadata": {
    "department": "Engineering",
    "owner": "team@vcc.local"
  },
  "registered_at": "2025-11-17T10:30:00"
}
```

**cURL Example:**
```bash
curl https://localhost:8443/api/v1/services/my-service
```

---

## CA Operations

### GET /api/v1/ca/root

Download Root CA certificate.

**Response:**
Returns Root CA certificate in PEM format.

**Content-Type:** `application/x-pem-file`

**cURL Example:**
```bash
curl -o root_ca.pem https://localhost:8443/api/v1/ca/root
```

---

### GET /api/v1/ca/intermediate

Download Intermediate CA certificate.

**Response:**
Returns Intermediate CA certificate in PEM format.

**Content-Type:** `application/x-pem-file`

**cURL Example:**
```bash
curl -o intermediate_ca.pem https://localhost:8443/api/v1/ca/intermediate
```

---

### GET /api/v1/ca/chain

Download complete CA certificate chain.

**Response:**
Returns CA chain (Root + Intermediate) in PEM format.

**Content-Type:** `application/x-pem-file`

**cURL Example:**
```bash
curl -o ca_chain.pem https://localhost:8443/api/v1/ca/chain
```

---

## CRL Operations

### GET /api/v1/crl

Get Certificate Revocation List.

**Response:**
Returns CRL in DER format (RFC 5280).

**Content-Type:** `application/pkix-crl`

**cURL Example:**
```bash
curl -o crl.der https://localhost:8443/api/v1/crl
```

**Convert DER to PEM:**
```bash
openssl crl -inform DER -in crl.der -outform PEM -out crl.pem
```

---

## Error Handling

All API endpoints follow consistent error response format:

### Error Response

```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| `200` | OK | Request successful |
| `201` | Created | Resource created successfully |
| `400` | Bad Request | Invalid request parameters |
| `401` | Unauthorized | Authentication required or failed |
| `404` | Not Found | Resource not found |
| `409` | Conflict | Resource already exists |
| `500` | Internal Server Error | Server error occurred |

### Example Error Response

```json
{
  "detail": "Certificate not found for service: unknown-service"
}
```

---

## Data Models

### CertificateRequestModel

```json
{
  "service_id": "string (3-64 chars, lowercase alphanumeric + hyphens)",
  "common_name": "string (3-64 chars)",
  "san_dns": ["string"],
  "san_ip": ["string"],
  "validity_days": "integer (1-730)"
}
```

### CertificateRenewalModel

```json
{
  "validity_days": "integer (1-730, default: 365)"
}
```

### CertificateRevocationModel

```json
{
  "reason": "enum (unspecified, key_compromise, ca_compromise, ...)"
}
```

### ServiceRegistrationModel

```json
{
  "service_id": "string (3-64 chars, lowercase alphanumeric + hyphens)",
  "service_name": "string (3-128 chars)",
  "endpoints": ["string"],
  "metadata": {"key": "value"},
  "health_check_url": "string (optional)"
}
```

### CertificateInfoResponse

```json
{
  "certificate_id": "string",
  "service_id": "string",
  "common_name": "string",
  "serial_number": "string",
  "fingerprint": "string",
  "not_before": "ISO 8601 datetime",
  "not_after": "ISO 8601 datetime",
  "status": "string (active, revoked, expired)",
  "san_dns": ["string"],
  "san_ip": ["string"],
  "issuer": "string",
  "days_until_expiry": "integer"
}
```

### ServiceInfoResponse

```json
{
  "service_id": "string",
  "service_name": "string",
  "certificate_status": "string",
  "certificate_expiry": "ISO 8601 datetime (nullable)",
  "endpoints": ["string"],
  "health_check_url": "string (nullable)",
  "metadata": {"key": "value"},
  "registered_at": "ISO 8601 datetime"
}
```

### APIResponse

```json
{
  "success": "boolean",
  "message": "string",
  "data": "object (nullable)"
}
```

---

## Integration Examples

### Python (using requests)

```python
import requests

# Disable SSL warnings for self-signed certs (dev only!)
import urllib3
urllib3.disable_warnings()

BASE_URL = "https://localhost:8443"
CA_PASSWORD = "your_ca_password"

# Request certificate
response = requests.post(
    f"{BASE_URL}/api/v1/certificates/request",
    json={
        "service_id": "my-service",
        "common_name": "my-service.vcc.local",
        "san_dns": ["my-service", "localhost"],
        "validity_days": 365
    },
    headers={"X-CA-Password": CA_PASSWORD},
    verify=False  # Dev only!
)

print(response.json())
```

### Python (using VCC PKI Client Library)

```python
from vcc_pki_client import PKIClient

# Initialize client
pki = PKIClient(
    pki_server_url="https://localhost:8443",
    service_id="my-service"
)

# Request certificate
pki.request_certificate(
    common_name="my-service.vcc.local",
    san_dns=["my-service", "localhost"]
)

# Enable auto-renewal
pki.enable_auto_renewal()

# Get SSL context for your app
ssl_context = pki.get_ssl_context()
```

### cURL (Bash)

```bash
#!/bin/bash

BASE_URL="https://localhost:8443"
CA_PASSWORD="your_ca_password"

# Request certificate
curl -X POST "$BASE_URL/api/v1/certificates/request" \
  -H "Content-Type: application/json" \
  -H "X-CA-Password: $CA_PASSWORD" \
  -d '{
    "service_id": "my-service",
    "common_name": "my-service.vcc.local",
    "san_dns": ["my-service", "localhost"],
    "validity_days": 365
  }'

# Download certificate
curl -o certs.zip "$BASE_URL/api/v1/certificates/my-service/download"
```

### PowerShell

```powershell
$BaseUrl = "https://localhost:8443"
$CaPassword = "your_ca_password"

# Disable SSL verification (dev only!)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Request certificate
$body = @{
    service_id = "my-service"
    common_name = "my-service.vcc.local"
    san_dns = @("my-service", "localhost")
    validity_days = 365
} | ConvertTo-Json

Invoke-RestMethod -Uri "$BaseUrl/api/v1/certificates/request" `
    -Method POST `
    -ContentType "application/json" `
    -Headers @{"X-CA-Password" = $CaPassword} `
    -Body $body
```

---

## Rate Limiting

Currently, no rate limiting is implemented. For production deployment, consider implementing:

- Per-service rate limits (e.g., 100 requests/hour)
- Per-IP rate limits (e.g., 1000 requests/hour)
- Redis-backed rate limiting for distributed systems

---

## Monitoring & Observability

### Health Check

Use `/health` endpoint for:
- Kubernetes liveness probes
- Load balancer health checks
- Monitoring systems (Nagios, Prometheus, etc.)

### Metrics (Planned)

Future versions will expose Prometheus metrics at `/metrics`:
- Certificate issuance rate
- Certificate expiry distribution
- API request rate and latency
- Error rate

---

## Security Considerations

### Development vs. Production

**Current (Development):**
- Bearer token authentication (simplified)
- Self-signed certificates
- No rate limiting
- Password in header

**Recommended (Production):**
- mTLS client authentication
- Proper CA infrastructure
- Rate limiting enabled
- Secrets from vault (Azure Key Vault, AWS Secrets Manager)
- IP whitelisting for sensitive operations
- Comprehensive audit logging to SIEM

### Best Practices

1. **Never commit CA passwords or private keys**
2. **Use environment variables or secrets management**
3. **Implement proper mTLS authentication**
4. **Enable comprehensive audit logging**
5. **Monitor certificate expiry and renewal**
6. **Implement automated certificate rotation**

---

## Changelog

### v1.0.0 (Current)

- Initial API implementation
- Certificate lifecycle management
- Service registration
- CA certificate distribution
- CRL support
- SQLite database backend

### Planned for v1.1

- OCSP responder
- Automated certificate renewal
- API rate limiting
- Prometheus metrics
- Enhanced audit logging

---

## Support & Resources

- **Documentation:** `/docs` folder
- **Admin CLI:** `pki_admin_cli.py`
- **Client Library:** `client/` folder
- **Examples:** `examples/` folder

---

*Last Updated: 17.11.2025*
