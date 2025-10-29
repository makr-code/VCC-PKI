# VCC PKI System - Documentation
# Complete implementation guide for production deployment

## System Overview

The VCC PKI System is a production-ready Public Key Infrastructure solution specifically designed for the Brandenburg Government's digital sovereignty requirements. The system provides comprehensive certificate lifecycle management, code signing capabilities, and Zero-Trust security compliance for the VCC (Veritas-Covina-Clara) ecosystem.

## Architecture

### Core Components

1. **FastAPI Backend** (`app/main.py`)
   - Production-ready REST API server
   - Comprehensive endpoint coverage
   - Built-in security middleware
   - Health monitoring and audit logging

2. **Database Layer** (`app/core/database.py`)
   - SQLite with SQLCipher encryption
   - Complete VCC service registry
   - Audit trail functionality
   - Multi-tenant architecture support

3. **Cryptographic Services** (`app/services/crypto_service.py`)
   - X.509 certificate operations
   - RSA-PSS signature algorithms
   - CA hierarchy management
   - HSM integration ready

4. **Business Logic** (`app/services/pki_service.py`)
   - Certificate lifecycle orchestration
   - VCC service auto-provisioning
   - Code signing workflows
   - Health monitoring integration

5. **CLI Management Tool** (`vcc-pki-cli.py`)
   - Complete administrative interface
   - Certificate management operations
   - System status monitoring
   - Audit trail access

## Quick Start Guide

### Windows Setup

```batch
# 1. Run automated setup
setup.bat

# 2. Start development server
start-dev.bat

# 3. Access API documentation
# Browser: http://localhost:12091/docs
```

### Linux/Unix Setup

```bash
# 1. Make setup script executable
chmod +x setup.sh

# 2. Run automated setup
./setup.sh

# 3. Start development server
./start-dev.sh

# 4. Access API documentation
# Browser: http://localhost:12091/docs
```

## API Endpoints

### Core System
- `GET /health` - Basic health check
- `GET /status` - Comprehensive system status
- `GET /api/v1/audit/events` - Audit trail access

### Organization Management
- `POST /api/v1/organizations` - Create organization
- `GET /api/v1/organizations` - List organizations

### VCC Service Management
- `GET /api/v1/services` - List VCC services
- `POST /api/v1/services` - Register new service
- `GET /api/v1/mock/vcc-services/{service_id}/health` - Mock health endpoints

### Certificate Authority
- `GET /api/v1/ca/list` - List certificate authorities
- `POST /api/v1/ca/create-issuing-ca` - Create issuing CA
- `GET /api/v1/crl/{ca_id}` - Certificate Revocation List

### Certificate Management
- `POST /api/v1/certs/request` - Request new certificate
- `GET /api/v1/certs/list` - List certificates
- `GET /api/v1/certs/status/{cert_id}` - Certificate status
- `POST /api/v1/certs/revoke/{cert_id}` - Revoke certificate

### Code Signing
- `POST /api/v1/sign/python-package` - Sign Python package
- `POST /api/v1/verify/signature` - Verify code signature
- `GET /api/v1/sign/audit/{signature_id}` - Signature audit trail

## CLI Usage Examples

### System Status
```bash
# Check overall system health
vcc-pki status

# Initialize CLI configuration
vcc-pki init
```

### Organization Management
```bash
# List all organizations
vcc-pki org list

# Create new organization
vcc-pki org create --org-id "new-dept" --name "New Department" --admin "admin@dept.gov"
```

### Service Management
```bash
# List VCC services
vcc-pki service list --org brandenburg-gov

# Register new service
vcc-pki service register \
  --service-id "new-service" \
  --name "New Service" \
  --type "web-service" \
  --endpoint "https://new-service.brandenburg.de"
```

### Certificate Operations
```bash
# List certificates
vcc-pki cert list --org brandenburg-gov

# Request service certificate
vcc-pki cert request --type vcc_service --service-id argus

# Request code signing certificate
vcc-pki cert request --type code_signing --signer-name "Developer Name"

# Check certificate status
vcc-pki cert status <certificate-id>

# Revoke certificate
vcc-pki cert revoke <certificate-id> --reason "key-compromise"
```

### Code Signing
```bash
# Sign Python package
vcc-pki sign python-package \
  --cert-id <certificate-id> \
  --package-path ./my-package/

# View signature audit
vcc-pki audit events --category code_signing --limit 50
```

## Configuration

### Development Environment
Configuration file: `config/development.env`

```env
VCC_PKI_ENVIRONMENT=development
VCC_PKI_DEBUG=true
VCC_PKI_MOCK_MODE=true
VCC_PKI_API_HOST=127.0.0.1
VCC_PKI_API_PORT=12091
VCC_PKI_DATABASE_PATH=./data/vcc-pki-dev.db
VCC_PKI_LOG_LEVEL=DEBUG
```

### Production Environment
Configuration file: `config/production.env`

```env
VCC_PKI_ENVIRONMENT=production
VCC_PKI_DEBUG=false
VCC_PKI_MOCK_MODE=false
VCC_PKI_API_HOST=0.0.0.0
VCC_PKI_API_PORT=12091
VCC_PKI_API_WORKERS=4
VCC_PKI_DATABASE_PATH=/var/lib/vcc-pki/vcc-pki.db
VCC_PKI_DATABASE_ENCRYPTION_KEY=<secure-key>
VCC_PKI_LOG_LEVEL=INFO
VCC_PKI_HSM_ENABLED=true
VCC_PKI_KEYCLOAK_URL=https://keycloak.brandenburg.de
```

## Security Features

### Authentication & Authorization
- Mock authentication for development
- Keycloak integration for production
- Role-based access control (RBAC)
- API token authentication

### Encryption & Cryptography
- Database encryption with SQLCipher
- RSA-PSS signature algorithms
- X.509 certificate standards
- HSM integration support

### Audit & Compliance
- Comprehensive audit logging
- GDPR compliance features
- Event tracking and analysis
- Regulatory reporting capabilities

## VCC Service Integration

### Supported Services
- **Argus**: Identity and access management
- **Covina**: Document management system  
- **Clara**: AI/ML processing platform
- **Veritas**: Blockchain verification service
- **VPB**: Virtual private blockchain

### Auto-Provisioning
The system automatically provisions certificates for registered VCC services:

```python
# Service registration triggers certificate issuance
{
  "service_id": "argus",
  "service_name": "Argus Identity Service",
  "endpoint_url": "https://argus.brandenburg.de",
  "auto_cert_renewal": true
}
```

### Health Monitoring
Built-in health check integration for all VCC services:

```bash
# System monitors service health automatically
GET /api/v1/services -> Shows health status for each service
```

## Deployment Options

### Docker Deployment
```bash
# Build container
docker build -t vcc-pki-system .

# Run with environment config
docker run -d \
  -p 12091:12091 \
  -v ./config:/app/config \
  -v ./data:/app/data \
  --env-file config/production.env \
  vcc-pki-system
```

### Systemd Service (Linux)
```bash
# Install service (generated by setup.sh)
sudo cp vcc-pki.service /etc/systemd/system/
sudo systemctl enable vcc-pki
sudo systemctl start vcc-pki

# Check status
sudo systemctl status vcc-pki
```

### Windows Service
```batch
# Install as Windows Service (requires additional tooling)
# Use NSSM or similar service wrapper
nssm install VCCPKISystem python.exe
nssm set VCCPKISystem Parameters "-m uvicorn app.main:app --host 0.0.0.0 --port 12091"
nssm set VCCPKISystem AppDirectory C:\VCC\PKI\vcc-pki-system
```

## Development Workflow

### Project Structure
```
vcc-pki-system/
├── app/
│   ├── core/
│   │   ├── config.py          # Configuration management
│   │   └── database.py        # Database layer
│   ├── services/
│   │   ├── crypto_service.py  # Cryptographic operations
│   │   └── pki_service.py     # Business logic
│   ├── models/
│   │   └── __init__.py        # Pydantic models
│   └── main.py                # FastAPI application
├── config/                    # Configuration files
├── data/                      # Database storage
├── logs/                      # Application logs
├── vcc-pki-cli.py            # CLI management tool
├── setup.sh / setup.bat       # Automated setup
└── start-dev.sh / start-dev.bat # Development server
```

### Mock vs Production Mode

**Mock Mode** (Development):
- Uses simplified authentication
- Generates test certificates
- Simulates VCC service health
- Includes debug endpoints
- No HSM requirements

**Production Mode**:
- Full Keycloak integration
- HSM-backed certificate storage
- Real VCC service integration
- Comprehensive audit logging
- Enhanced security measures

### Testing

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=app

# Run specific test categories
python -m pytest tests/test_crypto.py
python -m pytest tests/test_api.py
```

## Monitoring & Maintenance

### Health Endpoints
- `/health` - Basic availability check
- `/status` - Detailed system health with VCC service status
- Prometheus metrics (when enabled)

### Log Management
```bash
# View real-time logs (Linux)
tail -f logs/vcc-pki.log

# View logs with filtering
grep "ERROR" logs/vcc-pki.log | tail -20
```

### Database Maintenance
```bash
# Backup database
vcc-pki backup create --output ./backups/

# Database statistics
vcc-pki admin db-stats

# Certificate expiry report
vcc-pki admin expiry-report --days 30
```

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   ```bash
   # Check database file permissions
   ls -la data/vcc-pki-*.db
   
   # Reinitialize if corrupted
   rm data/vcc-pki-dev.db
   python -c "from app.core.database import VCCPKIDatabase; VCCPKIDatabase('./data/vcc-pki-dev.db', 'dev-key')"
   ```

2. **Certificate Generation Failures**
   ```bash
   # Check cryptographic service status
   vcc-pki status
   
   # Test certificate creation
   vcc-pki cert request --type code_signing --signer-name "Test User"
   ```

3. **API Server Won't Start**
   ```bash
   # Check port availability
   netstat -an | grep :12091
   
   # Check configuration
   python -c "from app.core.config import create_config; print(create_config().dict())"
   ```

### Debug Mode
```bash
# Enable debug logging
export VCC_PKI_LOG_LEVEL=DEBUG

# Run with verbose output
python -m uvicorn app.main:app --host 127.0.0.1 --port 12091 --log-level debug
```

## Production Checklist

### Security Hardening
- [ ] Change default database encryption key
- [ ] Configure Keycloak authentication
- [ ] Enable HTTPS with proper certificates
- [ ] Set up HSM integration
- [ ] Configure firewall rules
- [ ] Enable audit logging to secure location

### Performance Optimization
- [ ] Configure multiple workers for production
- [ ] Set up database connection pooling
- [ ] Enable caching where appropriate
- [ ] Configure load balancer if needed

### Backup & Recovery
- [ ] Automated database backups
- [ ] Certificate store backups
- [ ] Configuration backups
- [ ] Test recovery procedures

### Monitoring
- [ ] Health check endpoints monitored
- [ ] Log aggregation configured
- [ ] Alerting on certificate expiry
- [ ] Performance metrics collection

## Support & Documentation

### Additional Resources
- API Documentation: http://localhost:12091/docs
- Implementation Roadmap: `IMPLEMENTATION_ROADMAP.md`
- VCC Integration Examples: `VCC_SERVICE_INTEGRATION_EXAMPLES.md`
- Architecture Documentation: `/docs/architecture.md`

### Contact Information
For technical support and questions:
- System Administrator: vcc-pki-admin@brandenburg.de
- Development Team: vcc-dev-team@brandenburg.de
- Security Team: vcc-security@brandenburg.de

---

*This documentation is part of the Brandenburg Government's digital sovereignty initiative and implements Zero-Trust security principles for the VCC ecosystem.*