# VCC PKI - Public Key Infrastructure Library

PKI/CA Library für das Covina Framework - Certificate Management, Document Signing, Code Verification.

## 🎯 Features

- ✅ **Certificate Authority (CA) Management** - Root & Intermediate CA
- ✅ **Document Signing & Verification** - PKCS#7, PDF, XML, JWS
- ✅ **Code Signing** - Worker Verification für Covina
- ✅ **Mock-Implementierungen** - Testing ohne echte Kryptographie
- ✅ **Sigstore & TUF Integration** - Modern Security Frameworks
- ✅ **CLI & REST API** - Flexible Verwaltung
- ✅ **Production-Ready** - HSM Support, Monitoring, Compliance

## 📦 Installation

### Development Mode (Empfohlen für Covina Integration)

```bash
# PKI Package installieren
cd C:\VCC\PKI
pip install -e .

# In Covina verwenden
cd C:\VCC\Covina
# requirements.txt: -e C:\VCC\PKI
pip install -r requirements.txt
```

### Production Installation

```bash
pip install vcc-pki
```

### Requirements

- Python >= 3.10
- cryptography >= 41.0.0
- sigstore >= 2.0.0
- tuf >= 3.0.0
- click >= 8.1.0

## 🚀 Quick Start

### CLI Usage

```bash
# Certificate erstellen
vcc-pki create-cert --common-name test.covina.local --output cert.json

# Dokument signieren
vcc-pki sign --document file.txt --cert cert.json --output signature.json

# Signatur verifizieren
vcc-pki verify --document file.txt --signature signature.json --cert cert.json
```

### Python API

```python
from vcc_pki.api import PKIService

# Mock-Modus für Testing
pki = PKIService(mode="mock")

# Zertifikat erstellen
cert = pki.create_certificate(
    common_name="test.covina.local",
    organization="Covina",
    validity_days=365
)

# Dokument signieren
signature = pki.sign_document(
    document_path="document.pdf",
    certificate=cert["certificate"],
    private_key=cert["private_key"]
)

# Verifizieren
is_valid = pki.verify_document(
    document_path="document.pdf",
    signature=signature,
    certificate=cert["certificate"]
)

print(f"Signature valid: {is_valid}")
```

### Covina Integration

```python
from vcc_pki.api import PKIService
from integrations.pki_integration import CovinaPKIIntegration

# PKI Integration Layer
pki_integration = CovinaPKIIntegration(mode="mock")

# Dokument nach Ingestion signieren
result = pki_integration.sign_ingested_document(
    document_id="12345",
    document_path=Path("ingested_doc.pdf"),
    signer_cert=cert_data,
    signer_key=key_data
)

# Signature Metadata speichern
signature_store.store_signature(result)
```

## 📁 Package Structure

```
vcc_pki/
├── __init__.py              # Package Exports
├── __version__.py           # Version Info
├── ca/                      # Certificate Authority
│   ├── base_ca.py          # Abstract Base Class
│   ├── root_ca.py          # Root CA Implementation
│   └── ...
├── signing/                 # Signing Services
│   ├── base_signer.py      # Abstract Base Class
│   ├── document_signer.py  # Document Signing
│   └── ...
├── mock/                    # Mock Implementations (Testing)
│   ├── mock_ca.py          # Mock CA
│   ├── mock_signer.py      # Mock Signer
│   └── ...
├── api/                     # API Layer
│   ├── pki_service.py      # Unified PKI Service
│   ├── cli.py              # CLI Interface
│   └── ...
└── utils/                   # Utilities
    └── crypto_utils.py     # Cryptographic Helpers
```

## 🧪 Testing

```bash
# Alle Tests ausführen
pytest tests/ -v

# Mit Coverage
pytest tests/ --cov=vcc_pki --cov-report=html

# Einzelne Tests
pytest tests/test_ca.py -v
pytest tests/test_signing.py::test_sign_document -v
```

## 📖 Documentation

- [PKI Architecture](docs/PKI_ARCHITECTURE.md) - System Overview
- [CA Setup Guide](docs/CA_SETUP_GUIDE.md) - Certificate Authority Setup
- [API Reference](docs/API_REFERENCE.md) - Complete API Documentation
- [Integration Guide](docs/INTEGRATION_GUIDE.md) - Covina Integration
- [TODO Implementation](../Covina/docs/TODO_PKI_CA_IMPLEMENTATION.md) - Roadmap

## 🔐 Security

- **Mock Mode:** Für Testing ohne echte Kryptographie
- **Real Mode:** Produktionsreife X.509 Implementierung (Phase 4)
- **HSM Support:** Hardware Security Module Integration (PKCS#11)
- **Compliance:** Sigstore, TUF, Zero-Trust Architecture

## 🤝 Integration with Covina

Das VCC PKI Package ist speziell für die Integration mit dem Covina Framework entwickelt:

1. **Document Signing:** Automatische Signierung nach Ingestion
2. **Code Verification:** Worker Code Validation vor Ausführung
3. **Signature Storage:** PostgreSQL Metadata Storage
4. **API Endpoints:** Backend Integration für Verification

Siehe [Integration Guide](docs/INTEGRATION_GUIDE.md) für Details.

## 📝 Development Status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ In Progress | Mock Implementation & Package Setup |
| Phase 2 | ⏳ Planned | Testing & Validation |
| Phase 3 | ⏳ Planned | Documentation |
| Phase 4 | ⏳ Planned | Real Cryptography (X.509, PKCS#7) |
| Phase 5 | ⏳ Planned | Covina Integration |
| Phase 6 | ⏳ Planned | Production Readiness |

## 🛠️ CLI Commands Reference

```bash
# Certificate Management
vcc-pki create-cert --common-name <name> --output <file>
vcc-pki list-certs
vcc-pki revoke-cert --serial <serial>

# Document Signing
vcc-pki sign --document <file> --cert <cert> --output <sig>
vcc-pki verify --document <file> --signature <sig> --cert <cert>

# System Information
vcc-pki version
vcc-pki status
```

## 📄 License

MIT License - See LICENSE file for details.

## 👥 Authors

VCC Team - Covina Framework Development

## 🔗 Related Projects

- **Covina:** Document Processing & Knowledge Management
- **Veritas:** Document Verification System
- **Clara:** AI-Powered Analysis
- **VCC PKI System:** Production PKI Implementation (siehe `vcc-pki-system/`)

---

**Note:** Dieses Package befindet sich in aktiver Entwicklung (Phase 1). 
Für produktionsreife PKI siehe `vcc-pki-system/` Verzeichnis.
