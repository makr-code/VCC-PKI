# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Security - 2025-12-16
#### 🔒 Kritische Sicherheitsverbesserungen
- **KRITISCH**: Hardcodiertes Passwort-Fallback in `pki_server.py` entfernt
  - `get_ca_password()` erfordert nun zwingend die Umgebungsvariable `VCC_INTERMEDIATE_CA_PASSWORD`
  - Klare Fehlermeldung mit Hinweis auf sichere Secret-Management-Systeme
- **HOCH**: Sicherheits-Header zu FastAPI-Anwendung hinzugefügt
  - X-Content-Type-Options, X-Frame-Options, HSTS, CSP
  - Server-Identifikations-Header entfernt
- **HOCH**: Audit-Logging mit automatischer Filterung sensibler Daten
  - Passwörter, Schlüssel, Tokens werden in Logs automatisch gefiltert
  - X-Forwarded-For Support für Proxy-Umgebungen

#### 🔐 Kryptografische Verbesserungen
- `generate_keypair()` in `crypto_utils.py` erweitert:
  - Optionaler `password` Parameter für verschlüsselte private Schlüssel
  - Warnung bei unverschlüsselten Schlüsseln (nur für Entwicklung)
  - Erweiterte Dokumentation mit Sicherheitshinweisen

#### 📋 Input-Validierung
- Umfassende Validierungsfunktionen für Zertifikatsparameter:
  - `validate_service_id()`: Service-ID Format (3-64 Zeichen, alphanumerisch)
  - `validate_common_name()`: Common Name (DNS-konform, max 253 Zeichen)
  - `validate_san_dns()`: DNS SANs (max 100, Wildcard-Support)
  - `validate_san_ip()`: IP SANs (IPv4/IPv6, max 100)
  - `validate_validity_days()`: Gültigkeit (1-730 Tage, CA/Browser Forum konform)
  - `validate_key_size()`: RSA Schlüsselgröße (2048/3072/4096 bits)

#### 📝 Dokumentation
- **Neu**: `SECURITY.md` - Umfassende Sicherheitsdokumentation
  - Meldung von Sicherheitslücken
  - Best Practices für Deployment
  - Kryptografische Standards
  - Schlüsselverwaltung
  - Compliance (DSGVO, BSI, EU AI Act)
  - Production Deployment Checklist
- **Neu**: `.env.example` - Template für Umgebungsvariablen
  - Sicherheitsanforderungen für Passwörter
  - Konfigurationsoptionen dokumentiert
  - Best Practices integriert

#### 🛡️ Infrastruktur
- `.gitignore` erweitert:
  - Alle privaten Schlüssel und Zertifikate ausgeschlossen
  - Secret-Dateien und Verzeichnisse ausgeschlossen
  - CA-Storage und Service-Zertifikate geschützt
- **Neu**: `scripts/security-check.sh` - Deployment Security Check
  - Automatische Überprüfung vor Production-Deployment
  - Prüfung auf hardcodierte Passwörter
  - Dateiberechtigungen-Validierung
  - Kryptografische Standards-Check
  - Dependency-Vulnerability-Scan

### Changed
- `get_ca_password()` Funktion mit strikter Validierung
- FastAPI Middleware für Security Headers
- Audit-Log Funktion mit Sensitive-Data-Filtering

### Added
- Validierungsfunktionen in `service_cert_manager.py`
- Security Headers Middleware in `pki_server.py`
- Deployment Security Checklist Script
- Umfassende Sicherheitsdokumentation

## [1.0.0] - 2025-10-13

### Added
- Initiales Release des VCC-PKI Systems
- Root CA und Intermediate CA Management
- Service-Zertifikat-Verwaltung
- OCSP Responder
- CRL Distribution Point
- Auto-Renewal Engine
- HSM Integration Support
- Timestamp Authority
- Certificate Templates
- Multi-Tenant Manager
- REST API mit FastAPI
- SQLite Datenbank
- Audit Logging
- Code Signing Funktionalität

### Security
- RSA 2048/4096 bit Schlüsselgenerierung
- SHA-256 Signatur-Algorithmus
- Verschlüsselte Schlüsselspeicherung (optional)

---

## Kategorien
- **Added**: Neue Features
- **Changed**: Änderungen an bestehender Funktionalität
- **Deprecated**: Bald zu entfernende Features
- **Removed**: Entfernte Features
- **Fixed**: Bugfixes
- **Security**: Sicherheitsrelevante Änderungen

[Unreleased]: https://github.com/makr-code/VCC-PKI/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/makr-code/VCC-PKI/releases/tag/v1.0.0
