# VCC-PKI - Public Key Infrastructure System

⚠️ **SICHERHEITSHINWEIS**: Dieses System verwaltet kryptografische Schlüssel und Zertifikate. Bitte lesen Sie [SECURITY.md](SECURITY.md) vor dem Deployment.

Vollständiges PKI-System für das VCC-Projekt mit Certificate Authority, Code-Signing und Service-Zertifikaten.

## 📋 Übersicht

**Zweck:** Zentrale PKI-Infrastruktur für sichere Kommunikation und Code-Signierung

**Technologie-Stack:**
Python, FastAPI, cryptography, SQLite, Docker

## ⚠️ Sicherheitsanforderungen

**Vor dem ersten Start:**

1. **Konfigurieren Sie sichere Passwörter:**
   ```bash
   cp .env.example .env
   # Bearbeiten Sie .env mit starken, einzigartigen Passwörtern
   chmod 600 .env
   ```

2. **Production-Deployment:**
   - Verwenden Sie einen Secret-Management-Service (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault)
   - Aktivieren Sie mTLS für Service-to-Service Kommunikation
   - Setzen Sie restriktive Dateiberechtigungen (chmod 400 für Keys)
   - Lesen Sie die [Production Deployment Checklist](SECURITY.md#deployment-security)

3. **Security Check vor Deployment:**
   ```bash
   ./scripts/security-check.sh
   ```

Weitere Details: [SECURITY.md](SECURITY.md)

## ✨ Hauptfunktionen

- Certificate Authority (CA) Management
- Service-Zertifikate für VCC-Services
- Code-Signing für Python-Dateien
- Pre-Commit Hooks für automatische Signierung
- PKI Admin CLI
- GUI für Bulk-Signing
- Database-basiertes Zertifikats-Tracking

## 🚀 Schnellstart

### Server starten

```bash
# Alle Services starten
.\scripts\start_all.ps1

# Nur PKI-Server
.\scripts\start_pki_server.ps1

# Server-Status prüfen
.\scripts\status_server.ps1
```

### Admin CLI

```bash
# PKI Admin CLI starten
python pki_admin_cli.py

# Zertifikat erstellen
vcc-pki create-cert --service=my-service
```

### Code-Signing

```bash
# Einzelne Datei signieren
python examples/simple_signing.py

# Bulk-Signing GUI
python scripts/bulk_sign_gui.py
```

## 📚 Dokumentation

### Strategie & Architektur
- **[VCC-PKI Weiterentwicklungsstrategie](VCC_PKI_WEITERENTWICKLUNGSSTRATEGIE.md)** - Umfassende Entwicklungsstrategie 2026-2028
- **[Future Technical Architecture](docs/TECHNICAL_ARCHITECTURE_FUTURE.md)** - Detaillierte technische Architektur-Spezifikationen

### Projekt-Management
- [ROADMAP.md](ROADMAP.md) - Entwicklungsplan
- [PROJECT_STATUS.md](PROJECT_STATUS.md) - Aktueller Projektstatus
- [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) - Detaillierte Implementierungs-Roadmap

### Entwicklung & Integration
- [DEVELOPMENT.md](DEVELOPMENT.md) - Entwickler-Guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Beitragsrichtlinien
- [INTEGRATION_QUICK_START.md](INTEGRATION_QUICK_START.md) - Schnellstart für Service-Integration
- [SERVICE_INTEGRATION_TODO.md](SERVICE_INTEGRATION_TODO.md) - Service-Integrations-Checkliste

### Technische Dokumentation
- [docs/](docs/) - Detaillierte Dokumentation
  - [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md)
  - [CODE_SIGNING.md](docs/CODE_SIGNING.md)
  - [PKI_ADMIN_CLI.md](docs/PKI_ADMIN_CLI.md)
  - [PRE_COMMIT_HOOK_GUIDE.md](docs/PRE_COMMIT_HOOK_GUIDE.md)
  - [PKI_PROJECT_COMPLETE.md](docs/PKI_PROJECT_COMPLETE.md)

## 🔐 CA-Hierarchie

```
Root CA
└── Intermediate CA
    ├── Service Certificates
    │   ├── covina-backend
    │   ├── covina-ingestion
    │   ├── veritas-backend
    │   └── pki-server
    └── Code Signing Certificates
```

## 🛠️ Komponenten

### PKI Server
- FastAPI-basierter REST-API Server
- Port: 8443 (HTTPS)
- Datenbank: SQLite

### CA Manager
- Root CA und Intermediate CA
- Zertifikatserstellung und -verwaltung

### Service Certificate Manager
- Service-spezifische Zertifikate
- Automatische Erneuerung

### Code Signing
- Python-Code-Signierung
- Batch-Signierung
- Pre-Commit Hook Integration

## 🔗 Verwandte Repositories

Teil des [VCC-Projekts](https://github.com/makr-code/VCC)

## 📄 Lizenz

Private Repository - Alle Rechte vorbehalten

## 👤 Autor

**makr-code** - [GitHub](https://github.com/makr-code)

## 🎯 Zukunftsvision

VCC-PKI entwickelt sich zu einer **Enterprise-Grade PKI-Infrastruktur** mit:

- ✅ **Digitale Souveränität** - On-Premise-Betrieb, keine Vendor-Abhängigkeiten
- ✅ **Vollautomatisierung** - 100% automatisches Certificate Lifecycle Management
- ✅ **Multi-Organization Support** - Skalierbar für Brandenburg + Partner-Verwaltungen
- ✅ **On-Premise Kubernetes** - Kubernetes-ready für eigene Infrastruktur
- ✅ **HSM-Integration** - Hardware-basierte Schlüsselsicherheit (on-premise)
- ✅ **Compliance-Excellence** - DSGVO, EU AI Act, BSI Standards
- ✅ **Zero-Trust Architecture** - mTLS für alle VCC-Services

Mehr Details in der [Weiterentwicklungsstrategie](VCC_PKI_WEITERENTWICKLUNGSSTRATEGIE.md).

## 🔒 Sicherheit

### Kritische Sicherheitshinweise

1. **Niemals** Passwörter hardcodieren oder commiten
2. **Immer** private Schlüssel verschlüsseln (minimum 16-Zeichen Passwort)
3. **Immer** restriktive Dateiberechtigungen setzen (chmod 400 für Keys)
4. In Production: Secret Management System verwenden (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault)
5. mTLS für alle Service-to-Service Kommunikation aktivieren

### Sicherheits-Check

```bash
# Vor jedem Deployment ausführen
./scripts/security-check.sh
```

### Passwort-Anforderungen

- Minimum 16 Zeichen
- Mix aus Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen
- Unterschiedliche Passwörter für Dev, Staging, Production
- Rotation alle 90 Tage

### Compliance

- **DSGVO**: Datenschutz-konform
- **BSI TR-02102**: Kryptografische Verfahren
- **CA/Browser Forum**: Baseline Requirements

Vollständige Sicherheitsdokumentation: [SECURITY.md](SECURITY.md)

## 📋 Änderungsprotokoll

Siehe [CHANGELOG.md](CHANGELOG.md) für alle Änderungen und Versionshinweise.

---

*Letzte Aktualisierung: 16.12.2025*
