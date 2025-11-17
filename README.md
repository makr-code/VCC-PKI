# VCC-PKI - Public Key Infrastructure System

Vollständiges PKI-System für das VCC-Projekt mit Certificate Authority, Code-Signing und Service-Zertifikaten.

## 📋 Übersicht

**Zweck:** Zentrale PKI-Infrastruktur für sichere Kommunikation und Code-Signierung

**Technologie-Stack:**
Python, FastAPI, cryptography, SQLite, Docker

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

- [ROADMAP.md](ROADMAP.md) - Entwicklungsplan
- [DEVELOPMENT.md](DEVELOPMENT.md) - Entwickler-Guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Beitragsrichtlinien
- [docs/](docs/) - Detaillierte Dokumentation
  - [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md)
  - [CODE_SIGNING.md](docs/CODE_SIGNING.md)
  - [PKI_ADMIN_CLI.md](docs/PKI_ADMIN_CLI.md)
  - [PRE_COMMIT_HOOK_GUIDE.md](docs/PRE_COMMIT_HOOK_GUIDE.md)

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

---

*Letzte Aktualisierung: 17.11.2025*
