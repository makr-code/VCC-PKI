# VCC-PKI - Roadmap

## 🎯 Vision

Sichere, skalierbare PKI-Infrastruktur für alle VCC-Services mit vollständiger Zertifikatsverwaltung und Code-Signierung.

## 📅 Releases

### Version 1.0 (Aktuell)
- ✅ Root CA und Intermediate CA
- ✅ Service-Zertifikate für Covina, Veritas, PKI-Server
- ✅ Code-Signing-Funktionalität
- ✅ PKI Admin CLI
- ✅ Pre-Commit Hooks
- ✅ SQLite-basierte Datenbank
- ✅ REST API Server

### Version 1.1 (Geplant - Q1 2026)
- 🔄 Automatische Zertifikatserneuerung
- 🔄 OCSP (Online Certificate Status Protocol)
- 🔄 CRL (Certificate Revocation List) Support
- 🔄 Monitoring und Alerting
- 🔄 Backup und Recovery Automatisierung

### Version 1.2 (In Planung - Q2 2026)
- 📋 HSM (Hardware Security Module) Integration
- 📋 Multi-Tenant Support
- 📋 Certificate Templates
- 📋 Audit Logging erweitern
- 📋 Web-basiertes Admin Dashboard

### Version 2.0 (Zukunft - Q3-Q4 2026)
- 🚀 Kubernetes Integration
- 🚀 High Availability Setup
- 🚀 External CA Integration (Let's Encrypt)
- 🚀 SCEP (Simple Certificate Enrollment Protocol)
- 🚀 EST (Enrollment over Secure Transport)

## 🎨 Geplante Features

### Kurzfristig (1-3 Monate)
- [ ] Certificate Renewal Automation
- [ ] OCSP Responder implementieren
- [ ] CRL Generation
- [ ] Health Check Endpoints erweitern
- [ ] Prometheus Metrics Integration

### Mittelfristig (3-6 Monate)
- [ ] HSM Support (SoftHSM für Testing)
- [ ] Certificate Policy Framework
- [ ] Key Escrow System
- [ ] Certificate Transparency Logging
- [ ] Rate Limiting für API

### Langfristig (6-12 Monate)
- [ ] Cloud HSM Integration (Azure Key Vault, AWS KMS)
- [ ] Multi-CA Support
- [ ] Certificate Lifecycle Management Dashboard
- [ ] Compliance Reporting (SOC 2, ISO 27001)
- [ ] Mobile App für Admin-Funktionen

## 🐛 Bekannte Probleme

- Certificate Rotation noch manuell
- Keine automatische Backup-Strategie
- OCSP noch nicht implementiert
- Limited Logging für Audit Trail

## 💡 Feature-Requests

Feature-Anfragen bitte als Issue erstellen mit dem Label `enhancement`.

---

*Letzte Aktualisierung: 17.11.2025*
