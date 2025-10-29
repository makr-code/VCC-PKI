# VCC PKI - Legacy Files Audit Report

**Datum:** 13. Oktober 2025  
**Status:** Projekt-Bereinigung nach Neustrukturierung

---

## 🎯 Executive Summary

Das PKI-Projekt wurde komplett neu strukturiert. Folgende Legacy-Komponenten wurden identifiziert und können bereinigt werden:

### ⚠️ **KRITISCHE DUPLIKATE GEFUNDEN:**

1. **`vcc-pki-system/`** - Altes vollständiges PKI-System (12091 Port, click-basierte CLI)
2. **`vcc_pki/`** - Alte Package-Struktur (Legacy Library)
3. **Alte CLI-Tools** - Mehrere veraltete Admin-Scripts

**Empfehlung:** Archivierung oder Löschung nach Backup

---

## 📁 Legacy-Dateien Übersicht

### 1. **ALTES PKI-SYSTEM** ⚠️ **KRITISCH**

**Verzeichnis:** `C:\VCC\PKI\vcc-pki-system\`

**Status:** Vollständiges Legacy-System, komplett ersetzt durch neue Architektur

**Inhalt:**
```
vcc-pki-system/
├── app/                          # Alte FastAPI App (Port 12091)
├── config/                       # Alte Konfiguration
├── data/                         # Alte Datenbank
├── production/                   # Alte Production-Scripts
├── backups/                      # Alte Backups
├── vcc-pki-cli.py               # Alte CLI (click-basiert, 608 Zeilen)
├── vcc-pki-admin.ps1            # Alte PowerShell Admin
├── vcc-admin-simple.ps1         # Alte einfache Admin
├── vcc-pki-backup.py            # Altes Backup-Script
├── vcc-pki-monitor.py           # Altes Monitoring
├── vcc-tsa-cli.py               # Alter TSA-Client
├── vcc_pki_dashboard.py         # Altes Dashboard
├── simple_dashboard.py          # Einfaches Dashboard
├── start_dashboard.py           # Dashboard-Starter
├── setup.bat                    # Altes Setup
├── setup.sh                     # Altes Setup (Linux)
├── start-dev.bat                # Alter Dev-Starter
├── start_dashboard.bat          # Dashboard-Starter
└── *.md                         # Alte Dokumentation
```

**Unterschiede zum neuen System:**

| Feature | Alt (vcc-pki-system) | Neu (aktuell) |
|---------|---------------------|---------------|
| **Port** | 12091 | 8443 |
| **CLI Framework** | click | argparse |
| **CLI Datei** | `vcc-pki-cli.py` | `pki_admin_cli.py` |
| **CLI Größe** | 608 Zeilen | 950+ Zeilen |
| **Server** | `app/main.py` | `src/pki_server.py` |
| **GUI** | Dashboard (Streamlit?) | Tkinter GUI |
| **Architektur** | Monolithisch | Modular (src/) |
| **Dokumentation** | ADVANCED_CLI_STATUS.md | PKI_PROJECT_COMPLETE.md |

**Verwendung:** ❌ **NICHT MEHR VERWENDET**

**Letzte Aktivität:**
- `certificate-expiry-report-20251002.json` (2. Oktober 2025)
- Logs: `vcc-pki-admin.log`

**Empfehlung:** ⚠️ **ARCHIVIEREN & LÖSCHEN**
```powershell
# Backup erstellen
Move-Item vcc-pki-system\ backups\vcc-pki-system-legacy-20251013\

# Oder komplett löschen nach Backup
# Remove-Item vcc-pki-system\ -Recurse -Force
```

---

### 2. **ALTE PACKAGE-STRUKTUR** ⚠️ **MEDIUM**

**Verzeichnis:** `C:\VCC\PKI\vcc_pki\`

**Status:** Alte Python-Package-Struktur, teilweise noch von setup.py referenziert

**Inhalt:**
```
vcc_pki/
├── api/                # Alte API-Module
├── ca/                 # Alte CA-Implementierung
├── keystore/           # Alter Keystore
├── mock/               # Mock-Implementierungen
├── signing/            # Alte Signing-Logik
├── trust/              # Trust-Management
├── utils/              # Utilities
├── __init__.py
├── __version__.py
└── __pycache__/
```

**Verwendung:** 
- `setup.py` referenziert noch `vcc_pki/__version__.py`
- Möglicherweise von alten Imports abhängig

**Problem:** 
- Duplikation mit `src/` Struktur
- Verwirrt Package-Installation

**Empfehlung:** 🔶 **PRÜFEN & ARCHIVIEREN**

**Aktion:**
1. Prüfen ob `vcc_pki/` noch irgendwo importiert wird
2. Migrieren zu `src/` Struktur
3. `setup.py` auf neue Struktur umstellen
4. Dann archivieren

```powershell
# Suche nach Imports
grep -r "from vcc_pki" .
grep -r "import vcc_pki" .

# Wenn keine Treffer, dann archivieren
Move-Item vcc_pki\ backups\vcc_pki-legacy-20251013\
```

---

### 3. **LEGACY BUILD-ARTEFAKTE** ⚠️ **LOW**

**Dateien:**
```
vcc_pki.egg-info/        # Alte Build-Metadaten (setuptools)
__pycache__/             # Python Bytecode Cache (überall)
```

**Status:** Automatisch generiert, können gelöscht werden

**Empfehlung:** ✅ **LÖSCHEN**

```powershell
# Egg-Info löschen
Remove-Item vcc_pki.egg-info\ -Recurse -Force

# Alle __pycache__ löschen
Get-ChildItem -Recurse -Filter __pycache__ | Remove-Item -Recurse -Force
```

---

### 4. **TEST-DATEIEN IM ROOT** ⚠️ **LOW**

**Dateien:**
```
test_cert.json          # Test-Zertifikat
test_document.txt       # Test-Dokument
test_signature.json     # Test-Signatur
```

**Status:** Test-Artefakte im Root-Verzeichnis

**Empfehlung:** 🔶 **VERSCHIEBEN nach tests/**

```powershell
Move-Item test_*.* tests\fixtures\
```

---

### 5. **ALTE SETUP-DATEIEN** ⚠️ **MEDIUM**

**Dateien:**
```
setup.py                # Legacy setuptools config
pyproject.toml          # Moderne Konfiguration (behalten!)
```

**Status:** 
- `setup.py` ist Legacy-Kompatibilität
- `pyproject.toml` ist modern (PEP 517/518)

**Problem:** `setup.py` referenziert noch `vcc_pki/__version__.py`

**Empfehlung:** 🔶 **setup.py AKTUALISIEREN oder LÖSCHEN**

**Option A:** setup.py auf neue Struktur umstellen
```python
# setup.py anpassen:
# vcc_pki/__version__.py → src/__version__.py
```

**Option B:** setup.py komplett entfernen (pyproject.toml reicht)
```powershell
# Modern Python braucht nur pyproject.toml
Remove-Item setup.py
```

---

### 6. **DOPPELTE DOKUMENTATION** ℹ️ **INFO**

**Alte Dokumentation (vcc-pki-system/):**
```
vcc-pki-system/ADVANCED_CLI_STATUS.md
vcc-pki-system/CERTIFICATE_LIFECYCLE_SPEC.md
vcc-pki-system/dashboard_README.md
vcc-pki-system/DASHBOARD_STATUS.md
vcc-pki-system/PRODUCTION_DEPLOYMENT_GUIDE.md
vcc-pki-system/README.md
vcc-pki-system/SECURITY_FRAMEWORK.md
vcc-pki-system/TSA_IMPLEMENTATION_SPEC.md
```

**Neue Dokumentation (docs/):**
```
docs/PKI_PROJECT_COMPLETE.md      (1,000+ Zeilen)
docs/PKI_ADMIN_CLI.md             (600+ Zeilen)
docs/PKI_ADMIN_CLI_COMPLETE.md    (700+ Zeilen)
PROJECT_STATUS.md                  (200+ Zeilen)
README.md                          (225 Zeilen)
SERVICE_INTEGRATION_TODO.md        (5,000+ Zeilen)
INTEGRATION_QUICK_START.md         (300+ Zeilen)
```

**Empfehlung:** ✅ **Alte Doku wird mit vcc-pki-system/ archiviert**

---

## 📊 Zusammenfassung

### Legacy-Dateien Statistik

| Kategorie | Dateien/Verzeichnisse | Größe (geschätzt) | Aktion |
|-----------|---------------------|-------------------|--------|
| **vcc-pki-system/** | 1 Verzeichnis, 50+ Dateien | ~5 MB | ⚠️ **ARCHIVIEREN & LÖSCHEN** |
| **vcc_pki/** | 1 Package, 20+ Dateien | ~500 KB | 🔶 **PRÜFEN & ARCHIVIEREN** |
| **Build-Artefakte** | egg-info, __pycache__ | ~2 MB | ✅ **LÖSCHEN** |
| **Test-Dateien (Root)** | 3 Dateien | ~10 KB | 🔶 **VERSCHIEBEN** |
| **setup.py** | 1 Datei | ~3 KB | 🔶 **AKTUALISIEREN/LÖSCHEN** |

**Gesamt geschätzter Speicherplatz:** ~7.5 MB

---

## 🚀 Bereinigungsplan

### Phase 1: Backup erstellen ⏱️ 5 Minuten

```powershell
# Backup-Verzeichnis erstellen
New-Item -ItemType Directory -Path backups\legacy-20251013 -Force

# Legacy-System archivieren
Move-Item vcc-pki-system\ backups\legacy-20251013\

# Alte Package-Struktur archivieren
Move-Item vcc_pki\ backups\legacy-20251013\

# Git-Commit vor Löschung
git add -A
git commit -m "backup: Archive legacy PKI system before cleanup"
```

### Phase 2: Build-Artefakte löschen ⏱️ 2 Minuten

```powershell
# Egg-Info löschen
Remove-Item vcc_pki.egg-info\ -Recurse -Force -ErrorAction SilentlyContinue

# __pycache__ löschen (alle)
Get-ChildItem -Recurse -Filter __pycache__ | Remove-Item -Recurse -Force

# Git-Commit
git add -A
git commit -m "cleanup: Remove build artifacts"
```

### Phase 3: Test-Dateien organisieren ⏱️ 2 Minuten

```powershell
# Fixtures-Verzeichnis erstellen
New-Item -ItemType Directory -Path tests\fixtures -Force

# Test-Dateien verschieben
Move-Item test_*.* tests\fixtures\

# Git-Commit
git add -A
git commit -m "refactor: Move test files to tests/fixtures/"
```

### Phase 4: setup.py aktualisieren ⏱️ 5 Minuten

**Option A:** Auf neue Struktur umstellen (wenn Package-Installation noch benötigt)
```python
# setup.py ändern:
# Line 17: vcc_pki/__version__.py → src/__version__.py
```

**Option B:** Komplett entfernen (empfohlen für moderne Projekte)
```powershell
Remove-Item setup.py
# pyproject.toml reicht für moderne Python-Projekte
```

**Git-Commit:**
```powershell
git add -A
git commit -m "refactor: Modernize package structure (remove setup.py)"
```

### Phase 5: Verifizierung ⏱️ 5 Minuten

```powershell
# Neue Struktur prüfen
tree /F src\
tree /F scripts\

# Tests laufen lassen (falls vorhanden)
pytest tests\ -v

# Server starten (Test)
.\scripts\start_server.ps1 -Background

# Status prüfen
.\scripts\status_server.ps1

# Server stoppen
.\scripts\stop_server.ps1
```

---

## ✅ Nach der Bereinigung

### Neue Struktur (Clean)

```
C:\VCC\PKI\
├── src/                        # ✅ Haupt-Source Code
│   ├── pki_server.py          # REST API Server
│   ├── ca_manager.py          # CA Management
│   ├── service_cert_manager.py # Service Certificates
│   ├── database.py            # SQLite Backend
│   └── crypto_utils.py        # Krypto-Utilities
├── scripts/                    # ✅ PowerShell Management
│   ├── start_server.ps1
│   ├── stop_server.ps1
│   ├── start_frontend.ps1
│   ├── status_all.ps1
│   └── README.md
├── pki_admin_cli.py           # ✅ Admin CLI (950+ Zeilen)
├── pki_manager_gui.py         # ✅ Tkinter GUI (1,400+ Zeilen)
├── docs/                       # ✅ Aktuelle Dokumentation
│   ├── PKI_PROJECT_COMPLETE.md
│   ├── PKI_ADMIN_CLI.md
│   └── ...
├── tests/                      # ✅ Tests
│   ├── fixtures/              # Test-Dateien
│   │   ├── test_cert.json
│   │   ├── test_document.txt
│   │   └── test_signature.json
│   └── ...
├── client/                     # ✅ Python PKI Client Library
├── examples/                   # ✅ Beispiele
├── config/                     # ✅ Konfiguration
├── database/                   # ✅ DB-Schema
├── logs/                       # ✅ Server-Logs
├── ca_storage/                # ✅ CA-Zertifikate
├── service_certificates/      # ✅ Service-Certs
├── pyproject.toml             # ✅ Moderne Package-Config
├── requirements.txt           # ✅ Dependencies
├── requirements-dev.txt       # ✅ Dev-Dependencies
├── README.md                  # ✅ Haupt-Dokumentation
├── PROJECT_STATUS.md          # ✅ Status
└── backups/                   # ✅ Legacy-Archive
    └── legacy-20251013/       # Archivierte Legacy-Dateien
        ├── vcc-pki-system/
        └── vcc_pki/
```

---

## 🔍 Prüfungen vor Löschung

### 1. Import-Prüfung

```powershell
# Suche nach alten Imports
grep -r "from vcc_pki" .
grep -r "import vcc_pki" .
grep -r "vcc-pki-system" .

# Erwartetes Ergebnis: Keine Treffer (außer in Backups)
```

### 2. Referenz-Prüfung

```powershell
# Suche nach Referenzen auf Port 12091 (alter Server)
grep -r "12091" .

# Erwartetes Ergebnis: Nur in Backup-Dateien
```

### 3. Funktions-Tests

```powershell
# Neuer Server startet
.\scripts\start_server.ps1 -Background

# Admin CLI funktioniert
python pki_admin_cli.py health check

# GUI startet
python pki_manager_gui.py

# Alles stoppen
.\scripts\stop_all.ps1
```

---

## 📝 Checkliste

- [ ] **Backup erstellt** (vcc-pki-system → backups/)
- [ ] **Backup erstellt** (vcc_pki → backups/)
- [ ] **Git-Commit** (vor Löschung)
- [ ] **Import-Prüfung** durchgeführt (keine Treffer)
- [ ] **Build-Artefakte** gelöscht (egg-info, __pycache__)
- [ ] **Test-Dateien** verschoben (tests/fixtures/)
- [ ] **setup.py** aktualisiert oder gelöscht
- [ ] **Funktions-Tests** erfolgreich
- [ ] **Git-Commit** (nach Bereinigung)
- [ ] **Dokumentation** aktualisiert (dieser Report)

---

## 🎯 Empfohlene Sofort-Maßnahme

**Quick Cleanup (5 Minuten):**

```powershell
# 1. Backup & Archive
New-Item -ItemType Directory -Path backups\legacy-20251013 -Force
Move-Item vcc-pki-system\ backups\legacy-20251013\
Move-Item vcc_pki\ backups\legacy-20251013\

# 2. Build-Artefakte löschen
Remove-Item vcc_pki.egg-info\ -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter __pycache__ | Remove-Item -Recurse -Force

# 3. Test-Dateien organisieren
New-Item -ItemType Directory -Path tests\fixtures -Force
Move-Item test_*.* tests\fixtures\

# 4. Git-Commit
git add -A
git commit -m "cleanup: Archive legacy PKI system and organize files"

# 5. Verifizierung
.\scripts\start_all.ps1
.\scripts\status_all.ps1
.\scripts\stop_all.ps1
```

**Ergebnis:**
- ✅ ~7.5 MB Speicher frei
- ✅ Klare Struktur
- ✅ Keine Verwechslungen mehr
- ✅ Backup für Notfall vorhanden

---

**Letzte Aktualisierung:** 13. Oktober 2025  
**Status:** Bereinigung empfohlen  
**Priorität:** MEDIUM (keine Funktionalität betroffen, aber Struktur-Verbesserung)
