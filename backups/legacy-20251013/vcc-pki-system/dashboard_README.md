# VCC PKI System - Management Dashboard

## Übersicht

Das VCC PKI Management Dashboard ist eine benutzerfreundliche Desktop-Anwendung zur Verwaltung der Public Key Infrastructure (PKI) im Verwaltungscloud-Computing der Länder (VCC).

## Features

### 🎯 Übersicht-Tab
- **System Status**: Real-time Status der CA, Datenbank und Services
- **Zertifikat-Übersicht**: Anzahl gültiger, abgelaufener und widerrufener Zertifikate
- **VCC Service Status**: Verfügbarkeit der registrierten VCC Services
- **Aktivitäts-Log**: Aktuelle System-Ereignisse und Operationen

### 📜 Zertifikate-Tab
- Vollständige Liste aller ausgestellten Zertifikate
- Zertifikat-Details mit Gültigkeitsstatus
- Funktionen für Erstellung, Erneuerung und Widerruf
- Export-Funktionen für Zertifikate

### 🌐 VCC Services-Tab
- Registry aller VCC Services
- Service-Status und Verfügbarkeits-Monitoring
- URL und Endpoint-Informationen
- Letzte Prüfzeiten

### 📋 Audit Logs-Tab
- Systemweite Audit-Protokollierung
- Filterbare Log-Ansicht
- Real-time Updates
- Ereignis-Kategorisierung

## Installation und Start

### Einfacher Start (Empfohlen)
```bash
# Doppelklick auf start_dashboard.bat
# ODER im Terminal:
start_dashboard.bat
```

### Manuelle Starts

#### Simple Dashboard (Keine Dependencies)
```bash
python simple_dashboard.py
```

#### Full Dashboard (Mit Charts und erweiterten Features)
```bash
python start_dashboard.py
```

### Systemvoraussetzungen
- **Python 3.8+** (erforderlich)
- **Windows 10/11** (getestet)
- **Mindestens 4GB RAM**
- **Netzwerkzugriff** zum VCC PKI Backend

### Optionale Dependencies (für Full Dashboard)
```bash
pip install requests matplotlib pillow pandas
```

## Benutzeroberfläche

### Hauptfenster
Das Dashboard öffnet sich in einem 1000x700 Pixel Fenster mit:
- **Menüleiste**: Datei, Tools, Hilfe
- **Tab-Navigation**: Übersicht, Zertifikate, VCC Services, Audit Logs
- **Statusleiste**: Verbindungsstatus und Benutzerinformationen

### Farben und Design
Das Dashboard verwendet die offiziellen Brandenburg Government Farben:
- **Primär**: #003366 (Dunkelblau)
- **Sekundär**: #006699 (Blau) 
- **Akzent**: #FF6600 (Orange)
- **Erfolg**: #00AA44 (Grün)
- **Warnung**: #FF9900 (Orange)
- **Fehler**: #CC0000 (Rot)

### Navigation
- **Tabs**: Klicken Sie auf die Tab-Reiter zur Navigation
- **Aktualisierung**: Automatische Updates alle 30 Sekunden
- **Menüs**: Kontextmenüs mit rechter Maustaste
- **Shortcuts**: Standard Windows-Shortcuts (Ctrl+Q zum Beenden)

## Konfiguration

### Backend-Verbindung
Das Dashboard verbindet sich standardmäßig mit:
- **API Endpoint**: `https://pki-api.vcc.local`
- **Port**: 8080
- **Protokoll**: HTTPS mit PKI Client Certificate

### Mock-Modus
Aktuell läuft das Dashboard im Mock-Modus mit Beispieldaten:
- 42 Testzertifikate
- 8 VCC Services
- Simulierte Aktivitäten

## Funktionen im Detail

### Zertifikat-Management
1. **Neue Zertifikate erstellen**
   - Klick auf "Neues Zertifikat" 
   - Eingabe der erforderlichen Daten
   - Automatische Ausstellung durch CA

2. **Zertifikate erneuern**
   - Auswahl eines Zertifikats
   - Klick auf "Erneuern"
   - Bestätigung der Erneuerung

3. **Zertifikate widerrufen**
   - Auswahl eines Zertifikats
   - Klick auf "Widerrufen"
   - Sicherheitsabfrage und Bestätigung

### Service-Monitoring
- **Automatische Überwachung** aller registrierten VCC Services
- **Health Checks** mit konfigurierbaren Intervallen
- **Status-Alerts** bei Service-Ausfällen
- **Verfügbarkeits-Metriken** und Uptime-Statistiken

### Audit und Compliance
- **Vollständige Protokollierung** aller PKI-Operationen
- **Compliance Reports** für Governance-Anforderungen  
- **Filterbare Logs** nach Ereignistyp und Zeitraum
- **Export-Funktionen** für externe Audit-Tools

## Troubleshooting

### Häufige Probleme

#### "Python nicht gefunden"
```bash
# Python Installation prüfen:
python --version

# Falls nicht installiert:
# Download von https://python.org
```

#### "Dashboard startet nicht"
```bash
# Einfaches Dashboard testen:
python simple_dashboard.py

# Dependency-Check:
python -c "import tkinter; print('Tkinter OK')"
```

#### "Verbindungsfehler zur API"
- Überprüfen Sie die Netzwerkverbindung
- Stellen Sie sicher, dass das VCC PKI Backend läuft
- Prüfen Sie die Firewall-Einstellungen

### Log-Dateien
Detaillierte Logs finden Sie unter:
- **System Logs**: Im Audit Logs Tab des Dashboards
- **Application Logs**: Console Output beim Start
- **Error Logs**: Windows Event Viewer

## Sicherheit

### Authentifizierung
- **PKI Client Certificates** für API-Zugriff
- **Rollenbasierte Zugriffskontrolle** (RBAC)
- **Session Management** mit JWT Tokens
- **Multi-Faktor-Authentifizierung** (geplant)

### Verschlüsselung
- **TLS 1.3** für alle Netzwerkkommunikation
- **AES-256-GCM** für lokale Datenspeicherung
- **RSA-4096** für Zertifikat-Signaturen
- **Hardware Security Module** Integration (geplant)

### Compliance
- **BSI IT-Grundschutz** konforme Implementierung
- **DSGVO** konforme Datenverarbeitung
- **Common Criteria** Evaluierung (geplant)
- **ISO 27001** Zertifizierung (angestrebt)

## Support und Wartung

### Kontakt
- **IT-Servicezentrum Brandenburg**: support@service.brandenburg.de
- **VCC Team**: vcc-support@zit.brandenburg.de
- **Notfall-Hotline**: +49 (0) 331 / 866-0

### Wartungsfenster
- **Geplante Wartung**: Samstags 02:00 - 06:00 Uhr
- **Notfall-Wartung**: Nach Ankündigung
- **Update-Zyklen**: Monatlich (Patches), Quartalsweise (Features)

### Backup und Recovery
- **Automatische Backups**: Täglich um 01:00 Uhr
- **Retention**: 30 Tage (täglich), 12 Monate (wöchentlich)
- **Recovery Time Objective (RTO)**: < 4 Stunden
- **Recovery Point Objective (RPO)**: < 1 Stunde

## Version und Changelog

### Version 1.0.0 (Januar 2024)
- ✅ Initial Release
- ✅ Tkinter-basierte Desktop-Anwendung
- ✅ Multi-Tab Interface
- ✅ Mock-Daten Integration
- ✅ Brandenburg Government Design
- ✅ System Status Monitoring
- ✅ Zertifikat-Management (Mock)
- ✅ VCC Service Registry
- ✅ Audit Logging
- ✅ Automatische Updates

### Geplante Features (v1.1)
- 🔄 Live API Integration
- 🔄 Erweiterte Chart-Visualisierungen  
- 🔄 Export/Import Funktionen
- 🔄 Benutzer-Management
- 🔄 Erweiterte Filteroptionen
- 🔄 Push-Benachrichtigungen
- 🔄 Multi-Language Support
- 🔄 Dark Mode Theme

## Lizenz

Dieses Projekt ist entwickelt für das Land Brandenburg im Rahmen der VCC Initiative.
Alle Rechte vorbehalten.

© 2024 Land Brandenburg - Zentrale IT-Dienstleistungen