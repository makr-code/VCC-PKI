# VCC PKI Integration Quick Reference

**Quick Start Guide für jedes System** 🚀

---

## 📋 3-Schritte-Integration (10 Minuten pro Service)

### Schritt 1: PKI Client installieren (1 Minute)

```powershell
cd C:\VCC\{System-Name}
pip install C:\VCC\PKI\client
```

### Schritt 2: Backend Code hinzufügen (5 Minuten)

```python
# === IMPORT (am Anfang der Datei) ===
from vcc_pki_client import PKIClient
import os

# === INITIALISIERUNG (vor app) ===
pki = PKIClient(
    pki_server_url=os.getenv("PKI_SERVER_URL", "https://localhost:8443"),
    service_id="DEIN-SERVICE-ID",  # z.B. "covina-backend"
    ca_password=os.getenv("VCC_CA_PASSWORD")
)

# === STARTUP HANDLER ===
@app.on_event("startup")
async def startup():
    # Zertifikat anfordern (automatisch beim ersten Start)
    try:
        cert_info = pki.get_certificate_info()
        print(f"Zertifikat läuft ab in {cert_info['days_until_expiry']} Tagen")
    except:
        print("Fordere neues Zertifikat an...")
        pki.request_certificate(
            common_name="DEIN-SERVICE.vcc.local",  # z.B. "covina-backend.vcc.local"
            san_dns=["DEIN-SERVICE", "localhost"],
            san_ip=["127.0.0.1"]
        )
    
    # Service registrieren
    pki.register_service(
        service_name="DEIN SERVICE NAME",
        endpoints=["https://DEIN-SERVICE.vcc.local:PORT"],
        health_check_url="https://DEIN-SERVICE.vcc.local:PORT/health"
    )
    
    # Auto-Renewal aktivieren
    pki.enable_auto_renewal()

# === SHUTDOWN HANDLER ===
@app.on_event("shutdown")
async def shutdown():
    pki.disable_auto_renewal()

# === HTTPS AKTIVIEREN (in if __name__ == "__main__":) ===
if __name__ == "__main__":
    ssl_context = pki.get_ssl_context()
    
    uvicorn.run(
        app,  # oder "module:app"
        host="0.0.0.0",
        port=DEIN_PORT,
        ssl_context=ssl_context  # ← NEU!
    )
```

### Schritt 3: Environment Variables setzen (1 Minute)

**Erstelle/Ergänze `.env` Datei:**
```bash
PKI_SERVER_URL=https://localhost:8443
VCC_CA_PASSWORD=dein-ca-passwort
```

### Schritt 4: Testen (3 Minuten)

```powershell
# 1. PKI Server starten (falls nicht läuft)
cd C:\VCC\PKI\src
python pki_server.py --port 8443

# 2. Dein Service starten
cd C:\VCC\{System-Name}
python backend.py  # oder wie auch immer

# 3. HTTPS testen
curl -k https://localhost:DEIN_PORT/health

# 4. Zertifikat prüfen
cd C:\VCC\PKI
python pki_admin_cli.py cert info DEIN-SERVICE-ID
```

---

## 🎯 System-spezifische Konfiguration

### VERITAS Backend
```python
service_id="veritas-backend"
common_name="veritas-backend.vcc.local"
port=8001
```

### Covina Main Backend
```python
service_id="covina-backend"
common_name="covina-backend.vcc.local"
port=45678
```

### Covina Ingestion Backend
```python
service_id="covina-ingestion"
common_name="covina-ingestion.vcc.local"
port=45679
```

### Clara Backend
```python
service_id="clara-backend"
common_name="clara-backend.vcc.local"
port=8002  # Anpassen!
```

### VPB Backend
```python
service_id="vpb-backend"
common_name="vpb-backend.vcc.local"
port=8003  # Anpassen!
```

### Argus Backend
```python
service_id="argus-backend"
common_name="argus-backend.vcc.local"
port=8004  # Anpassen!
```

---

## 🔧 Frontend Integration (5 Minuten)

### Wenn Frontend API Client verwendet:

```python
# === ALTE URL ===
API_URL = "http://localhost:8001"

# === NEUE URL ===
API_URL = "https://DEIN-SERVICE.vcc.local:8001"

# === CA BUNDLE HERUNTERLADEN ===
import requests
import urllib.request
import ssl

# Einmalig beim Start
ca_bundle_url = "https://localhost:8443/api/ca/bundle"
ca_bundle_path = "ca_chain.pem"

ctx = ssl._create_unverified_context()
with urllib.request.urlopen(ca_bundle_url, context=ctx) as response:
    with open(ca_bundle_path, "wb") as f:
        f.write(response.read())

# === REQUESTS SESSION MIT CA BUNDLE ===
session = requests.Session()
session.verify = ca_bundle_path

# Alle Requests nutzen jetzt HTTPS mit Verifikation
response = session.get(f"{API_URL}/api/data")
```

---

## ⚠️ Häufige Fehler & Lösungen

### ❌ "Connection Refused"
**Problem:** PKI Server läuft nicht
**Lösung:**
```powershell
cd C:\VCC\PKI\src
python pki_server.py --port 8443
```

### ❌ "SSL: CERTIFICATE_VERIFY_FAILED"
**Problem:** CA Bundle fehlt
**Lösung:** CA Bundle herunterladen (siehe Frontend Integration oben)

### ❌ "service_id must match pattern"
**Problem:** Service ID enthält ungültige Zeichen
**Lösung:** Nur Kleinbuchstaben, Zahlen und Bindestriche: `^[a-z0-9-]+$`

### ❌ "Certificate not found"
**Problem:** Zertifikat wurde noch nicht angefordert
**Lösung:** Einmal den Service starten → automatische Anforderung

---

## 📊 Verifizierung

### Prüfe ob Integration erfolgreich:

```powershell
# 1. Liste alle Zertifikate
python pki_admin_cli.py cert list

# 2. Zeige Service-Details
python pki_admin_cli.py cert info DEIN-SERVICE-ID

# 3. Zeige alle registrierten Services
python pki_admin_cli.py service list

# 4. Health Check
python pki_admin_cli.py health check

# 5. Teste HTTPS Endpoint
curl -k https://localhost:DEIN_PORT/health
```

### Erwartete Ausgabe:

```
✓ Certificate issued successfully
  Certificate ID: cert_20251013_DEIN_SERVICE_ID
  Serial Number: ...
  Valid Until: 2026-10-13T...
  Days Until Expiry: 365
```

---

## ⏱️ Zeitplan

| System | Backend | Frontend | Total |
|--------|---------|----------|-------|
| Covina Main | 10 min | 5 min | 15 min |
| Covina Ingestion | 10 min | - | 10 min |
| VERITAS | 10 min | 5 min | 15 min |
| Clara | 10 min | 5 min | 15 min |
| VPB | 10 min | 5 min | 15 min |
| Argus | 10 min | 5 min | 15 min |
| **TOTAL** | | | **~1.5h** |

---

## 🎉 Nach erfolgreicher Integration:

**Vorher:**
- ❌ HTTP (unverschlüsselt)
- ❌ Manuelle Zertifikatsverwaltung
- ❌ Keine Ablaufüberwachung

**Nachher:**
- ✅ **HTTPS** (verschlüsselt)
- ✅ **Auto-Renewal** (alle 6h Check, 30 Tage vor Ablauf erneuern)
- ✅ **Zentral verwaltet** (PKI Server)
- ✅ **Zero Touch** (keine manuelle Arbeit)

---

**Viel Erfolg bei der Integration! 🚀**

Bei Fragen: Siehe `SERVICE_INTEGRATION_TODO.md` für Details.
