# VCC-PKI - Entwickler-Dokumentation

## 🛠️ Entwicklungsumgebung einrichten

### Voraussetzungen

- Python 3.9+
- OpenSSL
- Git
- Visual Studio Code (empfohlen)

### Lokales Setup

1. **Repository klonen:**
   ```bash
   git clone https://github.com/makr-code/VCC-PKI.git
   cd VCC-PKI
   ```

2. **Virtuelle Umgebung erstellen:**
   ```bash
   python -m venv venv
   
   # Windows
   .\venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Abhängigkeiten installieren:**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   pip install -r cli_requirements.txt
   ```

4. **Datenbank initialisieren:**
   ```bash
   python scripts/init_database.py
   ```

5. **CAs generieren:**
   ```bash
   python scripts/generate_keys.py
   ```

## 📁 Projektstruktur

```
PKI/
├── ca_storage/           # CA-Zertifikate und Schlüssel
├── client/               # Python Client Library
├── config/               # Server-Konfiguration
├── database/             # SQLite Datenbank
├── docs/                 # Detaillierte Dokumentation
├── examples/             # Code-Beispiele
├── keys/                 # Generierte Schlüssel
├── scripts/              # Hilfs-Skripte
├── service_certificates/ # Service-Zertifikate
├── src/                  # Quellcode
│   ├── ca_manager.py     # CA-Verwaltung
│   ├── cert_manager_base.py
│   ├── code_header.py    # Code-Header-Generierung
│   ├── crypto_utils.py   # Kryptographie-Utilities
│   ├── database.py       # Datenbank-Layer
│   ├── pki_server.py     # REST API Server
│   └── service_cert_manager.py
├── tests/                # Unit-Tests
├── pki_admin_cli.py      # Admin CLI
└── pki_manager_gui.py    # Management GUI
```

## 🧪 Tests ausführen

```bash
# Alle Tests
pytest

# Mit Coverage
pytest --cov=src tests/

# Spezifischer Test
pytest tests/test_ca_manager.py
```

## 🔍 Code-Qualität

### Linting
```bash
# Flake8
flake8 src/

# Black (Code Formatting)
black src/

# MyPy (Type Checking)
mypy src/
```

## 🐛 Debugging

### Server im Debug-Modus starten
```bash
# Mit erhöhtem Logging
python src/pki_server.py --debug --log-level DEBUG
```

### Zertifikate prüfen
```bash
# Zertifikat anzeigen
openssl x509 -in service_certificates/covina-backend/cert.pem -text -noout

# Zertifikatskette prüfen
openssl verify -CAfile ca_storage/root_ca.pem service_certificates/covina-backend/cert.pem
```

## 📦 Build und Deployment

### Docker
```bash
# Image bauen
docker-compose -f docker-compose.vcc.yml build

# Container starten
docker-compose -f docker-compose.vcc.yml up -d

# Logs anzeigen
docker-compose -f docker-compose.vcc.yml logs -f pki-server
```

## 🤝 Beitragen

### Workflow

1. **Branch erstellen:**
   ```bash
   git checkout -b feature/neue-funktion
   ```

2. **Änderungen committen:**
   ```bash
   git add .
   git commit -m "feat: Neue Funktion hinzugefügt"
   ```

3. **Pre-Commit Hook nutzen:**
   ```bash
   # Wird automatisch ausgeführt
   # Signiert alle geänderten Python-Dateien
   ```

4. **Push und Pull Request:**
   ```bash
   git push origin feature/neue-funktion
   ```

### Commit-Konventionen

- `feat:` - Neue Features
- `fix:` - Bug-Fixes
- `docs:` - Dokumentations-Änderungen
- `security:` - Sicherheits-Updates
- `refactor:` - Code-Refactoring
- `test:` - Test-Änderungen

## 🔐 Sicherheits-Best-Practices

1. **Private Keys niemals committen**
   - Prüfen Sie .gitignore
   - Verwenden Sie Secrets Management

2. **CA-Schlüssel schützen**
   - Nur auf sicheren Systemen
   - Backup verschlüsselt

3. **Zertifikats-Rotation**
   - Regelmäßige Erneuerung
   - Alte Zertifikate widerrufen

## 📚 Weitere Ressourcen

- [PKI Best Practices (Mozilla)](https://wiki.mozilla.org/PKI)
- [X.509 Certificate Standards](https://tools.ietf.org/html/rfc5280)
- [OpenSSL Cookbook](https://www.feistyduck.com/books/openssl-cookbook/)

---

*Letzte Aktualisierung: 17.11.2025*
