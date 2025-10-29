# Beitragsrichtlinien - VCC-PKI

Vielen Dank für Ihr Interesse, zu VCC-PKI beizutragen!

## 🤝 Wie kann ich beitragen?

### Sicherheits-Schwachstellen

⚠️ **WICHTIG:** Melden Sie Sicherheitsprobleme NICHT öffentlich!

Senden Sie Sicherheitsprobleme an: security@vcc-project.local

### Bug Reports

1. Prüfen Sie, ob der Bug bereits gemeldet wurde
2. Erstellen Sie ein Issue mit dem Label `bug`
3. Beschreiben Sie:
   - Erwartetes Verhalten
   - Tatsächliches Verhalten
   - Schritte zur Reproduktion
   - Log-Auszüge (ohne sensible Daten!)

### Feature Requests

1. Erstellen Sie ein Issue mit dem Label `enhancement`
2. Beschreiben Sie den Use Case
3. Berücksichtigen Sie Sicherheitsaspekte

## 📋 Code-Standards

### Python Style Guide

- Folgen Sie [PEP 8](https://pep8.org/)
- Verwenden Sie Type Hints
- Dokumentieren Sie Sicherheits-relevante Funktionen
- Maximum Line Length: 100 Zeichen

### Sicherheits-Standards

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def create_certificate_signature(
    data: bytes,
    private_key: rsa.RSAPrivateKey
) -> bytes:
    """
    Signiert Daten mit RSA-Private-Key.
    
    Security: Verwendet SHA-256 für Hashing.
    
    Args:
        data: Zu signierende Daten
        private_key: RSA Private Key
        
    Returns:
        Digitale Signatur
        
    Raises:
        ValueError: Bei ungültigen Eingaben
    """
    # Implementation...
```

## 🔐 Sicherheits-Checkliste

Vor jedem Commit:

- [ ] Keine Private Keys im Code
- [ ] Keine Passwörter oder Secrets
- [ ] Sensible Daten in Logs vermeiden
- [ ] Eingabe-Validierung durchgeführt
- [ ] Kryptographie-Best-Practices beachtet
- [ ] Tests für Security-Features geschrieben

## 📝 Commit-Nachrichten

Verwenden Sie [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - Neues Feature
- `fix:` - Bug-Fix
- `security:` - Sicherheits-Update
- `docs:` - Dokumentation
- `refactor:` - Refactoring
- `test:` - Tests

**Beispiele:**
```
security: Fix certificate validation bypass
feat: Add OCSP responder support
fix: Correct key generation for RSA-4096
```

## 🧪 Tests

Alle Security-relevanten Features benötigen Tests:

```python
def test_certificate_validation():
    """Test certificate chain validation"""
    # Setup
    ca = CAManager()
    cert = ca.create_certificate(...)
    
    # Test
    assert cert.validate_chain()
    assert not expired_cert.validate_chain()
```

## 🔄 Review-Prozess

1. Mindestens 1 Security-Review für PKI-Änderungen
2. Alle Tests müssen bestehen
3. Code Coverage >= 80%
4. Dokumentation aktualisiert

---

Vielen Dank für Ihre Beiträge! 🎉
