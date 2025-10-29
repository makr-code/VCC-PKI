"""Mock Certificate Authority Implementation

Mock CA for testing without real cryptography.
Uses JSON-based certificates for easy inspection and testing.
"""

import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from ..ca.base_ca import BaseCertificateAuthority


class MockCertificateAuthority(BaseCertificateAuthority):
    """Mock CA für Testing ohne echte Kryptographie
    
    Diese Mock-Implementation:
    - Verwendet JSON-basierte "Zertifikate" (kein X.509)
    - Simuliert CA-Verhalten für Testing
    - Erlaubt einfaches Inspizieren der Daten
    - Keine echte Kryptographie (schnell, keine Dependencies)
    
    Verwendung:
        ca = MockCertificateAuthority()
        cert = ca.generate_certificate(
            subject_dn={"CN": "test.local"},
            public_key=b"MOCK_PUBLIC_KEY"
        )
    """
    
    def __init__(self, ca_name: str = "Mock Root CA"):
        """Initialisiert Mock CA.
        
        Args:
            ca_name: Name der CA (default: "Mock Root CA")
        """
        self.ca_name = ca_name
        self.issued_certificates: Dict[str, Dict] = {}  # serial -> cert_data
        self.revoked_certificates: List[str] = []  # List of serial numbers
        self.serial_counter = 1000
        
        print(f"✅ Mock CA initialized: {ca_name}")
    
    def generate_certificate(
        self,
        subject_dn: Dict[str, str],
        public_key: bytes,
        validity_days: int = 365,
        extensions: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Generiert Mock-Zertifikat (JSON-basiert)."""
        
        # Validation
        if not subject_dn or "CN" not in subject_dn:
            raise ValueError("subject_dn must contain at least 'CN' field")
        
        if not public_key:
            raise ValueError("public_key cannot be empty")
        
        # Serial Number
        serial = str(self.serial_counter)
        self.serial_counter += 1
        
        # Validity Period
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_days)
        
        # Mock Certificate als JSON
        cert_data = {
            "format": "MOCK_CERTIFICATE_V1",
            "version": "3",
            "serial_number": serial,
            "issuer": {
                "CN": self.ca_name,
                "O": "VCC",
                "OU": "Mock PKI Testing"
            },
            "subject": subject_dn,
            "not_before": not_before.isoformat() + "Z",
            "not_after": not_after.isoformat() + "Z",
            "public_key_hash": hashlib.sha256(public_key).hexdigest(),
            "public_key_algorithm": "MOCK-RSA-2048",
            "extensions": extensions or {},
            "signature_algorithm": "MOCK-SHA256-RSA",
            "signature": self._generate_signature(subject_dn, public_key, serial)
        }
        
        # Speichern
        self.issued_certificates[serial] = cert_data
        
        print(f"✅ Mock Certificate generated: Serial={serial}, CN={subject_dn.get('CN')}")
        
        # Als JSON zurückgeben
        return json.dumps(cert_data, indent=2).encode('utf-8')
    
    def revoke_certificate(self, serial_number: str, reason: str = "unspecified") -> None:
        """Fügt Zert zur Mock-CRL hinzu."""
        
        if serial_number not in self.issued_certificates:
            raise ValueError(f"Certificate with serial {serial_number} not found")
        
        if serial_number in self.revoked_certificates:
            print(f"⚠️ Certificate {serial_number} already revoked")
            return
        
        self.revoked_certificates.append(serial_number)
        
        print(f"✅ Certificate {serial_number} revoked (Reason: {reason})")
    
    def validate_certificate(
        self,
        certificate: bytes,
        check_revocation: bool = True
    ) -> bool:
        """Validiert Mock-Zertifikat."""
        
        try:
            cert_data = json.loads(certificate.decode('utf-8'))
            
            # Check: Format
            if cert_data.get("format") != "MOCK_CERTIFICATE_V1":
                print("❌ Invalid certificate format")
                return False
            
            serial = cert_data["serial_number"]
            
            # Check: Zert existiert
            if serial not in self.issued_certificates:
                print(f"❌ Certificate {serial} not found in CA registry")
                return False
            
            # Check: Nicht widerrufen
            if check_revocation and serial in self.revoked_certificates:
                print(f"❌ Certificate {serial} is revoked")
                return False
            
            # Check: Zeitliche Gültigkeit
            not_before = datetime.fromisoformat(cert_data["not_before"].replace("Z", ""))
            not_after = datetime.fromisoformat(cert_data["not_after"].replace("Z", ""))
            now = datetime.utcnow()
            
            if now < not_before:
                print(f"❌ Certificate not yet valid (valid from {not_before})")
                return False
            
            if now > not_after:
                print(f"❌ Certificate expired (valid until {not_after})")
                return False
            
            # Check: Signature
            expected_sig = self._generate_signature(
                cert_data["subject"],
                cert_data["public_key_hash"].encode(),  # Simplified
                serial
            )
            
            if cert_data["signature"] != expected_sig:
                print("❌ Invalid signature")
                return False
            
            return True
            
        except json.JSONDecodeError:
            print("❌ Invalid certificate format (not JSON)")
            return False
        except KeyError as e:
            print(f"❌ Missing required field in certificate: {e}")
            return False
        except Exception as e:
            print(f"❌ Validation error: {e}")
            return False
    
    def get_certificate_info(self, certificate: bytes) -> Dict[str, Any]:
        """Extrahiert Info aus Mock-Zert."""
        
        cert_data = json.loads(certificate.decode('utf-8'))
        
        return {
            "serial": cert_data["serial_number"],
            "subject": cert_data["subject"],
            "issuer": cert_data["issuer"],
            "valid_from": cert_data["not_before"],
            "valid_until": cert_data["not_after"],
            "is_revoked": cert_data["serial_number"] in self.revoked_certificates,
            "public_key_hash": cert_data["public_key_hash"],
            "extensions": cert_data.get("extensions", {})
        }
    
    def get_crl(self) -> bytes:
        """Holt die aktuelle Mock-CRL."""
        
        crl_data = {
            "format": "MOCK_CRL_V1",
            "issuer": {
                "CN": self.ca_name,
                "O": "VCC",
                "OU": "Mock PKI Testing"
            },
            "this_update": datetime.utcnow().isoformat() + "Z",
            "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z",
            "revoked_certificates": [
                {
                    "serial_number": serial,
                    "revocation_date": datetime.utcnow().isoformat() + "Z",
                    "reason": "unspecified"
                }
                for serial in self.revoked_certificates
            ]
        }
        
        return json.dumps(crl_data, indent=2).encode('utf-8')
    
    def is_revoked(self, serial_number: str) -> bool:
        """Prüft ob ein Zertifikat widerrufen wurde."""
        return serial_number in self.revoked_certificates
    
    def _generate_signature(
        self,
        subject_dn: Dict[str, str],
        public_key: bytes,
        serial: str
    ) -> str:
        """Generiert Mock-Signatur."""
        
        data_to_sign = (
            json.dumps(subject_dn, sort_keys=True) +
            public_key.hex() if isinstance(public_key, bytes) else public_key +
            serial
        )
        
        signature = "MOCK_SIG_" + hashlib.sha256(data_to_sign.encode()).hexdigest()[:64]
        
        return signature
    
    def get_stats(self) -> Dict[str, Any]:
        """Liefert CA Statistiken."""
        return {
            "ca_name": self.ca_name,
            "total_certificates_issued": len(self.issued_certificates),
            "total_certificates_revoked": len(self.revoked_certificates),
            "next_serial_number": self.serial_counter,
            "active_certificates": len(self.issued_certificates) - len(self.revoked_certificates)
        }
