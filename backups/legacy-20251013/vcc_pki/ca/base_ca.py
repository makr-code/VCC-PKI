"""Base Certificate Authority Interface

Abstract Base Class defining the interface for all Certificate Authority implementations.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta


class BaseCertificateAuthority(ABC):
    """Abstract Base Class für Certificate Authority
    
    Diese Klasse definiert das Interface für CA-Implementierungen.
    Konkrete Implementierungen:
    - MockCertificateAuthority (mock/mock_ca.py) - Testing
    - RealCertificateAuthority (ca/real_ca.py) - Production (Phase 4)
    """
    
    @abstractmethod
    def generate_certificate(
        self,
        subject_dn: Dict[str, str],
        public_key: bytes,
        validity_days: int = 365,
        extensions: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Generiert ein neues Zertifikat.
        
        Args:
            subject_dn: Subject Distinguished Name (CN, O, OU, L, ST, C)
                Beispiel: {"CN": "test.covina.local", "O": "Covina", "OU": "Testing"}
            public_key: Public Key des Subjects (PEM/DER encoded)
            validity_days: Gültigkeit in Tagen (default: 365)
            extensions: X.509 Extensions (optional)
                Beispiel: {"basicConstraints": {"ca": False}, "keyUsage": ["digitalSignature"]}
            
        Returns:
            Zertifikat als PEM-encoded bytes
            
        Raises:
            ValueError: Bei ungültigen Parametern
            RuntimeError: Bei Generierungsfehlern
        """
        pass
    
    @abstractmethod
    def revoke_certificate(
        self,
        serial_number: str,
        reason: str = "unspecified"
    ) -> None:
        """Widerruft ein Zertifikat (fügt zu CRL hinzu).
        
        Args:
            serial_number: Serial Number des zu widerrufenden Zertifikats
            reason: Revocation Reason
                Gültige Werte: unspecified, keyCompromise, CACompromise, 
                              affiliationChanged, superseded, cessationOfOperation,
                              certificateHold, removeFromCRL
        
        Raises:
            ValueError: Wenn Zertifikat nicht gefunden
            RuntimeError: Bei CRL-Update-Fehlern
        """
        pass
    
    @abstractmethod
    def validate_certificate(
        self,
        certificate: bytes,
        check_revocation: bool = True
    ) -> bool:
        """Validiert ein Zertifikat.
        
        Prüft:
        - Signatur-Validität
        - Zeitliche Gültigkeit (notBefore, notAfter)
        - Revocation Status (optional, via CRL/OCSP)
        - Certificate Chain (wenn relevant)
        
        Args:
            certificate: Zu validierendes Zertifikat (PEM/DER)
            check_revocation: CRL/OCSP Check durchführen (default: True)
            
        Returns:
            True wenn Zertifikat gültig, False sonst
        """
        pass
    
    @abstractmethod
    def get_certificate_info(self, certificate: bytes) -> Dict[str, Any]:
        """Extrahiert Informationen aus einem Zertifikat.
        
        Args:
            certificate: Zertifikat (PEM/DER)
            
        Returns:
            Dictionary mit Certificate Information:
            {
                "serial": "1234567890",
                "subject": {"CN": "...", "O": "...", ...},
                "issuer": {"CN": "...", "O": "...", ...},
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2026-01-01T00:00:00Z",
                "is_revoked": False,
                "extensions": {...}
            }
        """
        pass
    
    @abstractmethod
    def get_crl(self) -> bytes:
        """Holt die aktuelle Certificate Revocation List (CRL).
        
        Returns:
            CRL im DER-Format
        """
        pass
    
    def is_revoked(self, serial_number: str) -> bool:
        """Prüft ob ein Zertifikat widerrufen wurde.
        
        Default-Implementation nutzt validate_certificate().
        Kann überschrieben werden für effizientere CRL-Checks.
        
        Args:
            serial_number: Serial Number des Zertifikats
            
        Returns:
            True wenn widerrufen, False sonst
        """
        # Subklassen können dies effizienter implementieren
        raise NotImplementedError("Subclass must implement is_revoked or override this method")
