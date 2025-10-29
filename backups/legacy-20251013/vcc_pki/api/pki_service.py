"""PKI Service - Unified API

Central service providing unified access to PKI operations.
Abstracts away implementation details (mock vs real).
"""

from typing import Optional, Dict, Any, Literal
from pathlib import Path
from ..ca.base_ca import BaseCertificateAuthority
from ..signing.base_signer import BaseDocumentSigner
from ..mock.mock_ca import MockCertificateAuthority
from ..mock.mock_signer import MockDocumentSigner


class PKIService:
    """Unified PKI Service API
    
    Zentrale API für alle PKI-Operationen. Abstrahiert Mock vs. Real Implementation.
    
    Verwendung:
        # Testing mit Mock
        pki = PKIService(mode="mock")
        
        # Production mit echter Krypto (Phase 4)
        pki = PKIService(mode="real")
        
        # Certificate erstellen
        cert = pki.create_certificate(common_name="test.local")
        
        # Dokument signieren
        sig = pki.sign_document(path, cert["certificate"], cert["private_key"])
        
        # Verifizieren (inkl. Certificate Validation)
        is_valid = pki.verify_document(path, sig, cert["certificate"])
    """
    
    def __init__(
        self,
        mode: Literal["mock", "real"] = "mock",
        ca_name: Optional[str] = None
    ):
        """Initialisiert PKI Service.
        
        Args:
            mode: "mock" für Testing, "real" für echte Kryptographie
            ca_name: Name der CA (optional, nur für Mock)
        """
        self.mode = mode
        
        if mode == "mock":
            self.ca: BaseCertificateAuthority = MockCertificateAuthority(
                ca_name=ca_name or "Mock Root CA"
            )
            self.signer: BaseDocumentSigner = MockDocumentSigner()
            
        elif mode == "real":
            # TODO: Real implementations in Phase 4
            raise NotImplementedError(
                "Real PKI not yet implemented (Phase 4)\n"
                "Use mode='mock' for testing"
            )
        else:
            raise ValueError(f"Invalid mode: {mode}. Use 'mock' or 'real'")
        
        print(f"✅ PKI Service initialized in {mode.upper()} mode")
    
    def create_certificate(
        self,
        common_name: str,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        locality: Optional[str] = None,
        state: Optional[str] = None,
        country: Optional[str] = None,
        validity_days: int = 365,
        extensions: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Erstellt ein neues Zertifikat mit Keypair.
        
        Args:
            common_name: Common Name (CN) - REQUIRED
            organization: Organization (O)
            organizational_unit: Organizational Unit (OU)
            locality: Locality (L)
            state: State/Province (ST)
            country: Country (C)
            validity_days: Gültigkeit in Tagen (default: 365)
            extensions: X.509 Extensions
        
        Returns:
            Dictionary mit:
            - certificate: Certificate bytes (PEM/JSON)
            - private_key: Private Key bytes
            - public_key: Public Key bytes
            - subject: Subject DN dict
            - info: Certificate info
        """
        
        # Mock Keypair generieren
        if self.mode == "mock":
            private_key = f"MOCK_PRIVATE_KEY_{common_name}_{hash(common_name) % 10000}".encode()
            public_key = f"MOCK_PUBLIC_KEY_{common_name}_{hash(common_name) % 10000}".encode()
        else:
            # TODO: Phase 4 - Real key generation
            raise NotImplementedError("Real key generation not yet implemented")
        
        # Subject DN aufbauen
        subject_dn = {"CN": common_name}
        if organization:
            subject_dn["O"] = organization
        if organizational_unit:
            subject_dn["OU"] = organizational_unit
        if locality:
            subject_dn["L"] = locality
        if state:
            subject_dn["ST"] = state
        if country:
            subject_dn["C"] = country
        
        # Certificate generieren
        certificate = self.ca.generate_certificate(
            subject_dn=subject_dn,
            public_key=public_key,
            validity_days=validity_days,
            extensions=extensions
        )
        
        # Certificate Info holen
        cert_info = self.ca.get_certificate_info(certificate)
        
        return {
            "certificate": certificate,
            "private_key": private_key,
            "public_key": public_key,
            "subject": subject_dn,
            "info": cert_info
        }
    
    def sign_document(
        self,
        document_path: Path,
        certificate: bytes,
        private_key: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Signiert ein Dokument.
        
        Args:
            document_path: Pfad zum Dokument
            certificate: Certificate bytes
            private_key: Private Key bytes
            metadata: Zusätzliche Metadaten
        
        Returns:
            Detached Signature bytes
        """
        
        # Ensure Path object
        if isinstance(document_path, str):
            document_path = Path(document_path)
        
        return self.signer.sign_document(
            document_path=document_path,
            private_key=private_key,
            certificate=certificate,
            metadata=metadata
        )
    
    def verify_document(
        self,
        document_path: Path,
        signature: bytes,
        certificate: bytes,
        check_certificate_validity: bool = True
    ) -> bool:
        """Verifiziert Dokument-Signatur mit optionaler Certificate-Validation.
        
        Prüft:
        1. Signatur kryptographisch korrekt
        2. Document unverändert
        3. Certificate gültig (optional)
        
        Args:
            document_path: Pfad zum Dokument
            signature: Detached Signature
            certificate: Signer Certificate
            check_certificate_validity: Certificate validieren (default: True)
        
        Returns:
            True wenn Signatur UND Certificate gültig, False sonst
        """
        
        # Ensure Path object
        if isinstance(document_path, str):
            document_path = Path(document_path)
        
        # 1. Certificate validieren (falls aktiviert)
        if check_certificate_validity:
            if not self.ca.validate_certificate(certificate):
                print("❌ Certificate validation failed")
                return False
        
        # 2. Signatur verifizieren
        return self.signer.verify_signature(
            document_path=document_path,
            signature=signature,
            certificate=certificate
        )
    
    def get_certificate_info(self, certificate: bytes) -> Dict[str, Any]:
        """Liefert Certificate Info.
        
        Args:
            certificate: Certificate bytes
        
        Returns:
            Dictionary mit Certificate Information
        """
        return self.ca.get_certificate_info(certificate)
    
    def get_signature_info(self, signature: bytes) -> Dict[str, Any]:
        """Liefert Signature Info.
        
        Args:
            signature: Signature bytes
        
        Returns:
            Dictionary mit Signature Information
        """
        return self.signer.get_signature_info(signature)
    
    def revoke_certificate(self, serial_number: str, reason: str = "unspecified") -> None:
        """Widerruft ein Zertifikat.
        
        Args:
            serial_number: Serial Number
            reason: Revocation Reason
        """
        self.ca.revoke_certificate(serial_number, reason)
    
    def get_crl(self) -> bytes:
        """Holt die aktuelle Certificate Revocation List (CRL).
        
        Returns:
            CRL bytes
        """
        return self.ca.get_crl()
    
    def batch_sign_documents(
        self,
        document_paths: list[Path],
        certificate: bytes,
        private_key: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[Path, bytes]:
        """Signiert mehrere Dokumente.
        
        Args:
            document_paths: Liste von Dokumentpfaden
            certificate: Certificate
            private_key: Private Key
            metadata: Shared Metadata
        
        Returns:
            Dictionary: {document_path: signature_bytes}
        """
        return self.signer.sign_multiple_documents(
            document_paths=document_paths,
            private_key=private_key,
            certificate=certificate,
            metadata=metadata
        )
    
    def batch_verify_documents(
        self,
        signature_data: Dict[Path, bytes],
        certificate: bytes
    ) -> Dict[Path, bool]:
        """Verifiziert mehrere Signaturen.
        
        Args:
            signature_data: Dictionary {document_path: signature_bytes}
            certificate: Signer Certificate
        
        Returns:
            Dictionary: {document_path: is_valid}
        """
        # Certificate validieren
        if not self.ca.validate_certificate(certificate):
            print("❌ Certificate validation failed - all verifications will fail")
            return {path: False for path in signature_data.keys()}
        
        return self.signer.verify_multiple_signatures(
            signature_data=signature_data,
            certificate=certificate
        )
    
    def get_service_info(self) -> Dict[str, Any]:
        """Liefert PKI Service Informationen.
        
        Returns:
            Dictionary mit Service Info
        """
        info = {
            "mode": self.mode,
            "version": "0.1.0",
            "ca_type": type(self.ca).__name__,
            "signer_type": type(self.signer).__name__,
        }
        
        # CA Stats (if available)
        if hasattr(self.ca, 'get_stats'):
            info["ca_stats"] = self.ca.get_stats()
        
        return info
