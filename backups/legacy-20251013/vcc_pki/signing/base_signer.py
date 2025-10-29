"""Base Document Signer Interface

Abstract Base Class defining the interface for all document signing implementations.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pathlib import Path


class BaseDocumentSigner(ABC):
    """Abstract Base Class für Document Signing
    
    Diese Klasse definiert das Interface für Document Signing Implementierungen.
    Konkrete Implementierungen:
    - MockDocumentSigner (mock/mock_signer.py) - Testing
    - RealDocumentSigner (signing/real_signer.py) - Production (Phase 4)
    """
    
    @abstractmethod
    def sign_document(
        self,
        document_path: Path,
        private_key: bytes,
        certificate: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Signiert ein Dokument.
        
        Erstellt eine detached signature (separate Datei).
        
        Args:
            document_path: Pfad zum zu signierenden Dokument
            private_key: Private Key des Signers (PEM/DER encoded)
            certificate: Signer Certificate (PEM/DER encoded)
            metadata: Zusätzliche Metadaten für Signatur (optional)
                Beispiel: {
                    "purpose": "document_verification",
                    "department": "Legal",
                    "reference": "DOC-2025-001"
                }
            
        Returns:
            Detached Signature (PKCS#7, CMS, oder custom format)
            
        Raises:
            FileNotFoundError: Wenn Dokument nicht existiert
            ValueError: Bei ungültigen Keys/Certificates
            RuntimeError: Bei Signing-Fehlern
        """
        pass
    
    @abstractmethod
    def verify_signature(
        self,
        document_path: Path,
        signature: bytes,
        certificate: bytes
    ) -> bool:
        """Verifiziert eine Dokument-Signatur.
        
        Prüft:
        - Signatur-Korrektheit (kryptographisch)
        - Dokument-Integrität (Hash-Vergleich)
        - Signer-Identity (Certificate Match)
        
        Args:
            document_path: Pfad zum Originaldokument
            signature: Detached Signature
            certificate: Signer Certificate
            
        Returns:
            True wenn Signatur gültig, False sonst
            
        Note:
            Diese Methode prüft NICHT die Certificate-Validität!
            Verwende PKIService.verify_document() für vollständige Validation.
        """
        pass
    
    @abstractmethod
    def get_signature_info(self, signature: bytes) -> Dict[str, Any]:
        """Extrahiert Informationen aus einer Signatur.
        
        Args:
            signature: Signature Bytes
            
        Returns:
            Dictionary mit Signature Information:
            {
                "algorithm": "SHA256-RSA",
                "document_hash": "a1b2c3...",
                "signer": {"CN": "...", "O": "...", ...},
                "timestamp": "2025-01-01T12:00:00Z",
                "certificate_serial": "1234567890",
                "metadata": {...}
            }
        """
        pass
    
    def sign_multiple_documents(
        self,
        document_paths: list[Path],
        private_key: bytes,
        certificate: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[Path, bytes]:
        """Signiert mehrere Dokumente.
        
        Default-Implementation ruft sign_document() für jedes Dokument.
        Kann überschrieben werden für Batch-Optimierung.
        
        Args:
            document_paths: Liste von Dokumentpfaden
            private_key: Private Key
            certificate: Certificate
            metadata: Shared Metadata für alle Signaturen
            
        Returns:
            Dictionary: {document_path: signature_bytes}
        """
        signatures = {}
        for doc_path in document_paths:
            signatures[doc_path] = self.sign_document(
                document_path=doc_path,
                private_key=private_key,
                certificate=certificate,
                metadata=metadata
            )
        return signatures
    
    def verify_multiple_signatures(
        self,
        signature_data: Dict[Path, bytes],
        certificate: bytes
    ) -> Dict[Path, bool]:
        """Verifiziert mehrere Signaturen.
        
        Default-Implementation ruft verify_signature() für jede Signatur.
        
        Args:
            signature_data: Dictionary {document_path: signature_bytes}
            certificate: Signer Certificate
            
        Returns:
            Dictionary: {document_path: is_valid}
        """
        results = {}
        for doc_path, signature in signature_data.items():
            results[doc_path] = self.verify_signature(
                document_path=doc_path,
                signature=signature,
                certificate=certificate
            )
        return results
