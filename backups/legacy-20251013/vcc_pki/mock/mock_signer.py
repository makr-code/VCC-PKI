"""Mock Document Signer Implementation

Mock signer for testing without real cryptography.
Uses JSON-based signatures with SHA256 hashing for document integrity.
"""

import json
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from ..signing.base_signer import BaseDocumentSigner


class MockDocumentSigner(BaseDocumentSigner):
    """Mock Document Signer für Testing
    
    Diese Mock-Implementation:
    - Verwendet JSON-basierte "Signaturen" (kein PKCS#7/CMS)
    - Echtes SHA256-Hashing für Dokument-Integrität
    - Simuliert Signing-Verhalten für Testing
    - Keine echte Kryptographie (schnell, keine Dependencies)
    
    Verwendung:
        signer = MockDocumentSigner()
        signature = signer.sign_document(
            document_path=Path("doc.pdf"),
            private_key=b"MOCK_PRIVATE_KEY",
            certificate=cert_bytes
        )
    """
    
    def __init__(self):
        """Initialisiert Mock Signer."""
        print("✅ Mock Document Signer initialized")
    
    def sign_document(
        self,
        document_path: Path,
        private_key: bytes,
        certificate: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Erstellt Mock-Signatur mit echtem Document Hash."""
        
        # Validation
        if not document_path.exists():
            raise FileNotFoundError(f"Document not found: {document_path}")
        
        if not private_key:
            raise ValueError("private_key cannot be empty")
        
        if not certificate:
            raise ValueError("certificate cannot be empty")
        
        # Dokument hashen (SHA256)
        with open(document_path, 'rb') as f:
            document_content = f.read()
            document_hash = hashlib.sha256(document_content).hexdigest()
        
        # Certificate Info extrahieren
        try:
            cert_data = json.loads(certificate.decode('utf-8'))
        except json.JSONDecodeError:
            raise ValueError("Invalid certificate format (expected JSON)")
        
        # Private Key Hash (um Key-Matching zu simulieren)
        key_hash = hashlib.sha256(private_key).hexdigest()
        
        # Signature Data
        signature_data = {
            "format": "MOCK_SIGNATURE_V1",
            "version": "1.0",
            "algorithm": "MOCK-SHA256-RSA",
            "document_path": str(document_path),
            "document_hash": document_hash,
            "document_size": len(document_content),
            "signer": cert_data.get("subject", {}),
            "certificate_serial": cert_data.get("serial_number", "UNKNOWN"),
            "certificate_fingerprint": hashlib.sha256(certificate).hexdigest()[:32],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "metadata": metadata or {},
            "signature_value": self._generate_signature_value(
                document_hash, certificate, key_hash
            )
        }
        
        print(f"✅ Mock Signature created for: {document_path.name}")
        
        return json.dumps(signature_data, indent=2).encode('utf-8')
    
    def verify_signature(
        self,
        document_path: Path,
        signature: bytes,
        certificate: bytes
    ) -> bool:
        """Verifiziert Mock-Signatur."""
        
        try:
            # Signatur parsen
            sig_data = json.loads(signature.decode('utf-8'))
            
            # Format check
            if sig_data.get("format") != "MOCK_SIGNATURE_V1":
                print("❌ Invalid signature format")
                return False
            
            # Certificate parsen
            cert_data = json.loads(certificate.decode('utf-8'))
            
            # Dokument existiert?
            if not document_path.exists():
                print(f"❌ Document not found: {document_path}")
                return False
            
            # Aktuellen Document Hash berechnen
            with open(document_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Hash-Vergleich
            if current_hash != sig_data["document_hash"]:
                print("❌ Document hash mismatch - document has been modified!")
                return False
            
            # Certificate Serial prüfen
            if sig_data["certificate_serial"] != cert_data.get("serial_number"):
                print("❌ Certificate serial mismatch")
                return False
            
            # Certificate Fingerprint prüfen
            cert_fp = hashlib.sha256(certificate).hexdigest()[:32]
            if sig_data["certificate_fingerprint"] != cert_fp:
                print("❌ Certificate fingerprint mismatch")
                return False
            
            # Signature Value prüfen
            # Note: In Mock-Mode können wir den Private Key nicht rekonstruieren,
            # daher können wir nur die Signature-Konsistenz prüfen
            expected_sig_prefix = "MOCK_SIG_"
            if not sig_data["signature_value"].startswith(expected_sig_prefix):
                print("❌ Invalid signature value format")
                return False
            
            print(f"✅ Signature verified for: {document_path.name}")
            return True
            
        except json.JSONDecodeError:
            print("❌ Invalid signature format (not JSON)")
            return False
        except KeyError as e:
            print(f"❌ Missing required field in signature: {e}")
            return False
        except Exception as e:
            print(f"❌ Verification error: {e}")
            return False
    
    def get_signature_info(self, signature: bytes) -> Dict[str, Any]:
        """Extrahiert Signature Info."""
        
        sig_data = json.loads(signature.decode('utf-8'))
        
        return {
            "format": sig_data.get("format"),
            "algorithm": sig_data["algorithm"],
            "document_path": sig_data["document_path"],
            "document_hash": sig_data["document_hash"],
            "document_size": sig_data.get("document_size"),
            "signer": sig_data["signer"],
            "certificate_serial": sig_data["certificate_serial"],
            "timestamp": sig_data["timestamp"],
            "metadata": sig_data.get("metadata", {})
        }
    
    def _generate_signature_value(
        self,
        document_hash: str,
        certificate: bytes,
        key_hash: str
    ) -> str:
        """Generiert Mock-Signaturwert.
        
        Simuliert eine kryptographische Signatur durch Hashing von:
        - Document Hash
        - Certificate
        - Private Key Hash
        """
        
        data_to_sign = (
            document_hash +
            hashlib.sha256(certificate).hexdigest() +
            key_hash
        )
        
        signature = "MOCK_SIG_" + hashlib.sha256(data_to_sign.encode()).hexdigest()
        
        return signature
    
    def sign_multiple_documents(
        self,
        document_paths: list[Path],
        private_key: bytes,
        certificate: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[Path, bytes]:
        """Signiert mehrere Dokumente (optimierte Mock-Version)."""
        
        print(f"✅ Batch signing {len(document_paths)} documents...")
        
        signatures = {}
        for i, doc_path in enumerate(document_paths, 1):
            doc_metadata = (metadata or {}).copy()
            doc_metadata["batch_index"] = i
            doc_metadata["batch_total"] = len(document_paths)
            
            signatures[doc_path] = self.sign_document(
                document_path=doc_path,
                private_key=private_key,
                certificate=certificate,
                metadata=doc_metadata
            )
        
        print(f"✅ Batch signing complete: {len(signatures)} signatures created")
        
        return signatures
    
    def verify_multiple_signatures(
        self,
        signature_data: Dict[Path, bytes],
        certificate: bytes
    ) -> Dict[Path, bool]:
        """Verifiziert mehrere Signaturen (optimierte Mock-Version)."""
        
        print(f"✅ Batch verification of {len(signature_data)} signatures...")
        
        results = {}
        valid_count = 0
        
        for doc_path, signature in signature_data.items():
            is_valid = self.verify_signature(
                document_path=doc_path,
                signature=signature,
                certificate=certificate
            )
            results[doc_path] = is_valid
            if is_valid:
                valid_count += 1
        
        print(f"✅ Batch verification complete: {valid_count}/{len(results)} valid")
        
        return results
