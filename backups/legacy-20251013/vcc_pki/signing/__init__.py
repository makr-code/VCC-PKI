"""Document Signing Package

This package contains all document signing and verification components.
"""

__all__ = ["BaseDocumentSigner"]

try:
    from .base_signer import BaseDocumentSigner
except ImportError:
    pass
