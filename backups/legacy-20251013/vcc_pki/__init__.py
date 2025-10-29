"""VCC PKI - Public Key Infrastructure Library

PKI/CA Library für das Covina Framework - Certificate Management, 
Document Signing, Code Verification.

Main Exports:
- PKIService: Unified API for PKI operations
- BaseCertificateAuthority: Abstract CA interface
- BaseDocumentSigner: Abstract signing interface
- MockCertificateAuthority: Testing CA
- MockDocumentSigner: Testing signer
"""

from .__version__ import __version__, __author__, __license__, __description__

# Conditional imports to avoid circular dependencies
__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "__description__",
]

# Import main components when available
try:
    from .api.pki_service import PKIService
    __all__.append("PKIService")
except ImportError:
    pass

try:
    from .ca.base_ca import BaseCertificateAuthority
    __all__.append("BaseCertificateAuthority")
except ImportError:
    pass

try:
    from .signing.base_signer import BaseDocumentSigner
    __all__.append("BaseDocumentSigner")
except ImportError:
    pass

try:
    from .mock.mock_ca import MockCertificateAuthority
    __all__.append("MockCertificateAuthority")
except ImportError:
    pass

try:
    from .mock.mock_signer import MockDocumentSigner
    __all__.append("MockDocumentSigner")
except ImportError:
    pass
