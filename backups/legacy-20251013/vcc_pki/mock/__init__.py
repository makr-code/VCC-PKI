"""Mock Implementations Package

Mock/Stub implementations for testing without real cryptography.
"""

__all__ = ["MockCertificateAuthority", "MockDocumentSigner"]

try:
    from .mock_ca import MockCertificateAuthority
except ImportError:
    pass

try:
    from .mock_signer import MockDocumentSigner
except ImportError:
    pass
