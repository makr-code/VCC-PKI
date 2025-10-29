"""
PKI Client Exceptions
=====================

Custom exception classes for VCC PKI Client.
"""


class PKIClientError(Exception):
    """Base exception for all PKI client errors"""
    pass


class CertificateNotFoundError(PKIClientError):
    """Raised when certificate is not found for service"""
    pass


class CertificateExpiredError(PKIClientError):
    """Raised when certificate has expired"""
    pass


class ServerConnectionError(PKIClientError):
    """Raised when connection to PKI server fails"""
    pass


class InvalidResponseError(PKIClientError):
    """Raised when PKI server returns invalid response"""
    pass


class CertificateValidationError(PKIClientError):
    """Raised when certificate validation fails"""
    pass


class AutoRenewalError(PKIClientError):
    """Raised when automatic renewal fails"""
    pass
