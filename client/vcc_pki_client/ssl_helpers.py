"""
SSL Helpers
===========

Helper functions for creating SSL contexts for various Python HTTP libraries.
"""

import ssl
from pathlib import Path
from typing import Optional, Tuple


def create_ssl_context(
    cert_file: str,
    key_file: str,
    ca_bundle: str,
    verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
) -> ssl.SSLContext:
    """
    Create SSL context for client connections
    
    Args:
        cert_file: Path to client certificate file
        key_file: Path to client private key file
        ca_bundle: Path to CA bundle (Root + Intermediate)
        verify_mode: SSL verification mode (default: CERT_REQUIRED)
    
    Returns:
        ssl.SSLContext configured for mTLS
    """
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=ca_bundle
    )
    
    # Load client certificate and key
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    
    # Set verification mode
    context.verify_mode = verify_mode
    
    # Enable hostname checking
    context.check_hostname = True
    
    return context


def create_server_ssl_context(
    cert_file: str,
    key_file: str,
    ca_bundle: str,
    client_auth: bool = False
) -> ssl.SSLContext:
    """
    Create SSL context for server (FastAPI/uvicorn)
    
    Args:
        cert_file: Path to server certificate file
        key_file: Path to server private key file
        ca_bundle: Path to CA bundle
        client_auth: Whether to require client certificates (mTLS)
    
    Returns:
        ssl.SSLContext configured for server
    """
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    
    # Load server certificate and key
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    
    # Client authentication (mTLS)
    if client_auth:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_bundle)
    else:
        context.verify_mode = ssl.CERT_NONE
    
    return context


def get_httpx_ssl_config(
    cert_file: str,
    key_file: str,
    ca_bundle: str
) -> Tuple[str, Tuple[str, str]]:
    """
    Get SSL configuration for httpx.Client
    
    Args:
        cert_file: Path to client certificate file
        key_file: Path to client private key file
        ca_bundle: Path to CA bundle
    
    Returns:
        Tuple of (verify, cert) for httpx.Client constructor
        
    Example:
        verify, cert = get_httpx_ssl_config(cert, key, ca)
        client = httpx.Client(verify=verify, cert=cert)
    """
    return (ca_bundle, (cert_file, key_file))


def get_requests_ssl_config(
    cert_file: str,
    key_file: str,
    ca_bundle: str
) -> Tuple[str, Tuple[str, str]]:
    """
    Get SSL configuration for requests.Session
    
    Args:
        cert_file: Path to client certificate file
        key_file: Path to client private key file
        ca_bundle: Path to CA bundle
    
    Returns:
        Tuple of (verify, cert) for requests.Session
        
    Example:
        verify, cert = get_requests_ssl_config(cert, key, ca)
        session = requests.Session()
        session.verify = verify
        session.cert = cert
    """
    return (ca_bundle, (cert_file, key_file))


def validate_certificate_files(
    cert_file: str,
    key_file: str,
    ca_bundle: Optional[str] = None
) -> bool:
    """
    Validate that certificate files exist and are readable
    
    Args:
        cert_file: Path to certificate file
        key_file: Path to key file
        ca_bundle: Optional path to CA bundle
    
    Returns:
        True if all files exist and are readable
    
    Raises:
        FileNotFoundError: If any file is missing
    """
    cert_path = Path(cert_file)
    key_path = Path(key_file)
    
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_file}")
    
    if not key_path.exists():
        raise FileNotFoundError(f"Key file not found: {key_file}")
    
    if ca_bundle:
        ca_path = Path(ca_bundle)
        if not ca_path.exists():
            raise FileNotFoundError(f"CA bundle not found: {ca_bundle}")
    
    return True
