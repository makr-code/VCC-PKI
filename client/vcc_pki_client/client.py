"""
VCC PKI Client
==============

Main client class for interacting with VCC PKI Server.
"""

import os
import ssl
import time
import logging
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from .exceptions import (
    PKIClientError,
    CertificateNotFoundError,
    CertificateExpiredError,
    ServerConnectionError,
    InvalidResponseError,
    CertificateValidationError,
    AutoRenewalError
)
from .ssl_helpers import (
    create_ssl_context,
    create_server_ssl_context,
    get_httpx_ssl_config,
    get_requests_ssl_config,
    validate_certificate_files
)


logger = logging.getLogger(__name__)


class PKIClient:
    """
    VCC PKI Client for easy certificate management
    
    Features:
    - Request and renew certificates
    - Automatic renewal (background thread)
    - SSL context creation
    - Service registration
    
    Example:
        client = PKIClient(
            pki_server_url="https://localhost:8443",
            service_id="my-service",
            ca_password="secret"
        )
        
        # Request certificate
        client.request_certificate(
            common_name="my-service.vcc.local",
            san_dns=["my-service", "localhost"]
        )
        
        # Enable auto-renewal
        client.enable_auto_renewal()
        
        # Get SSL context
        ssl_context = client.get_ssl_context()
    """
    
    def __init__(
        self,
        pki_server_url: str,
        service_id: str,
        ca_password: Optional[str] = None,
        storage_path: Optional[str] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize PKI Client
        
        Args:
            pki_server_url: URL of PKI server (e.g., https://localhost:8443)
            service_id: Service identifier (must match pattern ^[a-z0-9-]+$)
            ca_password: CA password for certificate operations (or set VCC_CA_PASSWORD env var)
            storage_path: Path to store certificates (default: ./pki_client/{service_id})
            verify_ssl: Whether to verify PKI server SSL certificate (default: True)
        """
        self.pki_server_url = pki_server_url.rstrip("/")
        self.service_id = service_id
        self.ca_password = ca_password or os.getenv("VCC_CA_PASSWORD")
        self.verify_ssl = verify_ssl
        
        # Setup storage paths
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path.cwd() / "pki_client" / service_id
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Certificate file paths
        self.cert_file = str(self.storage_path / "cert.pem")
        self.key_file = str(self.storage_path / "key.pem")
        self.ca_bundle = str(self.storage_path / "ca_chain.pem")
        
        # Auto-renewal thread
        self._renewal_thread: Optional[threading.Thread] = None
        self._renewal_stop_event = threading.Event()
        self._renewal_enabled = False
        
        # Download CA bundle on init
        self._download_ca_bundle()
        
        logger.info(f"PKI Client initialized for service: {service_id}")
    
    def _download_ca_bundle(self) -> None:
        """Download CA certificate chain from PKI server"""
        try:
            url = f"{self.pki_server_url}/api/v1/ca/chain"
            
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=False) as client:  # Bootstrap: No CA yet
                    response = client.get(url)
                    response.raise_for_status()
                    
                    # Save CA bundle
                    with open(self.ca_bundle, 'wb') as f:
                        f.write(response.content)
            else:
                # Fallback to urllib
                import urllib.request
                import urllib.error
                import ssl
                
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, context=ctx) as response:
                    ca_content = response.read()
                    with open(self.ca_bundle, 'wb') as f:
                        f.write(ca_content)
            
            logger.info(f"CA bundle downloaded: {self.ca_bundle}")
            
        except Exception as e:
            logger.warning(f"Failed to download CA bundle: {e}")
            # Non-fatal: Can still work with existing CA bundle
    
    def request_certificate(
        self,
        common_name: str,
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
        validity_days: int = 365
    ) -> Dict[str, Any]:
        """
        Request a new certificate from PKI server
        
        Args:
            common_name: Certificate common name (e.g., my-service.vcc.local)
            san_dns: List of DNS Subject Alternative Names
            san_ip: List of IP Subject Alternative Names
            validity_days: Certificate validity period in days (default: 365)
        
        Returns:
            dict: Certificate info (certificate_id, expires_at)
        
        Raises:
            ServerConnectionError: If connection to PKI server fails
            InvalidResponseError: If server response is invalid
        """
        try:
            url = f"{self.pki_server_url}/api/v1/certificates/request"
            
            headers = {}
            if self.ca_password:
                headers["X-CA-Password"] = self.ca_password
            
            payload = {
                "service_id": self.service_id,
                "common_name": common_name,
                "san_dns": san_dns or [],
                "san_ip": san_ip or [],
                "validity_days": validity_days
            }
            
            # Make request
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=self.ca_bundle if self.verify_ssl else False) as client:
                    response = client.post(url, json=payload, headers=headers)
                    response.raise_for_status()
                    result = response.json()
            else:
                import urllib.request
                import json
                
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode(),
                    headers={**headers, "Content-Type": "application/json"},
                    method="POST"
                )
                
                ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.verify_ssl else ssl._create_unverified_context()
                
                with urllib.request.urlopen(req, context=ctx) as response:
                    result = json.loads(response.read().decode())
            
            if not result.get("success"):
                raise InvalidResponseError(f"Certificate request failed: {result.get('message')}")
            
            # Download certificate files
            self._download_certificate()
            
            logger.info(f"Certificate requested successfully: {result['data']['certificate_id']}")
            return result["data"]
            
        except Exception as e:
            logger.error(f"Failed to request certificate: {e}")
            if isinstance(e, PKIClientError):
                raise
            raise ServerConnectionError(f"Certificate request failed: {e}")
    
    def _download_certificate(self) -> None:
        """Download certificate and key files from PKI server"""
        try:
            # Download certificate
            cert_url = f"{self.pki_server_url}/api/v1/certificates/{self.service_id}/download?file_type=cert"
            
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=self.ca_bundle if self.verify_ssl else False) as client:
                    response = client.get(cert_url)
                    response.raise_for_status()
                    with open(self.cert_file, 'wb') as f:
                        f.write(response.content)
            else:
                import urllib.request
                ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.verify_ssl else ssl._create_unverified_context()
                req = urllib.request.Request(cert_url)
                with urllib.request.urlopen(req, context=ctx) as response:
                    with open(self.cert_file, 'wb') as f:
                        f.write(response.read())
            
            # Download private key
            key_url = f"{self.pki_server_url}/api/v1/certificates/{self.service_id}/download?file_type=key"
            
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=self.ca_bundle if self.verify_ssl else False) as client:
                    response = client.get(key_url)
                    response.raise_for_status()
                    with open(self.key_file, 'wb') as f:
                        f.write(response.content)
            else:
                req = urllib.request.Request(key_url)
                with urllib.request.urlopen(req, context=ctx) as response:
                    with open(self.key_file, 'wb') as f:
                        f.write(response.read())
            
            logger.info(f"Certificate and key downloaded to: {self.storage_path}")
            
        except Exception as e:
            raise ServerConnectionError(f"Failed to download certificate: {e}")
    
    def renew_certificate(self, validity_days: int = 365) -> Dict[str, Any]:
        """
        Renew existing certificate
        
        Args:
            validity_days: New certificate validity period (default: 365)
        
        Returns:
            dict: New certificate info
        
        Raises:
            CertificateNotFoundError: If no certificate exists for service
            ServerConnectionError: If renewal request fails
        """
        try:
            url = f"{self.pki_server_url}/api/v1/certificates/{self.service_id}/renew"
            
            headers = {}
            if self.ca_password:
                headers["X-CA-Password"] = self.ca_password
            
            payload = {"validity_days": validity_days}
            
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=self.ca_bundle if self.verify_ssl else False) as client:
                    response = client.post(url, json=payload, headers=headers)
                    response.raise_for_status()
                    result = response.json()
            else:
                import urllib.request
                import json
                
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode(),
                    headers={**headers, "Content-Type": "application/json"},
                    method="POST"
                )
                
                ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.verify_ssl else ssl._create_unverified_context()
                
                with urllib.request.urlopen(req, context=ctx) as response:
                    result = json.loads(response.read().decode())
            
            if not result.get("success"):
                raise InvalidResponseError(f"Certificate renewal failed: {result.get('message')}")
            
            # Download new certificate
            self._download_certificate()
            
            logger.info(f"Certificate renewed successfully: {result['data']['certificate_id']}")
            return result["data"]
            
        except Exception as e:
            logger.error(f"Failed to renew certificate: {e}")
            if isinstance(e, PKIClientError):
                raise
            raise ServerConnectionError(f"Certificate renewal failed: {e}")
    
    def get_certificate_info(self) -> Dict[str, Any]:
        """
        Get certificate information from PKI server
        
        Returns:
            dict: Certificate info (status, expiry, etc.)
        
        Raises:
            CertificateNotFoundError: If certificate not found
            ServerConnectionError: If request fails
        """
        try:
            url = f"{self.pki_server_url}/api/v1/certificates/{self.service_id}"
            
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=self.ca_bundle if self.verify_ssl else False) as client:
                    response = client.get(url)
                    
                    if response.status_code == 404:
                        raise CertificateNotFoundError(f"Certificate not found for service: {self.service_id}")
                    
                    response.raise_for_status()
                    return response.json()
            else:
                import urllib.request
                import json
                
                req = urllib.request.Request(url)
                ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.verify_ssl else ssl._create_unverified_context()
                
                try:
                    with urllib.request.urlopen(req, context=ctx) as response:
                        return json.loads(response.read().decode())
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        raise CertificateNotFoundError(f"Certificate not found for service: {self.service_id}")
                    raise
            
        except CertificateNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            raise ServerConnectionError(f"Failed to get certificate info: {e}")
    
    def register_service(
        self,
        service_name: str,
        endpoints: Optional[List[str]] = None,
        health_check_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Register service in PKI server registry
        
        Args:
            service_name: Human-readable service name
            endpoints: List of service endpoints
            health_check_url: Health check endpoint URL
            metadata: Additional service metadata
        
        Returns:
            dict: Registration result
        
        Raises:
            ServerConnectionError: If registration fails
        """
        try:
            url = f"{self.pki_server_url}/api/v1/services/register"
            
            payload = {
                "service_id": self.service_id,
                "service_name": service_name,
                "endpoints": endpoints or [],
                "health_check_url": health_check_url,
                "metadata": metadata or {}
            }
            
            if HTTPX_AVAILABLE:
                with httpx.Client(verify=self.ca_bundle if self.verify_ssl else False) as client:
                    response = client.post(url, json=payload)
                    response.raise_for_status()
                    result = response.json()
            else:
                import urllib.request
                import json
                
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                
                ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.verify_ssl else ssl._create_unverified_context()
                
                with urllib.request.urlopen(req, context=ctx) as response:
                    result = json.loads(response.read().decode())
            
            if not result.get("success"):
                raise InvalidResponseError(f"Service registration failed: {result.get('message')}")
            
            logger.info(f"Service registered successfully: {self.service_id}")
            return result["data"]
            
        except Exception as e:
            logger.error(f"Failed to register service: {e}")
            if isinstance(e, PKIClientError):
                raise
            raise ServerConnectionError(f"Service registration failed: {e}")
    
    def enable_auto_renewal(
        self,
        check_interval_hours: int = 6,
        renew_before_days: int = 30
    ) -> None:
        """
        Enable automatic certificate renewal
        
        Starts background thread that checks certificate expiry
        and automatically renews when threshold is reached.
        
        Args:
            check_interval_hours: How often to check expiry (default: 6 hours)
            renew_before_days: Renew when expiry < X days (default: 30)
        """
        if self._renewal_enabled:
            logger.warning("Auto-renewal already enabled")
            return
        
        self._renewal_enabled = True
        self._renewal_stop_event.clear()
        
        def renewal_loop():
            logger.info(f"Auto-renewal enabled: check every {check_interval_hours}h, renew at {renew_before_days} days")
            
            while not self._renewal_stop_event.is_set():
                try:
                    # Check certificate expiry
                    cert_info = self.get_certificate_info()
                    days_until_expiry = cert_info.get("days_until_expiry", 999)
                    
                    if days_until_expiry <= renew_before_days:
                        logger.info(f"Certificate expires in {days_until_expiry} days - renewing...")
                        self.renew_certificate()
                        logger.info("Certificate renewed successfully")
                    else:
                        logger.debug(f"Certificate valid for {days_until_expiry} days - no renewal needed")
                
                except Exception as e:
                    logger.error(f"Auto-renewal check failed: {e}")
                
                # Sleep with interrupt check
                for _ in range(check_interval_hours * 3600):  # 1-second intervals
                    if self._renewal_stop_event.is_set():
                        break
                    time.sleep(1)
        
        self._renewal_thread = threading.Thread(target=renewal_loop, daemon=True, name=f"pki-renewal-{self.service_id}")
        self._renewal_thread.start()
        
        logger.info("Auto-renewal background thread started")
    
    def disable_auto_renewal(self) -> None:
        """Stop automatic certificate renewal"""
        if not self._renewal_enabled:
            return
        
        self._renewal_enabled = False
        self._renewal_stop_event.set()
        
        if self._renewal_thread:
            self._renewal_thread.join(timeout=5)
            self._renewal_thread = None
        
        logger.info("Auto-renewal disabled")
    
    def get_ssl_context(self, client_auth: bool = False) -> ssl.SSLContext:
        """
        Get SSL context for FastAPI/uvicorn server
        
        Args:
            client_auth: Whether to require client certificates (mTLS)
        
        Returns:
            ssl.SSLContext configured for server
        
        Example:
            ssl_context = pki_client.get_ssl_context()
            uvicorn.run(app, ssl_context=ssl_context)
        """
        validate_certificate_files(self.cert_file, self.key_file, self.ca_bundle)
        return create_server_ssl_context(
            self.cert_file,
            self.key_file,
            self.ca_bundle,
            client_auth=client_auth
        )
    
    def get_client_ssl_context(self) -> ssl.SSLContext:
        """
        Get SSL context for client connections (httpx, requests)
        
        Returns:
            ssl.SSLContext configured for client
        
        Example:
            ssl_context = pki_client.get_client_ssl_context()
            # Use with urllib, etc.
        """
        validate_certificate_files(self.cert_file, self.key_file, self.ca_bundle)
        return create_ssl_context(
            self.cert_file,
            self.key_file,
            self.ca_bundle
        )
    
    def get_httpx_config(self) -> tuple:
        """
        Get SSL configuration for httpx.Client
        
        Returns:
            Tuple of (verify, cert) for httpx.Client
        
        Example:
            verify, cert = pki_client.get_httpx_config()
            client = httpx.Client(verify=verify, cert=cert)
        """
        validate_certificate_files(self.cert_file, self.key_file, self.ca_bundle)
        return get_httpx_ssl_config(self.cert_file, self.key_file, self.ca_bundle)
    
    def get_requests_config(self) -> tuple:
        """
        Get SSL configuration for requests.Session
        
        Returns:
            Tuple of (verify, cert) for requests
        
        Example:
            verify, cert = pki_client.get_requests_config()
            session = requests.Session()
            session.verify = verify
            session.cert = cert
        """
        validate_certificate_files(self.cert_file, self.key_file, self.ca_bundle)
        return get_requests_ssl_config(self.cert_file, self.key_file, self.ca_bundle)
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - stops auto-renewal"""
        self.disable_auto_renewal()
