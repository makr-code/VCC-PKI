#!/usr/bin/env python3
"""
VCC PKI Server - Service Certificate Manager

Manages service certificates for all VCC microservices with:
- Certificate issuance (signed by Intermediate CA)
- Certificate renewal (30 days before expiry)
- Certificate revocation (CRL)
- Service registry integration
- Automatic rotation scheduling

Author: VCC Development Team
Created: 2025-10-13
"""

import os
import json
import uuid
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import generate_keypair


def validate_service_id(service_id: str) -> None:
    """
    Validate service ID format.
    
    Rules:
    - Only lowercase letters, numbers, and hyphens
    - 3-64 characters
    - Must start with a letter
    - Cannot end with hyphen
    
    Raises:
        ValueError: If service_id is invalid
    """
    if not service_id:
        raise ValueError("service_id cannot be empty")
    
    if len(service_id) < 3 or len(service_id) > 64:
        raise ValueError("service_id must be 3-64 characters")
    
    if not service_id[0].isalpha():
        raise ValueError("service_id must start with a letter")
    
    if service_id.endswith("-"):
        raise ValueError("service_id cannot end with hyphen")
    
    if not all(c.islower() or c.isdigit() or c == "-" for c in service_id):
        raise ValueError("service_id must contain only lowercase letters, numbers, and hyphens")


def validate_common_name(common_name: str) -> None:
    """
    Validate certificate common name.
    
    Rules:
    - 3-253 characters (DNS hostname max length)
    - Valid hostname format
    
    Raises:
        ValueError: If common_name is invalid
    """
    if not common_name:
        raise ValueError("common_name cannot be empty")
    
    if len(common_name) < 3 or len(common_name) > 253:
        raise ValueError("common_name must be 3-253 characters")
    
    # Basic hostname validation
    import re
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    if not re.match(hostname_pattern, common_name):
        raise ValueError("common_name must be a valid hostname")


def validate_san_dns(san_dns: List[str]) -> None:
    """
    Validate DNS Subject Alternative Names.
    
    Raises:
        ValueError: If any DNS name is invalid
    """
    if not san_dns:
        return
    
    if len(san_dns) > 100:
        raise ValueError("Maximum 100 DNS SANs allowed")
    
    import re
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    wildcard_pattern = r'^\*\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    
    for dns in san_dns:
        if not dns:
            raise ValueError("DNS SAN cannot be empty")
        if len(dns) > 253:
            raise ValueError(f"DNS SAN '{dns}' exceeds 253 characters")
        if not (re.match(hostname_pattern, dns) or re.match(wildcard_pattern, dns)):
            raise ValueError(f"Invalid DNS SAN format: '{dns}'")


def validate_san_ip(san_ip: List[str]) -> None:
    """
    Validate IP Subject Alternative Names.
    
    Raises:
        ValueError: If any IP address is invalid
    """
    if not san_ip:
        return
    
    if len(san_ip) > 100:
        raise ValueError("Maximum 100 IP SANs allowed")
    
    from ipaddress import IPv4Address, IPv6Address, AddressValueError
    
    for ip in san_ip:
        try:
            # Try to parse as IPv4 or IPv6
            try:
                IPv4Address(ip)
            except AddressValueError:
                IPv6Address(ip)
        except AddressValueError:
            raise ValueError(f"Invalid IP address: '{ip}'")


def validate_validity_days(validity_days: int) -> None:
    """
    Validate certificate validity period.
    
    Rules:
    - Minimum 1 day
    - Maximum 730 days (2 years, per CA/Browser Forum Baseline Requirements)
    
    Raises:
        ValueError: If validity_days is invalid
    """
    if validity_days < 1:
        raise ValueError("validity_days must be at least 1")
    
    if validity_days > 730:
        raise ValueError(
            "validity_days cannot exceed 730 days (2 years) per CA/Browser Forum requirements"
        )


def validate_key_size(key_size: int) -> None:
    """
    Validate RSA key size.
    
    Rules:
    - Must be 2048, 3072, or 4096 bits
    - 2048 is minimum for security
    - 4096 recommended for long-term certificates
    
    Raises:
        ValueError: If key_size is invalid
    """
    if key_size not in [2048, 3072, 4096]:
        raise ValueError(
            f"key_size must be 2048, 3072, or 4096 bits (got {key_size})"
        )


class ServiceCertificateManager:
    """
    Service Certificate Manager for VCC PKI Server.
    
    Manages certificates for all VCC microservices:
    - veritas-backend, veritas-frontend
    - covina-backend, covina-ingestion
    - vpb-backend
    - clara-backend
    - monitoring-service, etc.
    """
    
    def __init__(
        self,
        storage_path: str = "service_certificates",
        ca_manager=None
    ):
        """
        Initialize Service Certificate Manager.
        
        Args:
            storage_path: Path to service certificates directory
            ca_manager: CA Manager instance for signing certificates
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.ca_manager = ca_manager
        
        # Certificate registry file
        self.registry_file = self.storage_path / "certificate_registry.json"
        if not self.registry_file.exists():
            self._save_registry({})
    
    # ========================================================================
    # Certificate Issuance
    # ========================================================================
    
    def issue_service_certificate(
        self,
        service_id: str,
        common_name: str,
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
        validity_days: int = 365,
        key_size: int = 2048,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Issue a new certificate for a VCC service.
        
        Args:
            service_id: Unique service identifier (e.g., "veritas-backend")
            common_name: Certificate common name (e.g., "veritas-backend.vcc.local")
            san_dns: List of DNS SANs (Subject Alternative Names)
            san_ip: List of IP SANs
            validity_days: Certificate validity in days (default: 365)
            key_size: RSA key size (default: 2048)
            metadata: Additional metadata (owner, environment, etc.)
        
        Returns:
            Dict with certificate information
        
        Raises:
            ValueError: If service_id already has an active certificate
            RuntimeError: If certificate generation fails
        """
        print(f"🔐 Issuing certificate for service: {service_id}")
        print(f"   Common Name: {common_name}")
        print()
        
        # Validate input parameters
        validate_service_id(service_id)
        validate_common_name(common_name)
        validate_san_dns(san_dns or [])
        validate_san_ip(san_ip or [])
        validate_validity_days(validity_days)
        validate_key_size(key_size)
        
        # Check if service already has active certificate
        registry = self._load_registry()
        if service_id in registry:
            existing = registry[service_id]
            if existing.get("status") == "active":
                raise ValueError(
                    f"Service {service_id} already has an active certificate. "
                    "Revoke the existing certificate first or use renew_service_certificate()."
                )
        
        # Generate key pair
        print("   1/5 Generating RSA key pair...")
        private_key_pem, public_key_pem = generate_keypair(key_size)
        
        # Load private key object for CSR
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Build CSR
        print("   2/5 Creating Certificate Signing Request...")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VCC Framework"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Services"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        ])
        
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        # Add SAN extension
        san_list = []
        if san_dns:
            san_list.extend([x509.DNSName(dns) for dns in san_dns])
        if san_ip:
            from ipaddress import IPv4Address, IPv6Address
            for ip in san_ip:
                try:
                    # Try IPv4
                    san_list.append(x509.IPAddress(IPv4Address(ip)))
                except:
                    # Try IPv6
                    san_list.append(x509.IPAddress(IPv6Address(ip)))
        
        if san_list:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
        
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # Sign CSR with Intermediate CA
        print("   3/5 Signing certificate with Intermediate CA...")
        if not self.ca_manager:
            raise RuntimeError("CA Manager not configured")
        
        # Get Intermediate CA password from environment or instance variable
        ca_password = getattr(self.ca_manager, '_intermediate_ca_password', None)
        intermediate_cert, intermediate_key = self.ca_manager.load_intermediate_ca(ca_password)
        
        # Build certificate
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)
        
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(intermediate_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False
            )
        )
        
        # Add SAN from CSR
        for extension in csr.extensions:
            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                cert_builder = cert_builder.add_extension(
                    extension.value,
                    critical=False
                )
        
        # Sign certificate
        certificate = cert_builder.sign(intermediate_key, hashes.SHA256(), default_backend())
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        
        # Save certificate and key
        print("   4/5 Saving certificate files...")
        service_dir = self.storage_path / service_id
        service_dir.mkdir(parents=True, exist_ok=True)
        
        cert_file = service_dir / "cert.pem"
        key_file = service_dir / "key.pem"
        
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(private_key_pem)
        
        # Set restrictive permissions on key file
        try:
            os.chmod(key_file, 0o400)
        except Exception:
            pass
        
        # Update registry
        print("   5/5 Updating certificate registry...")
        cert_id = f"cert_{service_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        cert_info = {
            "certificate_id": cert_id,
            "service_id": service_id,
            "common_name": common_name,
            "serial_number": str(certificate.serial_number),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "issuer": "VCC Intermediate CA",
            "status": "active",
            "cert_file": str(cert_file),
            "key_file": str(key_file),
            "san_dns": san_dns or [],
            "san_ip": san_ip or [],
            "metadata": metadata or {},
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        registry[service_id] = cert_info
        self._save_registry(registry)
        
        print()
        print(f"✅ Certificate issued successfully!")
        print(f"   Certificate ID: {cert_id}")
        print(f"   Service ID: {service_id}")
        print(f"   Common Name: {common_name}")
        print(f"   Serial: {certificate.serial_number}")
        print(f"   Valid Until: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"   Certificate: {cert_file}")
        print(f"   Private Key: {key_file}")
        print()
        
        return cert_info
    
    # ========================================================================
    # Certificate Retrieval
    # ========================================================================
    
    def get_service_certificate(self, service_id: str) -> Optional[Dict[str, Any]]:
        """
        Get certificate information for a service.
        
        Args:
            service_id: Service identifier
        
        Returns:
            Certificate info dict or None if not found
        """
        registry = self._load_registry()
        return registry.get(service_id)
    
    def list_service_certificates(
        self,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List all service certificates.
        
        Args:
            status: Filter by status (active, revoked, expired)
        
        Returns:
            List of certificate info dicts
        """
        registry = self._load_registry()
        certs = list(registry.values())
        
        if status:
            certs = [c for c in certs if c.get("status") == status]
        
        return certs
    
    # ========================================================================
    # Certificate Renewal
    # ========================================================================
    
    def renew_service_certificate(
        self,
        service_id: str,
        validity_days: int = 365
    ) -> Dict[str, Any]:
        """
        Renew a service certificate.
        
        Args:
            service_id: Service identifier
            validity_days: New certificate validity in days
        
        Returns:
            New certificate info dict
        
        Raises:
            ValueError: If service not found
        """
        # Get existing certificate
        old_cert = self.get_service_certificate(service_id)
        if not old_cert:
            raise ValueError(f"Service {service_id} not found in registry")
        
        print(f"🔄 Renewing certificate for service: {service_id}")
        
        # Revoke old certificate
        self.revoke_service_certificate(service_id, reason="superseded")
        
        # Issue new certificate (same parameters)
        new_cert = self.issue_service_certificate(
            service_id=service_id,
            common_name=old_cert["common_name"],
            san_dns=old_cert.get("san_dns"),
            san_ip=old_cert.get("san_ip"),
            validity_days=validity_days,
            metadata=old_cert.get("metadata")
        )
        
        print(f"✅ Certificate renewed successfully!")
        return new_cert
    
    # ========================================================================
    # Certificate Revocation
    # ========================================================================
    
    def revoke_service_certificate(
        self,
        service_id: str,
        reason: str = "unspecified"
    ) -> bool:
        """
        Revoke a service certificate.
        
        Args:
            service_id: Service identifier
            reason: Revocation reason
        
        Returns:
            True if revoked, False if not found
        """
        registry = self._load_registry()
        
        if service_id not in registry:
            return False
        
        cert_info = registry[service_id]
        cert_info["status"] = "revoked"
        cert_info["revoked_at"] = datetime.now(timezone.utc).isoformat()
        cert_info["revocation_reason"] = reason
        
        self._save_registry(registry)
        
        print(f"🚫 Certificate revoked: {service_id}")
        print(f"   Reason: {reason}")
        
        return True
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _load_registry(self) -> Dict[str, Any]:
        """Load certificate registry from file."""
        if not self.registry_file.exists():
            return {}
        
        with open(self.registry_file, "r") as f:
            return json.load(f)
    
    def _save_registry(self, registry: Dict[str, Any]):
        """Save certificate registry to file."""
        with open(self.registry_file, "w") as f:
            json.dump(registry, f, indent=2)


# ==============================================================================
# CLI Interface
# ==============================================================================

if __name__ == "__main__":
    import argparse
    from ca_manager import CAManager
    
    parser = argparse.ArgumentParser(description="VCC PKI Service Certificate Manager")
    parser.add_argument("action", choices=["issue", "list", "renew", "revoke", "info"],
                       help="Action to perform")
    parser.add_argument("--service-id", help="Service identifier (e.g., veritas-backend)")
    parser.add_argument("--cn", help="Common name (e.g., veritas-backend.vcc.local)")
    parser.add_argument("--san-dns", nargs="*", help="DNS SANs")
    parser.add_argument("--san-ip", nargs="*", help="IP SANs")
    parser.add_argument("--ca-password", help="Intermediate CA password")
    parser.add_argument("--reason", default="unspecified", help="Revocation reason")
    
    args = parser.parse_args()
    
    # Initialize managers
    ca_mgr = CAManager()
    cert_mgr = ServiceCertificateManager(ca_manager=ca_mgr)
    
    # Set Intermediate CA password for signing
    if args.ca_password:
        ca_mgr._intermediate_ca_password = args.ca_password
    
    if args.action == "issue":
        if not args.service_id or not args.cn:
            print("❌ Error: --service-id and --cn required for issue action")
            exit(1)
        
        cert_mgr.issue_service_certificate(
            service_id=args.service_id,
            common_name=args.cn,
            san_dns=args.san_dns,
            san_ip=args.san_ip
        )
    
    elif args.action == "list":
        certs = cert_mgr.list_service_certificates()
        print("=" * 70)
        print("VCC PKI - Service Certificates")
        print("=" * 70)
        print()
        
        if not certs:
            print("No certificates found.")
        else:
            for cert in certs:
                print(f"Service ID: {cert['service_id']}")
                print(f"  Common Name: {cert['common_name']}")
                print(f"  Status: {cert['status']}")
                print(f"  Valid Until: {cert['not_after']}")
                print()
    
    elif args.action == "renew":
        if not args.service_id:
            print("❌ Error: --service-id required for renew action")
            exit(1)
        
        cert_mgr.renew_service_certificate(args.service_id)
    
    elif args.action == "revoke":
        if not args.service_id:
            print("❌ Error: --service-id required for revoke action")
            exit(1)
        
        cert_mgr.revoke_service_certificate(args.service_id, reason=args.reason)
    
    elif args.action == "info":
        if not args.service_id:
            print("❌ Error: --service-id required for info action")
            exit(1)
        
        cert = cert_mgr.get_service_certificate(args.service_id)
        if cert:
            print("=" * 70)
            print(f"Certificate Info: {args.service_id}")
            print("=" * 70)
            print()
            print(f"Certificate ID: {cert['certificate_id']}")
            print(f"Common Name: {cert['common_name']}")
            print(f"Serial: {cert['serial_number']}")
            print(f"Fingerprint: {cert['fingerprint_sha256']}")
            print(f"Status: {cert['status']}")
            print(f"Issuer: {cert['issuer']}")
            print(f"Valid From: {cert['not_before']}")
            print(f"Valid Until: {cert['not_after']}")
            print(f"Certificate File: {cert['cert_file']}")
            print(f"Private Key File: {cert['key_file']}")
            if cert.get('san_dns'):
                print(f"DNS SANs: {', '.join(cert['san_dns'])}")
            if cert.get('san_ip'):
                print(f"IP SANs: {', '.join(cert['san_ip'])}")
        else:
            print(f"❌ Certificate not found: {args.service_id}")
