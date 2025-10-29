#!/usr/bin/env python3
"""
VCC PKI Server - CA Manager

Manages Root CA and Intermediate CA operations for the VCC global PKI infrastructure.

Features:
- Root CA initialization and management (10-year validity)
- Intermediate CA generation and signing (5-year validity)
- Certificate signing for service certificates
- CA rotation and renewal
- Key encryption and secure storage

Author: VCC Development Team
Created: 2025-10-13
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
)


class CAManager:
    """
    Certificate Authority Manager for VCC PKI Server.
    
    Handles Root CA and Intermediate CA operations with secure key storage.
    """
    
    def __init__(self, ca_storage_path: str = "ca_storage"):
        """
        Initialize CA Manager.
        
        Args:
            ca_storage_path: Path to CA storage directory
        """
        self.ca_storage_path = Path(ca_storage_path)
        self.ca_storage_path.mkdir(parents=True, exist_ok=True)
        
        # CA configuration
        self.root_ca_config_file = self.ca_storage_path / "root_ca_config.json"
        self.intermediate_ca_config_file = self.ca_storage_path / "intermediate_ca_config.json"
        
        # Root CA files
        self.root_ca_cert_file = self.ca_storage_path / "root_ca.pem"
        self.root_ca_key_file = self.ca_storage_path / "root_ca_key.pem"
        
        # Intermediate CA files
        self.intermediate_ca_cert_file = self.ca_storage_path / "intermediate_ca.pem"
        self.intermediate_ca_key_file = self.ca_storage_path / "intermediate_ca_key.pem"
    
    # ========================================================================
    # Root CA Operations
    # ========================================================================
    
    def initialize_root_ca(
        self,
        country: str = "DE",
        state: str = "Bavaria",
        locality: str = "Munich",
        organization: str = "VCC Framework",
        org_unit: str = "PKI Infrastructure",
        common_name: str = "VCC Root CA",
        email: str = "pki@vcc.local",
        validity_days: int = 3650,  # 10 years
        key_size: int = 4096,
        password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Initialize Root CA (one-time operation).
        
        Args:
            country: Country code (2 letters)
            state: State/Province
            locality: City
            organization: Organization name
            org_unit: Organizational unit
            common_name: CA common name
            email: Email address
            validity_days: Certificate validity in days (default 10 years)
            key_size: RSA key size (default 4096 bits)
            password: Private key encryption password (optional but recommended)
        
        Returns:
            Dict with Root CA information
        
        Raises:
            ValueError: If Root CA already exists
        """
        if self.root_ca_cert_file.exists():
            raise ValueError("Root CA already exists. Use load_root_ca() instead.")
        
        print("🔐 Initializing Root CA...")
        print("   This is a ONE-TIME operation. Keep the private key SECURE!")
        print()
        
        # Generate private key
        print("   1/4 Generating Root CA private key (4096-bit RSA)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])
        
        # Build certificate
        print("   2/4 Building Root CA certificate...")
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)
        
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)  # Self-signed
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),  # Can sign 1 level (Intermediate CA)
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
        )
        
        # Sign certificate (self-signed)
        certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
        
        # Save private key (encrypted if password provided)
        print("   3/4 Saving Root CA private key...")
        encryption = (
            BestAvailableEncryption(password.encode()) if password
            else NoEncryption()
        )
        
        with open(self.root_ca_key_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                )
            )
        
        # Set restrictive permissions on key file (Unix only, Windows uses ACLs)
        try:
            os.chmod(self.root_ca_key_file, 0o400)
        except Exception:
            pass  # Windows doesn't support chmod
        
        # Save certificate
        print("   4/4 Saving Root CA certificate...")
        with open(self.root_ca_cert_file, "wb") as f:
            f.write(certificate.public_bytes(Encoding.PEM))
        
        # Save configuration
        ca_config = {
            "ca_type": "root",
            "common_name": common_name,
            "organization": organization,
            "country": country,
            "serial_number": str(certificate.serial_number),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "key_size": key_size,
            "encrypted": password is not None,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        with open(self.root_ca_config_file, "w") as f:
            json.dump(ca_config, f, indent=2)
        
        print()
        print("✅ Root CA initialized successfully!")
        print(f"   Certificate: {self.root_ca_cert_file}")
        print(f"   Private Key: {self.root_ca_key_file} ({'ENCRYPTED' if password else 'NOT ENCRYPTED'})")
        print(f"   Serial: {certificate.serial_number}")
        print(f"   Fingerprint: {ca_config['fingerprint_sha256']}")
        print(f"   Valid Until: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        print("⚠️  IMPORTANT:")
        print("   - Keep the Root CA private key SECURE (offline storage recommended)")
        print("   - Backup the Root CA certificate and configuration")
        print("   - Root CA is used ONLY to sign Intermediate CA")
        print()
        
        return ca_config
    
    def load_root_ca(self, password: Optional[str] = None) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Load Root CA certificate and private key.
        
        Args:
            password: Private key decryption password (if encrypted)
        
        Returns:
            Tuple of (certificate, private_key)
        
        Raises:
            FileNotFoundError: If Root CA files don't exist
            ValueError: If password is required but not provided
        """
        if not self.root_ca_cert_file.exists():
            raise FileNotFoundError(
                f"Root CA certificate not found: {self.root_ca_cert_file}\n"
                "Run initialize_root_ca() first."
            )
        
        # Load certificate
        with open(self.root_ca_cert_file, "rb") as f:
            cert_pem = f.read()
        certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
        # Load private key
        with open(self.root_ca_key_file, "rb") as f:
            key_pem = f.read()
        
        try:
            private_key = serialization.load_pem_private_key(
                key_pem,
                password=password.encode() if password else None,
                backend=default_backend()
            )
        except TypeError:
            raise ValueError("Root CA private key is encrypted. Provide password.")
        
        return certificate, private_key
    
    def get_root_ca_info(self) -> Dict[str, Any]:
        """
        Get Root CA information.
        
        Returns:
            Dict with Root CA details
        """
        if not self.root_ca_config_file.exists():
            return {"exists": False}
        
        with open(self.root_ca_config_file, "r") as f:
            config = json.load(f)
        
        config["exists"] = True
        return config
    
    # ========================================================================
    # Intermediate CA Operations
    # ========================================================================
    
    def create_intermediate_ca(
        self,
        root_ca_password: Optional[str] = None,
        country: str = "DE",
        state: str = "Bavaria",
        locality: str = "Munich",
        organization: str = "VCC Framework",
        org_unit: str = "PKI Services",
        common_name: str = "VCC Intermediate CA",
        email: str = "pki@vcc.local",
        validity_days: int = 1825,  # 5 years
        key_size: int = 2048,
        password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create Intermediate CA signed by Root CA.
        
        Args:
            root_ca_password: Root CA private key password
            country: Country code
            state: State/Province
            locality: City
            organization: Organization name
            org_unit: Organizational unit
            common_name: CA common name
            email: Email address
            validity_days: Certificate validity in days (default 5 years)
            key_size: RSA key size (default 2048 bits)
            password: Intermediate CA private key encryption password
        
        Returns:
            Dict with Intermediate CA information
        """
        print("🔐 Creating Intermediate CA...")
        print()
        
        # Load Root CA
        print("   1/5 Loading Root CA...")
        root_cert, root_key = self.load_root_ca(root_ca_password)
        
        # Generate private key for Intermediate CA
        print("   2/5 Generating Intermediate CA private key (2048-bit RSA)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])
        
        # Build certificate
        print("   3/5 Building Intermediate CA certificate...")
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)
        
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_cert.subject)  # Signed by Root CA
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),  # Can sign end-entity certs only
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False
            )
        )
        
        # Sign with Root CA
        print("   4/5 Signing Intermediate CA certificate with Root CA...")
        certificate = cert_builder.sign(root_key, hashes.SHA256(), default_backend())
        
        # Save private key
        print("   5/5 Saving Intermediate CA files...")
        encryption = (
            BestAvailableEncryption(password.encode()) if password
            else NoEncryption()
        )
        
        with open(self.intermediate_ca_key_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                )
            )
        
        # Set restrictive permissions
        try:
            os.chmod(self.intermediate_ca_key_file, 0o400)
        except Exception:
            pass
        
        # Save certificate
        with open(self.intermediate_ca_cert_file, "wb") as f:
            f.write(certificate.public_bytes(Encoding.PEM))
        
        # Save configuration
        ca_config = {
            "ca_type": "intermediate",
            "common_name": common_name,
            "organization": organization,
            "country": country,
            "serial_number": str(certificate.serial_number),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "key_size": key_size,
            "encrypted": password is not None,
            "signed_by": "root_ca",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        with open(self.intermediate_ca_config_file, "w") as f:
            json.dump(ca_config, f, indent=2)
        
        print()
        print("✅ Intermediate CA created successfully!")
        print(f"   Certificate: {self.intermediate_ca_cert_file}")
        print(f"   Private Key: {self.intermediate_ca_key_file} ({'ENCRYPTED' if password else 'NOT ENCRYPTED'})")
        print(f"   Serial: {certificate.serial_number}")
        print(f"   Fingerprint: {ca_config['fingerprint_sha256']}")
        print(f"   Valid Until: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        
        return ca_config
    
    def load_intermediate_ca(self, password: Optional[str] = None) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Load Intermediate CA certificate and private key.
        
        Args:
            password: Private key decryption password (if encrypted)
        
        Returns:
            Tuple of (certificate, private_key)
        """
        if not self.intermediate_ca_cert_file.exists():
            raise FileNotFoundError(
                f"Intermediate CA certificate not found: {self.intermediate_ca_cert_file}\n"
                "Run create_intermediate_ca() first."
            )
        
        # Load certificate
        with open(self.intermediate_ca_cert_file, "rb") as f:
            cert_pem = f.read()
        certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
        # Load private key
        with open(self.intermediate_ca_key_file, "rb") as f:
            key_pem = f.read()
        
        try:
            private_key = serialization.load_pem_private_key(
                key_pem,
                password=password.encode() if password else None,
                backend=default_backend()
            )
        except TypeError:
            raise ValueError("Intermediate CA private key is encrypted. Provide password.")
        
        return certificate, private_key
    
    def get_intermediate_ca_info(self) -> Dict[str, Any]:
        """
        Get Intermediate CA information.
        
        Returns:
            Dict with Intermediate CA details
        """
        if not self.intermediate_ca_config_file.exists():
            return {"exists": False}
        
        with open(self.intermediate_ca_config_file, "r") as f:
            config = json.load(f)
        
        config["exists"] = True
        return config


# ==============================================================================
# CLI Interface
# ==============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VCC PKI CA Manager")
    parser.add_argument("action", choices=["init-root", "create-intermediate", "info"],
                       help="Action to perform")
    parser.add_argument("--password", help="CA private key password")
    parser.add_argument("--root-password", help="Root CA password (for signing)")
    
    args = parser.parse_args()
    
    ca_mgr = CAManager()
    
    if args.action == "init-root":
        ca_mgr.initialize_root_ca(password=args.password)
    
    elif args.action == "create-intermediate":
        ca_mgr.create_intermediate_ca(
            root_ca_password=args.root_password,
            password=args.password
        )
    
    elif args.action == "info":
        print("=" * 70)
        print("VCC PKI - Certificate Authority Status")
        print("=" * 70)
        print()
        
        root_info = ca_mgr.get_root_ca_info()
        if root_info.get("exists"):
            print("✅ Root CA:")
            print(f"   Common Name: {root_info['common_name']}")
            print(f"   Serial: {root_info['serial_number']}")
            print(f"   Valid Until: {root_info['not_after']}")
            print(f"   Encrypted: {root_info['encrypted']}")
        else:
            print("❌ Root CA: Not initialized")
        
        print()
        
        intermediate_info = ca_mgr.get_intermediate_ca_info()
        if intermediate_info.get("exists"):
            print("✅ Intermediate CA:")
            print(f"   Common Name: {intermediate_info['common_name']}")
            print(f"   Serial: {intermediate_info['serial_number']}")
            print(f"   Valid Until: {intermediate_info['not_after']}")
            print(f"   Encrypted: {intermediate_info['encrypted']}")
        else:
            print("❌ Intermediate CA: Not created")
        
        print()
