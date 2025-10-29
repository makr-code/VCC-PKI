# VCC PKI System - Cryptographic Services
# Production-ready cryptographic operations for PKI

from cryptography import x509
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID, ExtendedKeyUsageOID, KeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
import datetime
import uuid
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import logging

from .config import VCCPKIConfig

logger = logging.getLogger(__name__)

class VCCCryptoService:
    """Production-grade cryptographic service for VCC PKI"""
    
    def __init__(self, config: VCCPKIConfig):
        self.config = config
        self.certificates_path = Path(config.certificates_path)
        self.private_keys_path = Path(config.private_keys_path)
        
        # Ensure directories exist
        self.certificates_path.mkdir(parents=True, exist_ok=True)
        self.private_keys_path.mkdir(parents=True, exist_ok=True)
    
    def generate_private_key(self, key_size: int = 2048, algorithm: str = "RSA") -> rsa.RSAPrivateKey:
        """Generate secure private key"""
        if algorithm.upper() == "RSA":
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def create_x509_name(self, subject_data: Dict[str, str]) -> x509.Name:
        """Create X.509 Distinguished Name from dictionary"""
        name_attributes = []
        
        if "country_name" in subject_data:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data["country_name"]))
        if "state_or_province_name" in subject_data:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data["state_or_province_name"]))
        if "locality_name" in subject_data:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data["locality_name"]))
        if "organization_name" in subject_data:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data["organization_name"]))
        if "organizational_unit_name" in subject_data:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_data["organizational_unit_name"]))
        if "common_name" in subject_data:
            name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_data["common_name"]))
        
        return x509.Name(name_attributes)
    
    def create_root_ca(self, ca_name: str, organization_id: str) -> Tuple[str, str, str]:
        """Create Root CA certificate and private key"""
        logger.info(f"Creating Root CA: {ca_name}")
        
        # Generate private key
        private_key = self.generate_private_key(
            key_size=self.config.root_ca_key_size,
            algorithm=self.config.root_ca_algorithm
        )
        
        # Create subject
        subject_data = self.config.get_ca_subject("root", ca_name)
        subject = self.create_x509_name(subject_data)
        
        # Create certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)  # Self-signed
        builder = builder.public_key(private_key.public_key())
        
        # Serial number
        serial_number = int(uuid.uuid4().hex, 16)
        builder = builder.serial_number(serial_number)
        
        # Validity period
        now = datetime.datetime.utcnow()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=365 * self.config.root_ca_validity_years))
        
        # Extensions for Root CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=2),
            critical=True
        )
        
        builder = builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Sign certificate
        certificate = builder.sign(private_key, hashes.SHA256())
        
        # Generate IDs
        ca_id = f"root-ca-{organization_id}-{datetime.datetime.now().strftime('%Y%m%d')}"
        
        # Save certificate (private key stays in memory for offline storage)
        cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')
        
        # For mock mode, save private key encrypted
        if self.config.mock_mode:
            key_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(b'vcc-root-ca-password-2025')
            ).decode('utf-8')
        else:
            # In production, private key should be stored in HSM
            key_pem = None
        
        logger.info(f"✅ Root CA created: {ca_id}")
        return ca_id, cert_pem, key_pem
    
    def create_issuing_ca(self, ca_name: str, purpose: str, root_ca_cert_pem: str, 
                         root_ca_key_pem: str, organization_id: str) -> Tuple[str, str, str]:
        """Create Issuing CA certificate signed by Root CA"""
        logger.info(f"Creating Issuing CA: {ca_name} for {purpose}")
        
        # Load root CA
        root_cert = x509.load_pem_x509_certificate(root_ca_cert_pem.encode('utf-8'))
        root_key = serialization.load_pem_private_key(
            root_ca_key_pem.encode('utf-8'),
            password=b'vcc-root-ca-password-2025' if self.config.mock_mode else None
        )
        
        # Generate private key for issuing CA
        private_key = self.generate_private_key(
            key_size=self.config.issuing_ca_key_size
        )
        
        # Create subject
        subject_data = self.config.get_ca_subject("issuing", ca_name)
        subject = self.create_x509_name(subject_data)
        
        # Create certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(root_cert.subject)  # Signed by root
        builder = builder.public_key(private_key.public_key())
        
        # Serial number
        serial_number = int(uuid.uuid4().hex, 16)
        builder = builder.serial_number(serial_number)
        
        # Validity period
        now = datetime.datetime.utcnow()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=365 * self.config.issuing_ca_validity_years))
        
        # Extensions for Issuing CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        
        # Key usage based on purpose
        if purpose == "services":
            key_usage = x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            )
        elif purpose == "code_signing":
            key_usage = x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=True,
                encipher_only=False,
                decipher_only=False
            )
        else:
            key_usage = x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            )
        
        builder = builder.add_extension(key_usage, critical=True)
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False
        )
        
        # Sign with root CA
        certificate = builder.sign(root_key, hashes.SHA256())
        
        # Generate IDs
        ca_id = f"issuing-ca-{purpose}-{organization_id}-{datetime.datetime.now().strftime('%Y%m%d')}"
        
        # Serialize certificate and key
        cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(b'vcc-issuing-ca-password-2025')
        ).decode('utf-8')
        
        logger.info(f"✅ Issuing CA created: {ca_id}")
        return ca_id, cert_pem, key_pem
    
    def create_service_certificate(self, service_name: str, service_type: str,
                                 issuing_ca_cert_pem: str, issuing_ca_key_pem: str,
                                 organization_id: str, san_domains: Optional[List[str]] = None) -> Tuple[str, str, str]:
        """Create service certificate for VCC services"""
        logger.info(f"Creating service certificate for {service_name} ({service_type})")
        
        # Load issuing CA
        issuing_cert = x509.load_pem_x509_certificate(issuing_ca_cert_pem.encode('utf-8'))
        issuing_key = serialization.load_pem_private_key(
            issuing_ca_key_pem.encode('utf-8'),
            password=b'vcc-issuing-ca-password-2025'
        )
        
        # Generate private key for service
        private_key = self.generate_private_key(key_size=2048)
        
        # Create subject
        subject_data = self.config.get_service_subject(service_name, service_type)
        subject = self.create_x509_name(subject_data)
        
        # Create certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuing_cert.subject)
        builder = builder.public_key(private_key.public_key())
        
        # Serial number
        serial_number = int(uuid.uuid4().hex, 16)
        builder = builder.serial_number(serial_number)
        
        # Validity period
        now = datetime.datetime.utcnow()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=self.config.service_cert_validity_days))
        
        # Extensions for service certificate
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        builder = builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Extended Key Usage for services
        extended_key_usage = [
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH
        ]
        
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usage),
            critical=True
        )
        
        # Subject Alternative Names
        san_list = [x509.DNSName(f"{service_name}.vcc.internal")]
        if san_domains:
            san_list.extend([x509.DNSName(domain) for domain in san_domains])
        
        # Add IP addresses for development
        if self.config.mock_mode:
            san_list.extend([
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
                x509.IPAddress("::1")
            ])
        
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuing_key.public_key()),
            critical=False
        )
        
        # Sign certificate
        certificate = builder.sign(issuing_key, hashes.SHA256())
        
        # Generate certificate ID
        cert_id = f"service-{service_name}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Serialize certificate and key
        cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(b'vcc-service-password-2025')
        ).decode('utf-8')
        
        logger.info(f"✅ Service certificate created: {cert_id}")
        return cert_id, cert_pem, key_pem
    
    def create_code_signing_certificate(self, signer_name: str, issuing_ca_cert_pem: str,
                                      issuing_ca_key_pem: str, organization_id: str) -> Tuple[str, str, str]:
        """Create code signing certificate"""
        logger.info(f"Creating code signing certificate for {signer_name}")
        
        # Load issuing CA
        issuing_cert = x509.load_pem_x509_certificate(issuing_ca_cert_pem.encode('utf-8'))
        issuing_key = serialization.load_pem_private_key(
            issuing_ca_key_pem.encode('utf-8'),
            password=b'vcc-issuing-ca-password-2025'
        )
        
        # Generate private key
        private_key = self.generate_private_key(key_size=2048)
        
        # Create subject
        subject_data = {
            "country_name": self.config.country_code,
            "state_or_province_name": self.config.state_name,
            "organization_name": self.config.organization_name,
            "organizational_unit_name": "VCC Code Signing",
            "common_name": f"VCC Code Signer - {signer_name}"
        }
        subject = self.create_x509_name(subject_data)
        
        # Create certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuing_cert.subject)
        builder = builder.public_key(private_key.public_key())
        
        # Serial number
        serial_number = int(uuid.uuid4().hex, 16)
        builder = builder.serial_number(serial_number)
        
        # Validity period
        now = datetime.datetime.utcnow()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=self.config.code_signing_cert_validity_days))
        
        # Extensions for code signing
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        builder = builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=True,  # Non-repudiation for code signing
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Extended Key Usage for code signing
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=True
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Authority Key Identifier  
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuing_key.public_key()),
            critical=False
        )
        
        # Sign certificate
        certificate = builder.sign(issuing_key, hashes.SHA256())
        
        # Generate certificate ID
        cert_id = f"codesign-{signer_name.lower().replace(' ', '-')}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Serialize certificate and key
        cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(b'vcc-codesign-password-2025')
        ).decode('utf-8')
        
        logger.info(f"✅ Code signing certificate created: {cert_id}")
        return cert_id, cert_pem, key_pem
    
    def sign_data(self, data: bytes, private_key_pem: str, password: bytes) -> bytes:
        """Sign data with private key"""
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password
        )
        
        # Sign data using RSA-PSS
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, certificate_pem: str) -> bool:
        """Verify signature using certificate"""
        try:
            # Load certificate
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
            public_key = certificate.public_key()
            
            # Verify signature
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def create_file_manifest(self, file_paths: List[Path]) -> Dict[str, str]:
        """Create SHA256 manifest for multiple files"""
        manifest = {}
        for file_path in file_paths:
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    manifest[str(file_path)] = file_hash
        
        return manifest
    
    def sign_file_manifest(self, manifest: Dict[str, str], private_key_pem: str, 
                          password: bytes) -> bytes:
        """Sign file manifest for code signing"""
        # Convert manifest to canonical JSON
        manifest_json = json.dumps(manifest, sort_keys=True, indent=None, separators=(',', ':'))
        manifest_bytes = manifest_json.encode('utf-8')
        
        # Sign manifest
        signature = self.sign_data(manifest_bytes, private_key_pem, password)
        return signature

# Test the crypto service
if __name__ == "__main__":
    from .config import create_config
    
    logging.basicConfig(level=logging.INFO)
    
    # Initialize with development config
    config = create_config("development")
    crypto_service = VCCCryptoService(config)
    
    print("🔐 VCC Cryptographic Service Test")
    print("=" * 50)
    
    # Test Root CA creation
    print("\n1. Creating Root CA...")
    root_ca_id, root_cert_pem, root_key_pem = crypto_service.create_root_ca(
        "VCC Root CA Brandenburg", "brandenburg-gov"
    )
    print(f"   Root CA ID: {root_ca_id}")
    
    # Test Issuing CA creation
    print("\n2. Creating Issuing CAs...")
    services_ca_id, services_cert_pem, services_key_pem = crypto_service.create_issuing_ca(
        "VCC Services CA", "services", root_cert_pem, root_key_pem, "brandenburg-gov"
    )
    print(f"   Services CA ID: {services_ca_id}")
    
    codesign_ca_id, codesign_cert_pem, codesign_key_pem = crypto_service.create_issuing_ca(
        "VCC Code Signing CA", "code_signing", root_cert_pem, root_key_pem, "brandenburg-gov"
    )
    print(f"   Code Signing CA ID: {codesign_ca_id}")
    
    # Test service certificate creation
    print("\n3. Creating Service Certificates...")
    vcc_services = ["argus", "covina", "clara", "veritas", "vpb"]
    
    for service in vcc_services:
        cert_id, cert_pem, key_pem = crypto_service.create_service_certificate(
            service, "api", services_cert_pem, services_key_pem, "brandenburg-gov"
        )
        print(f"   {service}: {cert_id}")
    
    # Test code signing certificate
    print("\n4. Creating Code Signing Certificate...")
    codesign_cert_id, codesign_cert, codesign_key = crypto_service.create_code_signing_certificate(
        "VCC CI/CD Pipeline", codesign_cert_pem, codesign_key_pem, "brandenburg-gov"
    )
    print(f"   Code Signing Cert: {codesign_cert_id}")
    
    # Test signing and verification
    print("\n5. Testing Code Signing...")
    test_data = b"This is test data for VCC code signing"
    signature = crypto_service.sign_data(test_data, codesign_key, b'vcc-codesign-password-2025')
    verification_result = crypto_service.verify_signature(test_data, signature, codesign_cert)
    print(f"   Signature verification: {'✅ SUCCESS' if verification_result else '❌ FAILED'}")
    
    print("\n✅ All cryptographic operations completed successfully!")