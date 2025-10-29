"""
Cryptographic Utilities Module

Production-Ready Cryptographic Operations:
- RSA Key Generation (2048/4096 bit)
- AES Encryption/Decryption (GCM mode)
- Digital Signatures (PKCS#1 v1.5, PSS)
- Hash Functions (SHA-256, SHA-384, SHA-512)
- CSR Generation

**Dependencies:** cryptography>=41.0.0
**Mode:** PRODUCTION (NO MOCK)
"""

import os
import hashlib
from typing import Tuple, Optional
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


# ============================================================================
# RSA Key Generation
# ============================================================================

def generate_keypair(
    key_size: int = 2048,
    public_exponent: int = 65537
) -> Tuple[bytes, bytes]:
    """
    Generate RSA key pair.
    
    Args:
        key_size: RSA key size in bits (2048, 3072, or 4096)
        public_exponent: RSA public exponent (default: 65537)
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    
    Raises:
        ValueError: If key_size is not supported
        RuntimeError: If key generation fails
    
    Example:
        >>> private_key, public_key = generate_keypair(2048)
        >>> print(f"Private Key: {len(private_key)} bytes")
        Private Key: 1679 bytes
    """
    if key_size not in [2048, 3072, 4096]:
        raise ValueError(f"Unsupported key size: {key_size}. Use 2048, 3072, or 4096.")
    
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize private key to PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key to PEM
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_key_pem, public_key_pem
    
    except Exception as e:
        raise RuntimeError(f"RSA key generation failed: {e}")


# ============================================================================
# CSR (Certificate Signing Request) Generation
# ============================================================================

def generate_csr(
    private_key_pem: bytes,
    common_name: str,
    country: Optional[str] = None,
    state: Optional[str] = None,
    locality: Optional[str] = None,
    organization: Optional[str] = None,
    organizational_unit: Optional[str] = None,
    email: Optional[str] = None
) -> bytes:
    """
    Generate Certificate Signing Request (CSR).
    
    Args:
        private_key_pem: Private key in PEM format
        common_name: Common Name (CN) - usually domain name
        country: Country (C) - 2 letter code
        state: State/Province (ST)
        locality: Locality/City (L)
        organization: Organization (O)
        organizational_unit: Organizational Unit (OU)
        email: Email Address
    
    Returns:
        CSR in PEM format
    
    Raises:
        ValueError: If private_key_pem is invalid
        RuntimeError: If CSR generation fails
    
    Example:
        >>> private_key, _ = generate_keypair()
        >>> csr = generate_csr(
        ...     private_key,
        ...     common_name="example.com",
        ...     organization="Example Corp"
        ... )
    """
    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Build subject name
        subject_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ]
        
        if country:
            subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if state:
            subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        if email:
            subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        
        subject = x509.Name(subject_attributes)
        
        # Build CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256(), backend=default_backend())
        
        # Serialize to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        return csr_pem
    
    except Exception as e:
        raise RuntimeError(f"CSR generation failed: {e}")


# ============================================================================
# AES Encryption/Decryption (GCM Mode)
# ============================================================================

def encrypt_data(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-256-GCM.
    
    Args:
        data: Data to encrypt
        key: 32-byte encryption key (AES-256)
    
    Returns:
        Tuple of (ciphertext, nonce, tag)
    
    Raises:
        ValueError: If key length is not 32 bytes
        RuntimeError: If encryption fails
    
    Example:
        >>> key = os.urandom(32)  # AES-256 key
        >>> plaintext = b"Secret message"
        >>> ciphertext, nonce, tag = encrypt_data(plaintext, key)
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (AES-256)")
    
    try:
        # Generate random nonce (12 bytes for GCM)
        nonce = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        # Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return ciphertext, nonce, encryptor.tag
    
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")


def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    
    Args:
        ciphertext: Encrypted data
        key: 32-byte encryption key (AES-256)
        nonce: 12-byte nonce used during encryption
        tag: 16-byte authentication tag
    
    Returns:
        Decrypted plaintext
    
    Raises:
        ValueError: If key/nonce/tag length is invalid
        RuntimeError: If decryption or authentication fails
    
    Example:
        >>> plaintext = decrypt_data(ciphertext, key, nonce, tag)
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (AES-256)")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    
    try:
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        # Decrypt
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    except Exception as e:
        raise RuntimeError(f"Decryption failed (invalid key/tag or corrupted data): {e}")


# ============================================================================
# RSA Digital Signatures
# ============================================================================

def sign_data(data: bytes, private_key_pem: bytes, algorithm: str = "PSS") -> bytes:
    """
    Sign data using RSA digital signature.
    
    Args:
        data: Data to sign
        private_key_pem: Private key in PEM format
        algorithm: Signature algorithm ("PSS" or "PKCS1v15")
    
    Returns:
        Digital signature
    
    Raises:
        ValueError: If private_key_pem is invalid or algorithm unknown
        RuntimeError: If signing fails
    
    Example:
        >>> private_key, _ = generate_keypair()
        >>> data = b"Important document"
        >>> signature = sign_data(data, private_key, algorithm="PSS")
    """
    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Select padding algorithm
        if algorithm == "PSS":
            padding_algo = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        elif algorithm == "PKCS1v15":
            padding_algo = padding.PKCS1v15()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}. Use 'PSS' or 'PKCS1v15'.")
        
        # Sign data
        signature = private_key.sign(
            data,
            padding_algo,
            hashes.SHA256()
        )
        
        return signature
    
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(f"Signing failed: {e}")


def verify_signature(
    data: bytes,
    signature: bytes,
    public_key_pem: bytes,
    algorithm: str = "PSS"
) -> bool:
    """
    Verify RSA digital signature.
    
    Args:
        data: Original data
        signature: Digital signature to verify
        public_key_pem: Public key in PEM format
        algorithm: Signature algorithm ("PSS" or "PKCS1v15")
    
    Returns:
        True if signature is valid, False otherwise
    
    Example:
        >>> _, public_key = generate_keypair()
        >>> is_valid = verify_signature(data, signature, public_key, "PSS")
        >>> print(f"Valid: {is_valid}")
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        # Select padding algorithm
        if algorithm == "PSS":
            padding_algo = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        elif algorithm == "PKCS1v15":
            padding_algo = padding.PKCS1v15()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        # Verify signature
        public_key.verify(
            signature,
            data,
            padding_algo,
            hashes.SHA256()
        )
        
        return True
    
    except Exception:
        # Signature verification failed
        return False


# ============================================================================
# Hash Functions
# ============================================================================

def hash_data(data: bytes, algorithm: str = "SHA256") -> str:
    """
    Hash data using cryptographic hash function.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm ("SHA256", "SHA384", "SHA512")
    
    Returns:
        Hex-encoded hash
    
    Raises:
        ValueError: If algorithm is unknown
    
    Example:
        >>> data = b"Hello, World!"
        >>> hash_hex = hash_data(data, "SHA256")
        >>> print(hash_hex)
        dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
    """
    algorithm_upper = algorithm.upper()
    
    if algorithm_upper == "SHA256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm_upper == "SHA384":
        return hashlib.sha384(data).hexdigest()
    elif algorithm_upper == "SHA512":
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unknown hash algorithm: {algorithm}. Use SHA256, SHA384, or SHA512.")


# ============================================================================
# Utility Functions
# ============================================================================

def generate_random_key(key_size: int = 32) -> bytes:
    """
    Generate cryptographically secure random key.
    
    Args:
        key_size: Key size in bytes (default: 32 for AES-256)
    
    Returns:
        Random key
    
    Example:
        >>> aes_key = generate_random_key(32)  # AES-256
        >>> print(f"Key: {aes_key.hex()}")
    """
    return os.urandom(key_size)


def load_private_key_from_file(file_path: str, password: Optional[bytes] = None):
    """
    Load private key from PEM file.
    
    Args:
        file_path: Path to PEM file
        password: Optional password for encrypted key
    
    Returns:
        Private key object
    
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is not valid PEM
    """
    with open(file_path, 'rb') as f:
        key_data = f.read()
    
    return serialization.load_pem_private_key(
        key_data,
        password=password,
        backend=default_backend()
    )


def load_public_key_from_file(file_path: str):
    """
    Load public key from PEM file.
    
    Args:
        file_path: Path to PEM file
    
    Returns:
        Public key object
    
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is not valid PEM
    """
    with open(file_path, 'rb') as f:
        key_data = f.read()
    
    return serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )


# ============================================================================
# Module Info
# ============================================================================

__all__ = [
    'generate_keypair',
    'generate_csr',
    'encrypt_data',
    'decrypt_data',
    'sign_data',
    'verify_signature',
    'hash_data',
    'generate_random_key',
    'load_private_key_from_file',
    'load_public_key_from_file'
]
