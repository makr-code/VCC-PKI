#!/usr/bin/env python3
"""
Generate ECDSA Key Pair for VCC Code Signing

Generates a new ECDSA key pair (NIST P-256 curve) for code signing.

Usage:
    python generate_keys.py --output keys/
    
This will create:
    - private_key.pem (⚠️ KEEP SECRET!)
    - public_key.pem (✅ Safe to distribute)
"""

import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_key_pair(output_dir: str = '.'):
    """Generate ECDSA key pair and save to files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print("Generating ECDSA key pair (NIST P-256 curve)...")
    
    # Generate private key
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # NIST P-256 curve
        default_backend()
    )
    
    # Export private key (PEM format, no encryption)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Export public key (PEM format)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save private key
    private_key_path = output_path / 'private_key.pem'
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    print(f"✓ Private key saved: {private_key_path}")
    print(f"  ⚠️  KEEP THIS SECRET! Never commit to git!")
    
    # Save public key
    public_key_path = output_path / 'public_key.pem'
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)
    print(f"✓ Public key saved: {public_key_path}")
    print(f"  ✅ Safe to distribute")
    
    print("\nKey pair generated successfully!")
    print("\nNext steps:")
    print(f"  1. Sign code: python scripts/bulk_sign_vcc.py --private-key {private_key_path}")
    print(f"  2. Update runtime_verifier.py with new public key")
    print(f"  3. Store private key in HSM/TPM (production)")
    
    return private_key_path, public_key_path


def main():
    parser = argparse.ArgumentParser(
        description='Generate ECDSA key pair for VCC code signing'
    )
    parser.add_argument(
        '--output', '-o',
        default='keys',
        help='Output directory for keys (default: keys/)'
    )
    
    args = parser.parse_args()
    generate_key_pair(args.output)


if __name__ == '__main__':
    main()
