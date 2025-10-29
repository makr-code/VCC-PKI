#!/usr/bin/env python3
"""
VCC PKI - Code Manifest System

Inline verification system for Python source code integrity.
Prevents execution of tampered/infected code at runtime.

Features:
- Source code signing with ECDSA (performance)
- Inline manifest embedded in .py files
- Enhanced metadata headers (copyright, version, UUID, hashes)
- Runtime verification before execution
- Import hook integration
- No external manifest files (tamper-resistant)
- Zero-trust architecture (verify every execution)

Security Model:
- Each .py file has embedded signature in header comment
- Signature covers entire file content (except signature itself)
- Private key stored in HSM/secure location
- Public key embedded in verifier
- Runtime verification via import hooks

Author: VCC Team
Date: 2025-10-13
"""

import hashlib
import hmac
import ast
import sys
import os
import re
import importlib.util
import importlib.machinery
from pathlib import Path
from typing import Optional, Dict, Tuple, List
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Import enhanced header system
try:
    from code_header import (
        CodeHeader, HeaderBuilder, HeaderExtractor,
        CopyrightInfo, VersionInfo, FileIdentity, BuildInfo, 
        AuthorInfo, SecurityInfo
    )
    HEADER_SUPPORT = True
except ImportError:
    HEADER_SUPPORT = False
    print("WARNING: code_header.py not found. Enhanced headers disabled.")


# ==================== Configuration ====================

MANIFEST_MARKER = "# VCC-MANIFEST:"
SIGNATURE_PATTERN = re.compile(
    r'^# VCC-MANIFEST:\s*'
    r'(?P<version>v\d+)\s+'
    r'(?P<algorithm>[A-Z0-9_]+)\s+'
    r'(?P<signature>[A-Fa-f0-9]+)\s*$',
    re.MULTILINE
)

DEFAULT_ALGORITHM = "ECDSA_SHA256"
MANIFEST_VERSION = "v1"

# Development: Use embedded test keys (REPLACE IN PRODUCTION!)
DEV_PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHZ+YD8VF4nqXxQGBcUhcFZKvLFZEpLxVNLxFKZxqLXtoAoGCCqGSM49
AwEHoUQDQgAE4iJVmvOlNprpTLFLUwLpzDFZGGlTe4iGCqJlLBCx4MZ4f7dLLqWF
lqxQzJ3mFCqLLZxCwqxFZGLLqxFZGLLqxA==
-----END EC PRIVATE KEY-----"""

DEV_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4iJVmvOlNprpTLFLUwLpzDFZGGlT
e4iGCqJlLBCx4MZ4f7dLLqWFlqxQzJ3mFCqLLZxCwqxFZGLLqxFZGLLqxA==
-----END PUBLIC KEY-----"""


# ==================== Code Signer ====================

class CodeSigner:
    """Signs Python source code files with embedded manifest."""
    
    def __init__(self, private_key_path: Optional[str] = None):
        """
        Initialize code signer.
        
        Args:
            private_key_path: Path to private key PEM file (None = use dev key)
        """
        self.private_key = self._load_private_key(private_key_path)
        self.algorithm = DEFAULT_ALGORITHM
    
    def _load_private_key(self, key_path: Optional[str]) -> ec.EllipticCurvePrivateKey:
        """Load private key from file or use dev key."""
        if key_path and os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                key_data = f.read()
        else:
            # Development mode: Use embedded test key
            key_data = DEV_PRIVATE_KEY_PEM.encode('utf-8')
        
        return serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
    
    def sign_file(self, file_path: str, output_path: Optional[str] = None,
                  enhanced_header: bool = True, **header_kwargs) -> bool:
        """
        Sign a Python source file with embedded manifest.
        
        Args:
            file_path: Path to .py file to sign
            output_path: Output path (None = overwrite input)
            enhanced_header: Use enhanced header with metadata (default: True)
            **header_kwargs: Additional arguments for HeaderBuilder
                - version: Semantic version (e.g., "1.2.3")
                - author: Author name
                - description: Module description
                - classification: Security classification
                - git_commit: Git commit hash
                - build_number: Build number
        
        Returns:
            True if successful
        """
        # Read source code
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Remove existing manifest/header if present
        if HEADER_SUPPORT and enhanced_header:
            # Remove enhanced header
            result = HeaderExtractor.extract_header(source_code)
            if result:
                _, source_code = result
        else:
            # Remove simple manifest
            source_code = self._remove_existing_manifest(source_code)
        
        # Compute signature
        signature = self._compute_signature(source_code)
        
        # Create header (enhanced or simple)
        if HEADER_SUPPORT and enhanced_header:
            header_block = self._create_enhanced_header(
                file_path, source_code, signature, **header_kwargs
            )
        else:
            header_block = self._create_manifest_header(signature)
        
        # Combine header + source code
        signed_code = header_block + source_code
        
        # Write to output
        output_file = output_path or file_path
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(signed_code)
        
        return True
    
    def _create_enhanced_header(self, file_path: str, source_code: str, 
                                signature: str, **kwargs) -> str:
        """
        Create enhanced header with full metadata.
        
        Args:
            file_path: Path to file being signed
            source_code: Source code (without header)
            signature: Computed ECDSA signature
            **kwargs: Additional header parameters
        
        Returns:
            Complete header block as string
        """
        # Parse version (default: 1.0.0)
        version_str = kwargs.get('version', '1.0.0')
        version_parts = version_str.split('.')
        major = int(version_parts[0]) if len(version_parts) > 0 else 1
        minor = int(version_parts[1]) if len(version_parts) > 1 else 0
        patch = int(version_parts[2]) if len(version_parts) > 2 else 0
        
        # Build header
        builder = HeaderBuilder()
        builder.copyright("VCC - Veritas Control Center", 2025, "Proprietary")
        builder.version(major, minor, patch)
        builder.author(
            kwargs.get('author', 'VCC Development Team'),
            kwargs.get('author_email', 'dev@vcc.local')
        )
        builder.module(
            Path(file_path).stem,
            kwargs.get('description', f'Module: {Path(file_path).stem}')
        )
        builder.build_info(
            build_number=kwargs.get('build_number'),
            git_commit=kwargs.get('git_commit'),
            channel=kwargs.get('channel', 'development')
        )
        builder.security(
            classification=kwargs.get('classification', 'INTERNAL'),
            drm_enabled=kwargs.get('drm_enabled', True)
        )
        builder.compute_identity(source_code)
        builder.sign(signature, kwargs.get('signer_id', 'VCC Code Signing System'))
        
        header = builder.build()
        header.file_path = str(file_path)
        
        return header.to_header_block(include_signature=True)
    
    def sign_directory(self, directory: str, recursive: bool = True) -> Dict[str, bool]:
        """
        Sign all .py files in directory.
        
        Args:
            directory: Directory path
            recursive: Recursively sign subdirectories
        
        Returns:
            Dict mapping file paths to success status
        """
        results = {}
        
        pattern = "**/*.py" if recursive else "*.py"
        for file_path in Path(directory).glob(pattern):
            if file_path.is_file():
                try:
                    success = self.sign_file(str(file_path))
                    results[str(file_path)] = success
                except Exception as e:
                    print(f"Error signing {file_path}: {e}")
                    results[str(file_path)] = False
        
        return results
    
    def _compute_signature(self, source_code: str) -> str:
        """Compute ECDSA signature of source code."""
        # Hash source code
        source_bytes = source_code.encode('utf-8')
        digest = hashlib.sha256(source_bytes).digest()
        
        # Sign with ECDSA
        signature = self.private_key.sign(
            digest,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Convert to hex
        return signature.hex()
    
    def _create_manifest_header(self, signature: str) -> str:
        """Create manifest header comment."""
        return (
            f"# VCC-MANIFEST: {MANIFEST_VERSION} {self.algorithm} {signature}\n"
            f"# Signed: {datetime.now().isoformat()}\n"
            f"# This file is cryptographically signed. Do not modify.\n\n"
        )
    
    def _remove_existing_manifest(self, source_code: str) -> str:
        """Remove existing manifest from source code."""
        lines = source_code.split('\n')
        result = []
        skip_manifest = False
        
        for line in lines:
            if line.startswith(MANIFEST_MARKER):
                skip_manifest = True
                continue
            elif skip_manifest and line.startswith('#'):
                continue
            else:
                skip_manifest = False
                result.append(line)
        
        return '\n'.join(result).lstrip('\n')


# ==================== Code Verifier ====================

class CodeVerifier:
    """Verifies Python source code signatures at runtime."""
    
    def __init__(self, public_key_path: Optional[str] = None, strict_mode: bool = True):
        """
        Initialize code verifier.
        
        Args:
            public_key_path: Path to public key PEM file (None = use dev key)
            strict_mode: Reject unsigned code (True) or warn only (False)
        """
        self.public_key = self._load_public_key(public_key_path)
        self.strict_mode = strict_mode
        self.verified_files = set()
        self.failed_files = set()
    
    def _load_public_key(self, key_path: Optional[str]) -> ec.EllipticCurvePublicKey:
        """Load public key from file or use dev key."""
        if key_path and os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                key_data = f.read()
        else:
            # Development mode: Use embedded test key
            key_data = DEV_PUBLIC_KEY_PEM.encode('utf-8')
        
        return serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
    
    def verify_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Verify signature of Python source file.
        
        Args:
            file_path: Path to .py file
        
        Returns:
            (success, error_message)
        """
        try:
            # Read source code
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Extract manifest
            match = SIGNATURE_PATTERN.search(source_code)
            if not match:
                return False, "No manifest found"
            
            version = match.group('version')
            algorithm = match.group('algorithm')
            signature_hex = match.group('signature')
            
            # Validate version
            if version != MANIFEST_VERSION:
                return False, f"Unsupported manifest version: {version}"
            
            # Validate algorithm
            if algorithm != DEFAULT_ALGORITHM:
                return False, f"Unsupported algorithm: {algorithm}"
            
            # Extract source code without manifest
            source_without_manifest = self._extract_source_without_manifest(source_code)
            
            # Verify signature
            signature_bytes = bytes.fromhex(signature_hex)
            source_bytes = source_without_manifest.encode('utf-8')
            digest = hashlib.sha256(source_bytes).digest()
            
            try:
                self.public_key.verify(
                    signature_bytes,
                    digest,
                    ec.ECDSA(hashes.SHA256())
                )
                self.verified_files.add(file_path)
                return True, None
            
            except InvalidSignature:
                self.failed_files.add(file_path)
                return False, "Invalid signature (code tampered)"
        
        except Exception as e:
            self.failed_files.add(file_path)
            return False, f"Verification error: {str(e)}"
    
    def verify_source_code(self, source_code: str) -> Tuple[bool, Optional[str]]:
        """
        Verify signature of source code string.
        
        Args:
            source_code: Python source code with embedded manifest
        
        Returns:
            (success, error_message)
        """
        try:
            # Extract manifest
            match = SIGNATURE_PATTERN.search(source_code)
            if not match:
                return False, "No manifest found"
            
            signature_hex = match.group('signature')
            
            # Extract source without manifest
            source_without_manifest = self._extract_source_without_manifest(source_code)
            
            # Verify signature
            signature_bytes = bytes.fromhex(signature_hex)
            source_bytes = source_without_manifest.encode('utf-8')
            digest = hashlib.sha256(source_bytes).digest()
            
            try:
                self.public_key.verify(
                    signature_bytes,
                    digest,
                    ec.ECDSA(hashes.SHA256())
                )
                return True, None
            
            except InvalidSignature:
                return False, "Invalid signature (code tampered)"
        
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def _extract_source_without_manifest(self, source_code: str) -> str:
        """Extract source code without manifest header."""
        lines = source_code.split('\n')
        result = []
        skip_manifest = False
        
        for line in lines:
            if line.startswith(MANIFEST_MARKER):
                skip_manifest = True
                continue
            elif skip_manifest and line.startswith('#'):
                continue
            else:
                skip_manifest = False
                result.append(line)
        
        return '\n'.join(result).lstrip('\n')
    
    def get_statistics(self) -> Dict[str, int]:
        """Get verification statistics."""
        return {
            'verified': len(self.verified_files),
            'failed': len(self.failed_files),
            'total': len(self.verified_files) + len(self.failed_files)
        }


# ==================== Import Hook (Runtime Protection) ====================

class SecureImportHook:
    """Import hook that verifies code signatures before execution."""
    
    def __init__(self, verifier: CodeVerifier):
        """
        Initialize import hook.
        
        Args:
            verifier: CodeVerifier instance
        """
        self.verifier = verifier
        self.original_loader = importlib.machinery.SourceFileLoader
    
    def install(self):
        """Install import hook into sys.meta_path."""
        sys.meta_path.insert(0, self)
    
    def uninstall(self):
        """Remove import hook from sys.meta_path."""
        if self in sys.meta_path:
            sys.meta_path.remove(self)
    
    def find_module(self, fullname, path=None):
        """Find module (required by import hook protocol)."""
        # Let default finder handle this
        return None
    
    def find_spec(self, fullname, path, target=None):
        """Find module spec and verify signature."""
        # Use default finder
        spec = importlib.util.find_spec(fullname)
        
        if spec and spec.origin and spec.origin.endswith('.py'):
            # Verify signature before allowing import
            success, error = self.verifier.verify_file(spec.origin)
            
            if not success:
                if self.verifier.strict_mode:
                    raise ImportError(
                        f"Code verification failed for {fullname}: {error}\n"
                        f"File: {spec.origin}\n"
                        f"Refusing to load unsigned/tampered code."
                    )
                else:
                    print(f"WARNING: Code verification failed for {fullname}: {error}")
        
        return spec


# ==================== CLI Commands ====================

def sign_command(args):
    """Sign files command."""
    signer = CodeSigner(args.private_key)
    
    if args.file:
        # Sign single file
        success = signer.sign_file(args.file, args.output)
        if success:
            print(f"✓ Signed: {args.file}")
        else:
            print(f"✗ Failed to sign: {args.file}")
            return 1
    
    elif args.directory:
        # Sign directory
        results = signer.sign_directory(args.directory, args.recursive)
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        print(f"\nSigned {success_count}/{total_count} files:")
        for file_path, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {file_path}")
        
        return 0 if success_count == total_count else 1
    
    return 0


def verify_command(args):
    """Verify files command."""
    verifier = CodeVerifier(args.public_key, strict_mode=False)
    
    if args.file:
        # Verify single file
        success, error = verifier.verify_file(args.file)
        if success:
            print(f"✓ Valid signature: {args.file}")
        else:
            print(f"✗ Invalid signature: {args.file}")
            print(f"  Error: {error}")
            return 1
    
    elif args.directory:
        # Verify directory
        pattern = "**/*.py" if args.recursive else "*.py"
        files = list(Path(args.directory).glob(pattern))
        
        results = []
        for file_path in files:
            success, error = verifier.verify_file(str(file_path))
            results.append((str(file_path), success, error))
        
        success_count = sum(1 for _, s, _ in results if s)
        total_count = len(results)
        
        print(f"\nVerified {success_count}/{total_count} files:")
        for file_path, success, error in results:
            status = "✓" if success else "✗"
            print(f"  {status} {file_path}")
            if not success and args.verbose:
                print(f"      Error: {error}")
        
        return 0 if success_count == total_count else 1
    
    return 0


def keygen_command(args):
    """Generate key pair command."""
    # Generate ECDSA key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write keys
    with open(args.private_key, 'wb') as f:
        f.write(private_pem)
    
    with open(args.public_key, 'wb') as f:
        f.write(public_pem)
    
    print(f"✓ Generated key pair:")
    print(f"  Private key: {args.private_key}")
    print(f"  Public key:  {args.public_key}")
    
    return 0


# ==================== Main CLI ====================

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='VCC Code Manifest System - Sign and verify Python source code'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign Python files')
    sign_parser.add_argument('--file', help='Sign single file')
    sign_parser.add_argument('--directory', help='Sign directory')
    sign_parser.add_argument('--recursive', action='store_true', help='Recursive directory signing')
    sign_parser.add_argument('--private-key', help='Private key PEM file')
    sign_parser.add_argument('--output', help='Output file (for single file signing)')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify Python files')
    verify_parser.add_argument('--file', help='Verify single file')
    verify_parser.add_argument('--directory', help='Verify directory')
    verify_parser.add_argument('--recursive', action='store_true', help='Recursive directory verification')
    verify_parser.add_argument('--public-key', help='Public key PEM file')
    verify_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    # Keygen command
    keygen_parser = subparsers.add_parser('keygen', help='Generate key pair')
    keygen_parser.add_argument('--private-key', default='code_signing_private.pem', help='Private key output')
    keygen_parser.add_argument('--public-key', default='code_signing_public.pem', help='Public key output')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == 'sign':
        return sign_command(args)
    elif args.command == 'verify':
        return verify_command(args)
    elif args.command == 'keygen':
        return keygen_command(args)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
