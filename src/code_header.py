#!/usr/bin/env python3
"""
VCC Code Header System - Enhanced Metadata & Copyright Protection

Erweitert Code-Signing um umfassende Metadaten:
- Copyright & License Information
- Version Management (Semantic Versioning)
- Unique File Identification (UUID, Content Hash)
- Tamper-Evident Checksums
- Build/Release Information
- Digital Rights Management (DRM) Metadata

Author: VCC Security Team
Version: 1.0.0
Date: 2025-10-13
"""

import os
import sys
import hashlib
import uuid
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field

# Cryptography imports
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: cryptography library not installed")
    print("Install: pip install cryptography")
    sys.exit(1)


# ============================================================================
#                           DATA STRUCTURES
# ============================================================================

@dataclass
class CopyrightInfo:
    """Copyright and licensing information."""
    holder: str = "VCC - Veritas Control Center"
    year: int = 2025
    license: str = "Proprietary"
    license_url: Optional[str] = None
    contact: Optional[str] = "legal@vcc.local"
    
    def to_comment(self) -> List[str]:
        """Generate copyright comment lines."""
        lines = [
            f"# Copyright (c) {self.year} {self.holder}",
            f"# License: {self.license}"
        ]
        if self.license_url:
            lines.append(f"# License URL: {self.license_url}")
        if self.contact:
            lines.append(f"# Contact: {self.contact}")
        return lines


@dataclass
class VersionInfo:
    """Semantic versioning information."""
    major: int = 1
    minor: int = 0
    patch: int = 0
    prerelease: Optional[str] = None  # e.g., "alpha", "beta.1", "rc.2"
    build_metadata: Optional[str] = None  # e.g., "20251013.1", "commit.abc123"
    
    @property
    def version(self) -> str:
        """Get semantic version string (e.g., 1.2.3-beta.1+build.123)."""
        ver = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            ver += f"-{self.prerelease}"
        if self.build_metadata:
            ver += f"+{self.build_metadata}"
        return ver
    
    def to_comment(self) -> List[str]:
        """Generate version comment lines."""
        return [
            f"# Version: {self.version}",
            f"# Semantic Version: {self.major}.{self.minor}.{self.patch}"
        ]


@dataclass
class FileIdentity:
    """Unique file identification metadata."""
    file_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    content_hash_sha256: str = ""
    content_hash_sha512: str = ""
    file_size: int = 0
    line_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    modified_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def compute_hashes(self, content: str) -> None:
        """Compute content hashes."""
        content_bytes = content.encode('utf-8')
        self.content_hash_sha256 = hashlib.sha256(content_bytes).hexdigest()
        self.content_hash_sha512 = hashlib.sha512(content_bytes).hexdigest()
        self.file_size = len(content_bytes)
        self.line_count = content.count('\n')
    
    def to_comment(self) -> List[str]:
        """Generate identity comment lines."""
        return [
            f"# File UUID: {self.file_uuid}",
            f"# Content Hash (SHA-256): {self.content_hash_sha256}",
            f"# Content Hash (SHA-512): {self.content_hash_sha512}",
            f"# File Size: {self.file_size} bytes",
            f"# Line Count: {self.line_count}",
            f"# Created: {self.created_at}",
            f"# Modified: {self.modified_at}"
        ]


@dataclass
class BuildInfo:
    """Build and release metadata."""
    build_number: Optional[str] = None
    build_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    builder: Optional[str] = None  # CI/CD system or developer name
    build_host: Optional[str] = None
    git_commit: Optional[str] = None
    git_branch: Optional[str] = None
    git_tag: Optional[str] = None
    release_channel: str = "development"  # development, staging, production
    
    def to_comment(self) -> List[str]:
        """Generate build info comment lines."""
        lines = [
            f"# Build Date: {self.build_date}",
            f"# Release Channel: {self.release_channel}"
        ]
        if self.build_number:
            lines.append(f"# Build Number: {self.build_number}")
        if self.builder:
            lines.append(f"# Builder: {self.builder}")
        if self.git_commit:
            lines.append(f"# Git Commit: {self.git_commit[:8]}")
        if self.git_branch:
            lines.append(f"# Git Branch: {self.git_branch}")
        if self.git_tag:
            lines.append(f"# Git Tag: {self.git_tag}")
        return lines


@dataclass
class AuthorInfo:
    """Author and maintainer information."""
    author: str = "VCC Development Team"
    author_email: Optional[str] = "dev@vcc.local"
    maintainer: Optional[str] = None
    maintainer_email: Optional[str] = None
    contributors: List[str] = field(default_factory=list)
    
    def to_comment(self) -> List[str]:
        """Generate author comment lines."""
        lines = [f"# Author: {self.author}"]
        if self.author_email:
            lines.append(f"# Author Email: {self.author_email}")
        if self.maintainer:
            lines.append(f"# Maintainer: {self.maintainer}")
            if self.maintainer_email:
                lines.append(f"# Maintainer Email: {self.maintainer_email}")
        if self.contributors:
            lines.append(f"# Contributors: {', '.join(self.contributors[:3])}")
            if len(self.contributors) > 3:
                lines.append(f"#   ... and {len(self.contributors) - 3} more")
        return lines


@dataclass
class SecurityInfo:
    """Security and DRM metadata."""
    classification: str = "INTERNAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, SECRET
    security_contact: Optional[str] = "security@vcc.local"
    drm_enabled: bool = True
    allowed_domains: List[str] = field(default_factory=lambda: ["vcc.local"])
    expiration_date: Optional[str] = None  # ISO format
    required_python_version: str = ">=3.8"
    dependencies_hash: Optional[str] = None  # Hash of requirements.txt
    
    def to_comment(self) -> List[str]:
        """Generate security comment lines."""
        lines = [
            f"# Classification: {self.classification}",
            f"# DRM Protected: {'Yes' if self.drm_enabled else 'No'}"
        ]
        if self.security_contact:
            lines.append(f"# Security Contact: {self.security_contact}")
        if self.allowed_domains:
            lines.append(f"# Allowed Domains: {', '.join(self.allowed_domains)}")
        if self.expiration_date:
            lines.append(f"# Expires: {self.expiration_date}")
        lines.append(f"# Required Python: {self.required_python_version}")
        return lines


@dataclass
class CodeHeader:
    """Complete code header with all metadata."""
    # Core components
    copyright_info: CopyrightInfo = field(default_factory=CopyrightInfo)
    version_info: VersionInfo = field(default_factory=VersionInfo)
    file_identity: FileIdentity = field(default_factory=FileIdentity)
    build_info: BuildInfo = field(default_factory=BuildInfo)
    author_info: AuthorInfo = field(default_factory=AuthorInfo)
    security_info: SecurityInfo = field(default_factory=SecurityInfo)
    
    # Code signing (from code_manifest.py)
    signature_version: str = "v1"
    signature_algorithm: str = "ECDSA_SHA256"
    signature: Optional[str] = None
    signed_at: Optional[str] = None
    signer_id: Optional[str] = None  # Email or certificate CN
    
    # File metadata
    file_path: Optional[str] = None
    module_name: Optional[str] = None
    description: Optional[str] = None
    
    def to_header_block(self, include_signature: bool = True) -> str:
        """
        Generate complete header block as Python comment.
        
        Args:
            include_signature: Include VCC-MANIFEST signature line
            
        Returns:
            Multi-line header block with all metadata
        """
        lines = []
        
        # Header separator
        lines.append("# " + "=" * 76)
        lines.append("# VCC PROTECTED SOURCE CODE")
        lines.append("# " + "=" * 76)
        lines.append("#")
        
        # Copyright
        lines.extend(self.copyright_info.to_comment())
        lines.append("#")
        
        # Module info
        if self.module_name:
            lines.append(f"# Module: {self.module_name}")
        if self.description:
            lines.append(f"# Description: {self.description}")
        if self.file_path:
            lines.append(f"# File Path: {self.file_path}")
        if self.module_name or self.description or self.file_path:
            lines.append("#")
        
        # Version
        lines.extend(self.version_info.to_comment())
        lines.append("#")
        
        # Author
        lines.extend(self.author_info.to_comment())
        lines.append("#")
        
        # Build Info
        lines.extend(self.build_info.to_comment())
        lines.append("#")
        
        # File Identity
        lines.extend(self.file_identity.to_comment())
        lines.append("#")
        
        # Security
        lines.extend(self.security_info.to_comment())
        lines.append("#")
        
        # Signature (if present and requested)
        if include_signature and self.signature:
            lines.append("# " + "-" * 76)
            lines.append("# DIGITAL SIGNATURE")
            lines.append("# " + "-" * 76)
            lines.append(f"# VCC-MANIFEST: {self.signature_version} {self.signature_algorithm} {self.signature}")
            if self.signed_at:
                lines.append(f"# Signed: {self.signed_at}")
            if self.signer_id:
                lines.append(f"# Signer: {self.signer_id}")
            lines.append("# WARNING: This file is cryptographically signed.")
            lines.append("# Any modification will invalidate the signature and may prevent execution.")
            lines.append("#")
        
        # Footer separator
        lines.append("# " + "=" * 76)
        lines.append("")  # Empty line after header
        
        return '\n'.join(lines)
    
    def to_json(self) -> str:
        """Export metadata as JSON (for external manifests)."""
        data = {
            'copyright': asdict(self.copyright_info),
            'version': asdict(self.version_info),
            'identity': asdict(self.file_identity),
            'build': asdict(self.build_info),
            'author': asdict(self.author_info),
            'security': asdict(self.security_info),
            'signature': {
                'version': self.signature_version,
                'algorithm': self.signature_algorithm,
                'signature': self.signature,
                'signed_at': self.signed_at,
                'signer_id': self.signer_id
            },
            'file': {
                'path': self.file_path,
                'module': self.module_name,
                'description': self.description
            }
        }
        return json.dumps(data, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CodeHeader':
        """Import metadata from JSON."""
        data = json.loads(json_str)
        
        header = cls()
        header.copyright_info = CopyrightInfo(**data['copyright'])
        header.version_info = VersionInfo(**data['version'])
        header.file_identity = FileIdentity(**data['identity'])
        header.build_info = BuildInfo(**data['build'])
        header.author_info = AuthorInfo(**data['author'])
        header.security_info = SecurityInfo(**data['security'])
        
        sig = data.get('signature', {})
        header.signature_version = sig.get('version', 'v1')
        header.signature_algorithm = sig.get('algorithm', 'ECDSA_SHA256')
        header.signature = sig.get('signature')
        header.signed_at = sig.get('signed_at')
        header.signer_id = sig.get('signer_id')
        
        file_info = data.get('file', {})
        header.file_path = file_info.get('path')
        header.module_name = file_info.get('module')
        header.description = file_info.get('description')
        
        return header


# ============================================================================
#                           HEADER EXTRACTION
# ============================================================================

class HeaderExtractor:
    """Extract and parse VCC code headers from Python files."""
    
    # Regex patterns
    HEADER_START = re.compile(r'^# ={76}$')
    HEADER_END = re.compile(r'^# ={76}$')
    VCC_PROTECTED = re.compile(r'^# VCC PROTECTED SOURCE CODE$')
    
    # Metadata patterns
    COPYRIGHT_PATTERN = re.compile(r'^# Copyright \(c\) (\d+) (.+)$')
    VERSION_PATTERN = re.compile(r'^# Version: (.+)$')
    FILE_UUID_PATTERN = re.compile(r'^# File UUID: ([0-9a-f-]+)$')
    HASH_SHA256_PATTERN = re.compile(r'^# Content Hash \(SHA-256\): ([0-9a-f]+)$')
    HASH_SHA512_PATTERN = re.compile(r'^# Content Hash \(SHA-512\): ([0-9a-f]+)$')
    MANIFEST_PATTERN = re.compile(
        r'^# VCC-MANIFEST:\s*(?P<version>v\d+)\s+(?P<algorithm>[A-Z0-9_]+)\s+(?P<signature>[A-Fa-f0-9]+)\s*$'
    )
    
    @staticmethod
    def extract_header(source_code: str) -> Optional[Tuple[CodeHeader, str]]:
        """
        Extract VCC header from source code.
        Removes ALL VCC headers (handles duplicates).
        
        Args:
            source_code: Complete Python source code
            
        Returns:
            Tuple of (CodeHeader, source_without_header) or None if no header found
        """
        lines = source_code.split('\n')
        
        # Find ALL headers and collect them
        headers = []
        i = 0
        
        while i < len(lines):
            # Check for header start (first ===)
            if HeaderExtractor.HEADER_START.match(lines[i]):
                start_idx = i
                found_vcc_marker = False
                end_idx = None
                
                # Look for VCC marker (should be within first 5 lines)
                for j in range(i, min(i + 5, len(lines))):
                    if HeaderExtractor.VCC_PROTECTED.match(lines[j]):
                        found_vcc_marker = True
                        break
                
                if not found_vcc_marker:
                    i += 1
                    continue
                
                # Now find the CLOSING === (after VCC marker)
                for j in range(i + 3, len(lines)):  # Start search after opening ===
                    if HeaderExtractor.HEADER_END.match(lines[j]):
                        end_idx = j
                        break
                
                if end_idx is not None:
                    # Extract this header
                    header_lines = lines[start_idx:end_idx + 1]
                    header = HeaderExtractor._parse_header_lines(header_lines)
                    headers.append(header)
                    
                    # Skip to after header
                    i = end_idx + 1
                    
                    # Skip empty line after header
                    if i < len(lines) and lines[i].strip() == '':
                        i += 1
                else:
                    i += 1
            else:
                # Found non-header content, stop looking
                break
        
        if not headers:
            return None  # No VCC header found
        
        # Return last header (most recent) and source without any headers
        source_without_headers = '\n'.join(lines[i:])
        return (headers[-1], source_without_headers)
    
    @staticmethod
    def _parse_header_lines(lines: List[str]) -> CodeHeader:
        """Parse header lines into CodeHeader object."""
        header = CodeHeader()
        
        for line in lines:
            # DON'T strip here - patterns expect leading #
            
            # Copyright
            match = HeaderExtractor.COPYRIGHT_PATTERN.match(line)
            if match:
                header.copyright_info.year = int(match.group(1))
                header.copyright_info.holder = match.group(2)
                continue
            
            # Version
            match = HeaderExtractor.VERSION_PATTERN.match(line)
            if match:
                version_str = match.group(1)
                # Parse semantic version (simplified)
                parts = version_str.split('.')
                if len(parts) >= 3:
                    header.version_info.major = int(parts[0])
                    header.version_info.minor = int(parts[1])
                    header.version_info.patch = int(parts[2].split('-')[0].split('+')[0])
                continue
            
            # File UUID
            match = HeaderExtractor.FILE_UUID_PATTERN.match(line)
            if match:
                header.file_identity.file_uuid = match.group(1)
                continue
            
            # SHA-256 Hash
            match = HeaderExtractor.HASH_SHA256_PATTERN.match(line)
            if match:
                header.file_identity.content_hash_sha256 = match.group(1)
                continue
            
            # SHA-512 Hash
            match = HeaderExtractor.HASH_SHA512_PATTERN.match(line)
            if match:
                header.file_identity.content_hash_sha512 = match.group(1)
                continue
            
            # Manifest/Signature
            match = HeaderExtractor.MANIFEST_PATTERN.match(line)
            if match:
                header.signature_version = match.group('version')
                header.signature_algorithm = match.group('algorithm')
                header.signature = match.group('signature')
                continue
            
            # Add more parsers as needed...
        
        return header
    
    @staticmethod
    def has_vcc_header(source_code: str) -> bool:
        """Check if source code has VCC header."""
        lines = source_code.split('\n')
        if len(lines) < 3:
            return False
        
        # Check first 5 lines for VCC marker
        for line in lines[:5]:
            if HeaderExtractor.VCC_PROTECTED.match(line):
                return True
        
        return False


# ============================================================================
#                           HEADER BUILDER
# ============================================================================

class HeaderBuilder:
    """Builder for creating code headers with fluent API."""
    
    def __init__(self):
        self.header = CodeHeader()
    
    def copyright(self, holder: str, year: int = 2025, license: str = "Proprietary") -> 'HeaderBuilder':
        """Set copyright information."""
        self.header.copyright_info.holder = holder
        self.header.copyright_info.year = year
        self.header.copyright_info.license = license
        return self
    
    def version(self, major: int, minor: int, patch: int, prerelease: str = None) -> 'HeaderBuilder':
        """Set semantic version."""
        self.header.version_info.major = major
        self.header.version_info.minor = minor
        self.header.version_info.patch = patch
        self.header.version_info.prerelease = prerelease
        return self
    
    def author(self, name: str, email: str = None) -> 'HeaderBuilder':
        """Set author information."""
        self.header.author_info.author = name
        self.header.author_info.author_email = email
        return self
    
    def module(self, name: str, description: str = None) -> 'HeaderBuilder':
        """Set module information."""
        self.header.module_name = name
        self.header.description = description
        return self
    
    def build_info(self, build_number: str = None, git_commit: str = None, channel: str = "development") -> 'HeaderBuilder':
        """Set build information."""
        self.header.build_info.build_number = build_number
        self.header.build_info.git_commit = git_commit
        self.header.build_info.release_channel = channel
        return self
    
    def security(self, classification: str = "INTERNAL", drm_enabled: bool = True) -> 'HeaderBuilder':
        """Set security information."""
        self.header.security_info.classification = classification
        self.header.security_info.drm_enabled = drm_enabled
        return self
    
    def compute_identity(self, source_code: str) -> 'HeaderBuilder':
        """Compute file identity (hashes, size, etc.)."""
        self.header.file_identity.compute_hashes(source_code)
        return self
    
    def sign(self, signature: str, signer_id: str = None) -> 'HeaderBuilder':
        """Add digital signature."""
        self.header.signature = signature
        self.header.signed_at = datetime.now(timezone.utc).isoformat()
        self.header.signer_id = signer_id
        return self
    
    def build(self) -> CodeHeader:
        """Build and return the CodeHeader."""
        return self.header


# ============================================================================
#                           CLI INTERFACE
# ============================================================================

def main():
    """CLI interface for code header management."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="VCC Code Header System - Enhanced Metadata & Copyright Protection"
    )
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Generate header command
    gen_parser = subparsers.add_parser('generate', help='Generate header for file')
    gen_parser.add_argument('--file', required=True, help='Python file to add header to')
    gen_parser.add_argument('--output', help='Output file (default: overwrite input)')
    gen_parser.add_argument('--version', default='1.0.0', help='Semantic version (default: 1.0.0)')
    gen_parser.add_argument('--author', default='VCC Development Team', help='Author name')
    gen_parser.add_argument('--description', help='Module description')
    gen_parser.add_argument('--classification', default='INTERNAL', 
                           choices=['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET'],
                           help='Security classification')
    
    # Extract header command
    ext_parser = subparsers.add_parser('extract', help='Extract header from file')
    ext_parser.add_argument('--file', required=True, help='Python file to extract header from')
    ext_parser.add_argument('--format', choices=['text', 'json'], default='text', 
                           help='Output format')
    
    # Verify header command
    ver_parser = subparsers.add_parser('verify', help='Verify header integrity')
    ver_parser.add_argument('--file', required=True, help='Python file to verify')
    ver_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.command == 'generate':
        generate_header_for_file(args)
    elif args.command == 'extract':
        extract_header_from_file(args)
    elif args.command == 'verify':
        verify_header_integrity(args)
    else:
        parser.print_help()


def generate_header_for_file(args):
    """Generate and add header to file."""
    file_path = Path(args.file)
    
    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}")
        return
    
    # Read existing code
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    # Remove ALL existing headers (VCC headers + any copyright blocks)
    source_code = remove_all_headers(source_code)
    
    # Parse version
    version_parts = args.version.split('.')
    major = int(version_parts[0]) if len(version_parts) > 0 else 1
    minor = int(version_parts[1]) if len(version_parts) > 1 else 0
    patch = int(version_parts[2]) if len(version_parts) > 2 else 0
    
    # Build header
    builder = HeaderBuilder()
    builder.copyright("VCC - Veritas Control Center", 2025, "Proprietary")
    builder.version(major, minor, patch)
    builder.author(args.author)
    builder.module(file_path.stem, args.description)
    builder.security(args.classification)
    builder.compute_identity(source_code)
    
    header = builder.build()
    header.file_path = str(file_path)
    
    # Generate header block
    header_block = header.to_header_block(include_signature=False)
    
    # Combine header + code
    new_source = header_block + '\n' + source_code
    
    # Write to file
    output_path = Path(args.output) if args.output else file_path
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(new_source)
    
    print(f"[OK] Header generated for: {file_path}")
    print(f"  UUID: {header.file_identity.file_uuid}")
    print(f"  Version: {header.version_info.version}")
    print(f"  Hash: {header.file_identity.content_hash_sha256[:16]}...")
    print(f"  Classification: {header.security_info.classification}")


def remove_all_headers(source_code: str) -> str:
    """
    Remove ALL headers from source code (VCC headers + any copyright/license blocks).
    Aggressively removes all comment blocks at the start of the file.
    """
    lines = source_code.split('\n')
    
    # Skip ALL leading comment lines and empty lines
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Skip empty lines
        if line == '':
            i += 1
            continue
        
        # Skip comment lines
        if line.startswith('#'):
            i += 1
            continue
        
        # Skip shebang
        if line.startswith('#!'):
            i += 1
            continue
        
        # Found non-comment, non-empty line - stop
        break
    
    # Return source without leading comment blocks
    return '\n'.join(lines[i:])


def extract_header_from_file(args):
    """Extract header from file."""
    file_path = Path(args.file)
    
    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}")
        sys.exit(1)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    result = HeaderExtractor.extract_header(source_code)
    if not result:
        print(f"ERROR: No VCC header found in {file_path}")
        sys.exit(1)
    
    header, _ = result
    
    if args.format == 'json':
        print(header.to_json())
    else:
        print(f"File: {file_path}")
        print(f"UUID: {header.file_identity.file_uuid}")
        print(f"Version: {header.version_info.version}")
        print(f"Copyright: {header.copyright_info.holder} ({header.copyright_info.year})")
        print(f"License: {header.copyright_info.license}")
        print(f"Author: {header.author_info.author}")
        print(f"Classification: {header.security_info.classification}")
        if header.signature:
            print(f"Signature: {header.signature[:32]}...")
            print(f"Signed At: {header.signed_at}")
    
    sys.exit(0)


def verify_header_integrity(args):
    """Verify header integrity."""
    file_path = Path(args.file)
    
    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}")
        sys.exit(1)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    result = HeaderExtractor.extract_header(source_code)
    if not result:
        print(f"[ERROR] No VCC header found")
        sys.exit(1)
    
    header, source_without_header = result
    
    # Compute current hashes
    current_identity = FileIdentity()
    current_identity.compute_hashes(source_without_header)
    
    # Compare hashes
    stored_hash = header.file_identity.content_hash_sha256
    current_hash = current_identity.content_hash_sha256
    
    if stored_hash and current_hash:
        # Only check if stored hash exists
        if stored_hash.startswith(current_hash[:32]):
            print(f"[OK] Header integrity verified")
            print(f"  UUID: {header.file_identity.file_uuid}")
            print(f"  Hash: {current_hash[:32]}...")
            if args.verbose:
                print(f"  Full SHA-256: {current_hash}")
                print(f"  Full SHA-512: {current_identity.content_hash_sha512}")
            sys.exit(0)
        else:
            print(f"[ERROR] Header integrity FAILED")
            print(f"  Stored Hash:  {stored_hash[:32]}...")
            print(f"  Current Hash: {current_hash[:32]}...")
            print(f"  WARNING: File content has been modified!")
            sys.exit(1)
    else:
        print(f"[WARNING] Cannot verify integrity (no stored hash)")
        sys.exit(0)


if __name__ == '__main__':
    main()
