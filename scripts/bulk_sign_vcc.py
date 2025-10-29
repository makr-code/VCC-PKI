#!/usr/bin/env python3
"""
VCC Bulk Code Signing Script

Signs all Python files in VCC directory structure with:
1. Enhanced metadata headers (copyright, version, UUID, hashes, classification)
2. Cryptographic signatures (ECDSA with SHA-256)
3. Manifest system (inline verification)

Security Model:
- Asymmetric encryption: ECDSA (Elliptic Curve Digital Signature Algorithm)
- Private key: Signs files (must be kept secure)
- Public key: Verifies signatures at runtime
- Algorithm: ECDSA with SHA-256 (NIST P-256 curve)
- Signature embedded in header as hex string

Features:
- Auto-classification based on file content
- Batch signing with progress tracking
- Manifest database (JSON) for central tracking
- Selective signing (by classification, pattern, etc.)
- Verification before signing (detect already signed files)
- Detailed reporting (success, failure, skipped)

Usage:
    # Sign all Python files in VCC directory
    python bulk_sign_vcc.py --directory C:\\VCC --recursive
    
    # Sign only specific classifications
    python bulk_sign_vcc.py --directory C:\\VCC --classification CONFIDENTIAL SECRET
    
    # Sign with custom private key
    python bulk_sign_vcc.py --directory C:\\VCC --private-key path/to/key.pem
    
    # Dry run (preview without signing)
    python bulk_sign_vcc.py --directory C:\\VCC --dry-run
    
    # Generate manifest database
    python bulk_sign_vcc.py --directory C:\\VCC --generate-manifest

Author: VCC Development Team
Date: 2025-10-13
License: Proprietary
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
import hashlib

# Add src/ to path
SCRIPT_DIR = Path(__file__).parent.absolute()
SRC_DIR = SCRIPT_DIR.parent / 'src'
sys.path.insert(0, str(SRC_DIR))

# Import VCC signing and classification tools
try:
    from code_manifest import CodeSigner, CodeVerifier
    from code_header import HeaderExtractor
    from classify_code import CodeClassifier
except ImportError as e:
    print(f"ERROR: Cannot import VCC tools: {e}")
    print(f"Ensure code_manifest.py, code_header.py, and classify_code.py are in: {SRC_DIR}")
    sys.exit(1)


# ==================== Configuration ====================

DEFAULT_EXCLUDE_PATTERNS = [
    '__pycache__',
    '.git',
    '.venv',
    'venv',
    'env',
    'node_modules',
    '.pytest_cache',
    'build',
    'dist',
    '*.egg-info',
    'backup_*',
    'test_*',
    '*_tmp',
    '*_temp',
]

DEFAULT_CLASSIFICATIONS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET']

MANIFEST_DATABASE_FILENAME = 'vcc_code_manifest.json'


# ==================== Data Models ====================

@dataclass
class SigningResult:
    """Result of signing a single file."""
    file_path: str
    success: bool
    classification: str
    signature_hex: str
    file_uuid: str
    content_hash: str
    error_message: Optional[str] = None
    skipped: bool = False
    skip_reason: Optional[str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ManifestDatabase:
    """Central manifest database for all signed files."""
    version: str
    created_at: str
    last_updated: str
    total_files: int
    files: Dict[str, Dict]
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict):
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str):
        return cls.from_dict(json.loads(json_str))


# ==================== Bulk Signer ====================

class BulkCodeSigner:
    """Signs multiple Python files with progress tracking."""
    
    def __init__(
        self,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        exclude_patterns: Optional[List[str]] = None,
        dry_run: bool = False,
        verbose: bool = False
    ):
        """
        Initialize bulk signer.
        
        Args:
            private_key_path: Path to ECDSA private key (PEM format)
            public_key_path: Path to ECDSA public key (PEM format)
            exclude_patterns: File/directory patterns to exclude
            dry_run: Preview without actually signing
            verbose: Print detailed progress
        """
        # Allow None for dry-run mode
        self.signer = CodeSigner(private_key_path) if private_key_path else None
        self.verifier = CodeVerifier(public_key_path, strict_mode=False) if public_key_path else None
        self.classifier = CodeClassifier()
        self.exclude_patterns = exclude_patterns or DEFAULT_EXCLUDE_PATTERNS
        self.dry_run = dry_run
        self.verbose = verbose
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'signed': 0,
            'skipped': 0,
            'failed': 0,
            'by_classification': {
                'PUBLIC': 0,
                'INTERNAL': 0,
                'CONFIDENTIAL': 0,
                'SECRET': 0
            }
        }
        
        self.results: List[SigningResult] = []
    
    def should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded based on patterns."""
        path_str = str(file_path)
        
        for pattern in self.exclude_patterns:
            if pattern.startswith('*'):
                # Suffix match (e.g., *.pyc)
                if path_str.endswith(pattern[1:]):
                    return True
            elif pattern.endswith('*'):
                # Prefix match (e.g., test_*)
                if file_path.name.startswith(pattern[:-1]):
                    return True
            else:
                # Exact match or substring match
                if pattern in path_str:
                    return True
        
        return False
    
    def find_python_files(self, directory: str, recursive: bool = True) -> List[Path]:
        """
        Find all Python files in directory.
        
        Args:
            directory: Root directory to scan
            recursive: Recursively scan subdirectories
        
        Returns:
            List of .py file paths
        """
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(f"ERROR: Directory not found: {directory}")
            return []
        
        pattern = "**/*.py" if recursive else "*.py"
        files = []
        
        for file_path in dir_path.glob(pattern):
            if file_path.is_file() and not self.should_exclude(file_path):
                files.append(file_path)
        
        return sorted(files)
    
    def classify_file(self, file_path: Path) -> Tuple[str, float]:
        """
        Classify file to determine security level.
        
        Returns:
            (classification, confidence)
        """
        result = self.classifier.classify_file(str(file_path))
        return result.suggested_classification, result.confidence
    
    def is_already_signed(self, file_path: Path) -> bool:
        """Check if file already has valid signature."""
        success, error = self.verifier.verify_file(str(file_path))
        return success
    
    def sign_file(
        self,
        file_path: Path,
        classification: Optional[str] = None,
        force: bool = False
    ) -> SigningResult:
        """
        Sign a single file.
        
        Args:
            file_path: Path to .py file
            classification: Override auto-classification
            force: Re-sign even if already signed
        
        Returns:
            SigningResult with details
        """
        self.stats['total_files'] += 1
        
        # Check if already signed
        if not force and self.is_already_signed(file_path):
            if self.verbose:
                print(f"  [SKIP] Already signed: {file_path.name}")
            
            self.stats['skipped'] += 1
            return SigningResult(
                file_path=str(file_path),
                success=False,
                classification='UNKNOWN',
                signature_hex='',
                file_uuid='',
                content_hash='',
                skipped=True,
                skip_reason='Already signed'
            )
        
        # Auto-classify if not specified
        if not classification:
            classification, confidence = self.classify_file(file_path)
            
            if self.verbose:
                print(f"  [CLASSIFY] {file_path.name} → {classification} ({int(confidence * 100)}%)")
        
        # Dry run mode
        if self.dry_run:
            if self.verbose:
                print(f"  [DRY-RUN] Would sign: {file_path.name} as {classification}")
            
            self.stats['signed'] += 1
            self.stats['by_classification'][classification] += 1
            
            return SigningResult(
                file_path=str(file_path),
                success=True,
                classification=classification,
                signature_hex='DRY_RUN_SIGNATURE',
                file_uuid='DRY_RUN_UUID',
                content_hash='DRY_RUN_HASH',
                skipped=True,
                skip_reason='Dry run mode'
            )
        
        # Sign file
        try:
            success = self.signer.sign_file(
                str(file_path),
                enhanced_header=True,
                classification=classification,
                author='VCC Development Team',
                version='1.0.0'
            )
            
            if success:
                # Extract signature and metadata
                with open(file_path, 'r', encoding='utf-8') as f:
                    source_code = f.read()
                
                result = HeaderExtractor.extract_header(source_code)
                if result:
                    header, _ = result
                    
                    self.stats['signed'] += 1
                    self.stats['by_classification'][classification] += 1
                    
                    if self.verbose:
                        print(f"  [OK] Signed: {file_path.name}")
                    
                    return SigningResult(
                        file_path=str(file_path),
                        success=True,
                        classification=classification,
                        signature_hex=header.signature or 'N/A',
                        file_uuid=header.file_identity.file_uuid,
                        content_hash=header.file_identity.content_hash_sha256
                    )
                else:
                    raise Exception("Failed to extract header after signing")
            else:
                raise Exception("Signing returned False")
        
        except Exception as e:
            self.stats['failed'] += 1
            
            if self.verbose:
                print(f"  [ERROR] Failed to sign {file_path.name}: {e}")
            
            return SigningResult(
                file_path=str(file_path),
                success=False,
                classification=classification or 'UNKNOWN',
                signature_hex='',
                file_uuid='',
                content_hash='',
                error_message=str(e)
            )
    
    def sign_directory(
        self,
        directory: str,
        recursive: bool = True,
        classifications: Optional[List[str]] = None,
        force: bool = False
    ) -> List[SigningResult]:
        """
        Sign all Python files in directory.
        
        Args:
            directory: Root directory
            recursive: Scan subdirectories
            classifications: Only sign files with these classifications
            force: Re-sign already signed files
        
        Returns:
            List of SigningResult
        """
        print(f"\n{'=' * 80}")
        print(f"VCC Bulk Code Signing")
        print(f"{'=' * 80}\n")
        
        print(f"Directory: {directory}")
        print(f"Recursive: {recursive}")
        print(f"Dry Run: {self.dry_run}")
        print(f"Force: {force}")
        if classifications:
            print(f"Classifications: {', '.join(classifications)}")
        print()
        
        # Find files
        print("Scanning for Python files...")
        files = self.find_python_files(directory, recursive)
        print(f"Found {len(files)} Python files\n")
        
        if not files:
            print("No Python files found!")
            return []
        
        # Sign files
        print("Signing files...")
        print("-" * 80)
        print()
        
        for i, file_path in enumerate(files, 1):
            if self.verbose:
                print(f"[{i}/{len(files)}] {file_path.relative_to(directory)}")
            
            # Classify file
            classification, confidence = self.classify_file(file_path)
            
            # Skip if not in requested classifications
            if classifications and classification not in classifications:
                if self.verbose:
                    print(f"  [SKIP] Classification {classification} not requested\n")
                self.stats['skipped'] += 1
                continue
            
            # Sign file
            result = self.sign_file(file_path, classification, force)
            self.results.append(result)
            
            if not self.verbose:
                # Progress indicator
                if i % 10 == 0:
                    print(f"Progress: {i}/{len(files)} files processed...")
        
        print()
        print("-" * 80)
        self._print_summary()
        
        return self.results
    
    def _print_summary(self):
        """Print signing summary."""
        print()
        print("=" * 80)
        print("SIGNING SUMMARY")
        print("=" * 80)
        print()
        
        print(f"Total Files: {self.stats['total_files']}")
        print(f"  Signed:    {self.stats['signed']} ({self._percent(self.stats['signed'])})")
        print(f"  Skipped:   {self.stats['skipped']} ({self._percent(self.stats['skipped'])})")
        print(f"  Failed:    {self.stats['failed']} ({self._percent(self.stats['failed'])})")
        print()
        
        print("By Classification:")
        for level, count in self.stats['by_classification'].items():
            if count > 0:
                print(f"  {level:15} {count:3} files")
        print()
        
        if self.stats['failed'] > 0:
            print("Failed Files:")
            for result in self.results:
                if not result.success and not result.skipped:
                    print(f"  X {result.file_path}")
                    print(f"    Error: {result.error_message}")
            print()
    
    def _percent(self, count: int) -> str:
        """Calculate percentage of total."""
        if self.stats['total_files'] == 0:
            return "0%"
        pct = (count / self.stats['total_files']) * 100
        return f"{pct:.1f}%"
    
    def generate_manifest_database(self, output_path: Optional[str] = None) -> str:
        """
        Generate central manifest database (JSON).
        
        Args:
            output_path: Output path for JSON file
        
        Returns:
            Path to generated manifest file
        """
        if not output_path:
            output_path = MANIFEST_DATABASE_FILENAME
        
        # Build manifest
        files_dict = {}
        for result in self.results:
            if result.success and not result.skipped:
                files_dict[result.file_path] = {
                    'classification': result.classification,
                    'signature': result.signature_hex,
                    'uuid': result.file_uuid,
                    'content_hash': result.content_hash,
                    'timestamp': result.timestamp
                }
        
        manifest = ManifestDatabase(
            version='1.0.0',
            created_at=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat(),
            total_files=len(files_dict),
            files=files_dict
        )
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(manifest.to_json())
        
        print(f">>> Manifest database generated: {output_path}")
        print(f"  Total files: {manifest.total_files}")
        
        return output_path


# ==================== CLI ====================

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='VCC Bulk Code Signing Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign all files in VCC directory
  python bulk_sign_vcc.py --directory C:\\VCC --recursive
  
  # Sign only CONFIDENTIAL and SECRET files
  python bulk_sign_vcc.py --directory C:\\VCC --classification CONFIDENTIAL SECRET
  
  # Dry run (preview without signing)
  python bulk_sign_vcc.py --directory C:\\VCC --dry-run
  
  # Use custom private key
  python bulk_sign_vcc.py --directory C:\\VCC --private-key path/to/key.pem
  
  # Generate manifest database
  python bulk_sign_vcc.py --directory C:\\VCC --generate-manifest
        """
    )
    
    parser.add_argument(
        '--directory', '-d',
        required=True,
        help='Root directory to scan for Python files'
    )
    
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        default=True,
        help='Recursively scan subdirectories (default: True)'
    )
    
    parser.add_argument(
        '--classification', '-c',
        nargs='+',
        choices=['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET'],
        help='Only sign files with specified classifications'
    )
    
    parser.add_argument(
        '--private-key', '-k',
        help='Path to ECDSA private key (PEM format)'
    )
    
    parser.add_argument(
        '--public-key', '-p',
        help='Path to ECDSA public key (PEM format)'
    )
    
    parser.add_argument(
        '--exclude', '-e',
        nargs='+',
        help='Additional exclude patterns'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Re-sign files even if already signed'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview without actually signing files'
    )
    
    parser.add_argument(
        '--generate-manifest', '-m',
        action='store_true',
        help='Generate central manifest database (JSON)'
    )
    
    parser.add_argument(
        '--manifest-output', '-o',
        help='Output path for manifest database'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print detailed progress'
    )
    
    args = parser.parse_args()
    
    # Build exclude patterns
    exclude_patterns = DEFAULT_EXCLUDE_PATTERNS.copy()
    if args.exclude:
        exclude_patterns.extend(args.exclude)
    
    # Initialize signer
    signer = BulkCodeSigner(
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        exclude_patterns=exclude_patterns,
        dry_run=args.dry_run,
        verbose=args.verbose
    )
    
    # Sign directory
    results = signer.sign_directory(
        directory=args.directory,
        recursive=args.recursive,
        classifications=args.classification,
        force=args.force
    )
    
    # Generate manifest database
    if args.generate_manifest:
        print()
        signer.generate_manifest_database(args.manifest_output)
    
    # Exit code
    if signer.stats['failed'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
