#!/usr/bin/env python3
"""
VCC Code Classification Tool

Automatically classify Python source files based on content analysis.
Helps developers choose the correct classification level.

Classification Levels:
- PUBLIC: Open source, no secrets
- INTERNAL: Internal tools, no business secrets
- CONFIDENTIAL: Business logic, proprietary algorithms
- SECRET: Critical infrastructure, key management

Usage:
    python classify_code.py --file my_module.py --suggest
    python classify_code.py --scan src/ --recursive --report
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


# ==================== Classification Rules ====================

@dataclass
class ClassificationResult:
    """Result of classification analysis."""
    file_path: str
    suggested_classification: str
    confidence: float  # 0.0 to 1.0
    reasons: List[str]
    warnings: List[str]
    keywords_found: List[str]


# Keywords that indicate classification level
SECRET_KEYWORDS = [
    # CA & Key Management
    'private_key', 'hsm', 'master_key', 'ca_sign', 'root_certificate',
    'secret_key_base', 'encryption_key', 'signing_key',
    
    # Authentication Core
    'authenticate_user', 'verify_password', 'generate_token',
    'session_secret', 'oauth_secret',
    
    # Critical Infrastructure
    'security_audit', 'access_control', 'zero_trust',
    'certificate_authority', 'tpm_', 'secure_enclave'
]

CONFIDENTIAL_KEYWORDS = [
    # Business Logic
    'proprietary', 'patent', 'competitive', 'trade_secret',
    'business_logic', 'pricing_algorithm', 'revenue',
    
    # Customer Data
    'customer_data', 'payment', 'credit_card', 'financial',
    'pii', 'personal_identifiable', 'gdpr',
    
    # Algorithms
    'ml_model', 'neural_network', 'prediction', 'recommendation',
    'optimization', 'analytics'
]

INTERNAL_KEYWORDS = [
    # Internal Tools
    'admin_tool', 'deployment', 'monitoring', 'logging',
    'config_manager', 'utility', 'helper',
    
    # Testing
    'test_', 'mock_', 'fixture', 'unittest'
]

PUBLIC_KEYWORDS = [
    # Open Source
    'mit_license', 'apache_license', 'bsd_license', 'gpl',
    'open_source',
    
    # Public APIs
    'public_api', 'client_library', 'sdk'
]

# Red flags - MUST NOT be in code
FORBIDDEN_PATTERNS = [
    # Hard-coded secrets
    (r'password\s*=\s*["\'](?!.*\$\{)[\w@#$%]{8,}["\']', 'Hard-coded password'),
    (r'api_key\s*=\s*["\'][A-Za-z0-9]{20,}["\']', 'Hard-coded API key'),
    (r'token\s*=\s*["\'][A-Za-z0-9]{20,}["\']', 'Hard-coded token'),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', 'Embedded private key'),
    (r'aws_secret_access_key\s*=', 'AWS secret key'),
    (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
]

# Open source license indicators
OPEN_SOURCE_LICENSES = [
    'MIT License', 'Apache License', 'BSD License', 'GPL',
    'LGPL', 'MPL', 'ISC License'
]


# ==================== Classification Engine ====================

class CodeClassifier:
    """Classify Python source code files."""
    
    def __init__(self):
        self.results = []
    
    def classify_file(self, file_path: str) -> ClassificationResult:
        """
        Classify a single Python file.
        
        Args:
            file_path: Path to .py file
            
        Returns:
            ClassificationResult with suggested classification
        """
        # Read file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Analyze
        reasons = []
        warnings = []
        keywords_found = []
        confidence = 0.5  # Default confidence
        
        # Check for forbidden patterns (CRITICAL)
        for pattern, description in FORBIDDEN_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return ClassificationResult(
                    file_path=file_path,
                    suggested_classification='ERROR',
                    confidence=1.0,
                    reasons=[f'SECURITY VIOLATION: {description}'],
                    warnings=[
                        'Hard-coded secrets detected!',
                        'Use environment variables or Vault!',
                        'DO NOT COMMIT THIS FILE!'
                    ],
                    keywords_found=[]
                )
        
        # Check filename patterns
        filename = os.path.basename(file_path)
        
        if filename.startswith('test_') or filename.endswith('_test.py'):
            return ClassificationResult(
                file_path=file_path,
                suggested_classification='INTERNAL',
                confidence=0.9,
                reasons=['Test file (filename pattern)'],
                warnings=[],
                keywords_found=[]
            )
        
        if 'example' in filename.lower():
            return ClassificationResult(
                file_path=file_path,
                suggested_classification='PUBLIC',
                confidence=0.8,
                reasons=['Example code (filename pattern)'],
                warnings=[],
                keywords_found=[]
            )
        
        # Check for open source license
        for license_name in OPEN_SOURCE_LICENSES:
            if license_name in content:
                reasons.append(f'Open source license detected: {license_name}')
                confidence = 0.95
                return ClassificationResult(
                    file_path=file_path,
                    suggested_classification='PUBLIC',
                    confidence=confidence,
                    reasons=reasons,
                    warnings=[],
                    keywords_found=[license_name]
                )
        
        # Score keywords
        secret_score = self._count_keywords(content, SECRET_KEYWORDS, keywords_found)
        confidential_score = self._count_keywords(content, CONFIDENTIAL_KEYWORDS, keywords_found)
        internal_score = self._count_keywords(content, INTERNAL_KEYWORDS, keywords_found)
        public_score = self._count_keywords(content, PUBLIC_KEYWORDS, keywords_found)
        
        # Determine classification
        if secret_score > 0:
            classification = 'SECRET'
            confidence = min(0.7 + (secret_score * 0.1), 1.0)
            reasons.append(f'SECRET keywords detected ({secret_score} matches)')
            if secret_score >= 3:
                reasons.append('High concentration of security-critical code')
        
        elif confidential_score > 0:
            classification = 'CONFIDENTIAL'
            confidence = min(0.6 + (confidential_score * 0.1), 0.95)
            reasons.append(f'CONFIDENTIAL keywords detected ({confidential_score} matches)')
            if confidential_score >= 3:
                reasons.append('Business logic or customer data processing detected')
        
        elif internal_score > 0:
            classification = 'INTERNAL'
            confidence = min(0.5 + (internal_score * 0.1), 0.9)
            reasons.append(f'INTERNAL keywords detected ({internal_score} matches)')
        
        elif public_score > 0:
            classification = 'PUBLIC'
            confidence = min(0.6 + (public_score * 0.1), 0.9)
            reasons.append(f'PUBLIC keywords detected ({public_score} matches)')
        
        else:
            # Default: INTERNAL
            classification = 'INTERNAL'
            confidence = 0.4
            reasons.append('No specific indicators found (default: INTERNAL)')
            warnings.append('Low confidence - manual review recommended')
        
        # Additional checks
        if 'TODO' in content or 'FIXME' in content:
            warnings.append('Contains TODOs/FIXMEs - review before classification')
        
        if len(content) < 500:
            warnings.append('Small file - may need manual review')
        
        return ClassificationResult(
            file_path=file_path,
            suggested_classification=classification,
            confidence=confidence,
            reasons=reasons,
            warnings=warnings,
            keywords_found=keywords_found
        )
    
    def _count_keywords(self, content: str, keywords: List[str], 
                       found_list: List[str]) -> int:
        """Count keyword matches in content."""
        count = 0
        content_lower = content.lower()
        
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword.replace('_', r'[_\s]')) + r'\b'
            if re.search(pattern, content_lower):
                count += 1
                found_list.append(keyword)
        
        return count
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[ClassificationResult]:
        """
        Scan directory for Python files and classify them.
        
        Args:
            directory: Path to directory
            recursive: Scan subdirectories
            
        Returns:
            List of ClassificationResults
        """
        results = []
        
        if recursive:
            pattern = '**/*.py'
        else:
            pattern = '*.py'
        
        for file_path in Path(directory).glob(pattern):
            if file_path.is_file():
                result = self.classify_file(str(file_path))
                results.append(result)
        
        self.results = results
        return results
    
    def generate_report(self, output_format: str = 'text') -> str:
        """
        Generate classification report.
        
        Args:
            output_format: 'text' or 'json'
            
        Returns:
            Formatted report string
        """
        if output_format == 'json':
            return json.dumps([asdict(r) for r in self.results], indent=2)
        
        # Text report
        lines = []
        lines.append("=" * 80)
        lines.append("VCC Code Classification Report")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 80)
        lines.append("")
        
        # Group by classification
        by_class = {}
        errors = []
        
        for result in self.results:
            if result.suggested_classification == 'ERROR':
                errors.append(result)
            else:
                if result.suggested_classification not in by_class:
                    by_class[result.suggested_classification] = []
                by_class[result.suggested_classification].append(result)
        
        # Errors first
        if errors:
            lines.append("SECURITY VIOLATIONS (CRITICAL):")
            lines.append("-" * 80)
            for result in errors:
                lines.append(f"  [ERROR] {result.file_path}")
                for reason in result.reasons:
                    lines.append(f"          {reason}")
                for warning in result.warnings:
                    lines.append(f"          WARNING: {warning}")
            lines.append("")
        
        # Classifications
        for classification in ['SECRET', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC']:
            if classification not in by_class:
                continue
            
            files = by_class[classification]
            lines.append(f"{classification} ({len(files)} files):")
            lines.append("-" * 80)
            
            for result in files:
                conf_pct = int(result.confidence * 100)
                lines.append(f"  [{classification}] {result.file_path} ({conf_pct}% confidence)")
                
                if result.reasons:
                    lines.append(f"              Reasons: {', '.join(result.reasons[:2])}")
                
                if result.warnings:
                    for warning in result.warnings:
                        lines.append(f"              WARNING: {warning}")
            
            lines.append("")
        
        # Summary
        lines.append("=" * 80)
        lines.append("SUMMARY:")
        lines.append(f"  Total Files: {len(self.results)}")
        if errors:
            lines.append(f"  ERRORS:      {len(errors)} (CRITICAL - FIX IMMEDIATELY!)")
        for classification in ['SECRET', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC']:
            if classification in by_class:
                lines.append(f"  {classification:13}: {len(by_class[classification])} files")
        lines.append("=" * 80)
        
        return '\n'.join(lines)


# ==================== CLI Interface ====================

def main():
    """CLI interface."""
    parser = argparse.ArgumentParser(
        description="VCC Code Classification Tool - Suggest classification levels"
    )
    
    parser.add_argument('--file', help='Classify single file')
    parser.add_argument('--scan', help='Scan directory')
    parser.add_argument('--recursive', action='store_true', 
                       help='Recursive scan (with --scan)')
    parser.add_argument('--suggest', action='store_true',
                       help='Show classification suggestion')
    parser.add_argument('--report', action='store_true',
                       help='Generate full report')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Report format (default: text)')
    parser.add_argument('--output', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    classifier = CodeClassifier()
    
    # Single file classification
    if args.file:
        result = classifier.classify_file(args.file)
        
        if result.suggested_classification == 'ERROR':
            print(f"\n🔥 SECURITY VIOLATION: {result.file_path}")
            print(f"\n{result.reasons[0]}")
            for warning in result.warnings:
                print(f"   {warning}")
            print("\nDO NOT COMMIT THIS FILE!")
            return 1
        
        print(f"\nFile: {result.file_path}")
        print(f"Suggested Classification: {result.suggested_classification}")
        print(f"Confidence: {int(result.confidence * 100)}%")
        
        if result.reasons:
            print(f"\nReasons:")
            for reason in result.reasons:
                print(f"  - {reason}")
        
        if result.keywords_found:
            print(f"\nKeywords Found: {', '.join(result.keywords_found[:5])}")
        
        if result.warnings:
            print(f"\nWarnings:")
            for warning in result.warnings:
                print(f"  ⚠️  {warning}")
        
        if args.suggest:
            print(f"\nRecommended Action:")
            print(f"  python code_header.py generate \\")
            print(f"      --file {result.file_path} \\")
            print(f"      --classification {result.suggested_classification} \\")
            print(f"      --version 1.0.0")
        
        return 0
    
    # Directory scan
    elif args.scan:
        print(f"Scanning: {args.scan} (recursive: {args.recursive})")
        results = classifier.scan_directory(args.scan, args.recursive)
        
        if args.report:
            report = classifier.generate_report(args.format)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"\nReport saved to: {args.output}")
            else:
                print(report)
        
        else:
            # Quick summary
            by_class = {}
            errors = 0
            
            for result in results:
                if result.suggested_classification == 'ERROR':
                    errors += 1
                else:
                    classification = result.suggested_classification
                    if classification not in by_class:
                        by_class[classification] = 0
                    by_class[classification] += 1
            
            print(f"\nClassification Summary:")
            print(f"  Total Files: {len(results)}")
            if errors > 0:
                print(f"  🔥 ERRORS:   {errors} (SECURITY VIOLATIONS!)")
            for classification in ['SECRET', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC']:
                if classification in by_class:
                    print(f"  {classification:13}: {by_class[classification]} files")
            
            if errors > 0:
                print(f"\n⚠️  Run with --report to see detailed error information!")
                return 1
        
        return 0
    
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    exit(main())
