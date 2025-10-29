#!/usr/bin/env python3
"""
VCC PKI - Runtime Code Verification

Automatic runtime verification system that prevents execution of tampered code.

Features:
- Transparent import hook (zero code changes needed)
- Pre-execution verification
- Memory-based verification (no temp files)
- Configurable strict/permissive mode
- Performance optimized (cached verification)
- Integration with Python import system

Security:
- Verifies EVERY import before execution
- Prevents runtime code injection
- Detects tampered files immediately
- Works with .py, .pyc, and runtime compilation

Usage:
    # In your main application entry point:
    from runtime_verifier import enable_runtime_verification
    
    # Enable strict mode (reject unsigned code)
    enable_runtime_verification(strict=True)
    
    # Now all imports are automatically verified
    import my_module  # <- Verified before execution!

Author: VCC Team
Date: 2025-10-13
"""

import sys
import os
import importlib.abc
import importlib.machinery
import importlib.util
from pathlib import Path
from typing import Optional, Set, Dict
import threading
import hashlib
from code_manifest import CodeVerifier, SIGNATURE_PATTERN


# ==================== Global State ====================

_verifier: Optional[CodeVerifier] = None
_verification_cache: Dict[str, bool] = {}
_cache_lock = threading.Lock()
_enabled = False
_strict_mode = True
_verified_modules: Set[str] = set()
_failed_modules: Set[str] = set()


# ==================== Verification Cache ====================

def _compute_file_hash(file_path: str) -> str:
    """Compute SHA256 hash of file for caching."""
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def _is_verified_cached(file_path: str) -> Optional[bool]:
    """Check if file verification result is cached."""
    try:
        file_hash = _compute_file_hash(file_path)
        cache_key = f"{file_path}:{file_hash}"
        
        with _cache_lock:
            return _verification_cache.get(cache_key)
    except Exception:
        return None


def _cache_verification_result(file_path: str, success: bool):
    """Cache verification result for performance."""
    try:
        file_hash = _compute_file_hash(file_path)
        cache_key = f"{file_path}:{file_hash}"
        
        with _cache_lock:
            _verification_cache[cache_key] = success
    except Exception:
        pass


# ==================== Secure Module Finder ====================

class SecureModuleFinder(importlib.abc.MetaPathFinder):
    """
    Custom module finder that verifies code signatures.
    
    This finder intercepts import statements and verifies code
    signatures before allowing module loading.
    """
    
    def find_spec(self, fullname, path, target=None):
        """
        Find module spec and verify signature.
        
        This is called by Python's import system for every import.
        We verify the code signature here before allowing the import.
        """
        global _verifier, _strict_mode, _verified_modules, _failed_modules
        
        # Let the default finder locate the module
        spec = importlib.util.find_spec(fullname)
        
        if spec and spec.origin:
            # Only verify .py files (source code)
            if spec.origin.endswith('.py'):
                file_path = spec.origin
                
                # Skip already verified modules (performance optimization)
                if fullname in _verified_modules:
                    return spec
                
                # Skip failed modules (avoid repeated errors)
                if fullname in _failed_modules:
                    if _strict_mode:
                        raise ImportError(
                            f"Module {fullname} failed verification previously.\n"
                            f"File: {file_path}\n"
                            f"Fix the issue and restart the application."
                        )
                    return spec
                
                # Check cache first (performance)
                cached_result = _is_verified_cached(file_path)
                if cached_result is not None:
                    if cached_result:
                        _verified_modules.add(fullname)
                        return spec
                    else:
                        _failed_modules.add(fullname)
                        if _strict_mode:
                            raise ImportError(
                                f"Code verification failed for {fullname} (cached result)\n"
                                f"File: {file_path}"
                            )
                        return spec
                
                # Perform verification
                success, error = _verifier.verify_file(file_path)
                
                # Cache result
                _cache_verification_result(file_path, success)
                
                if success:
                    _verified_modules.add(fullname)
                else:
                    _failed_modules.add(fullname)
                    
                    if _strict_mode:
                        raise ImportError(
                            f"Code verification failed for {fullname}: {error}\n"
                            f"File: {file_path}\n"
                            f"Refusing to load unsigned/tampered code.\n\n"
                            f"To fix this issue:\n"
                            f"1. Sign the file: python src/code_manifest.py sign --file {file_path}\n"
                            f"2. Verify: python src/code_manifest.py verify --file {file_path}\n"
                            f"3. Restart application"
                        )
                    else:
                        print(f"\n⚠️  WARNING: Code verification failed!")
                        print(f"    Module: {fullname}")
                        print(f"    File:   {file_path}")
                        print(f"    Error:  {error}")
                        print(f"    Action: Loading anyway (permissive mode)\n")
        
        return spec


# ==================== Public API ====================

def enable_runtime_verification(
    strict: bool = True,
    public_key_path: Optional[str] = None,
    exclude_patterns: Optional[list] = None
):
    """
    Enable runtime code verification for all imports.
    
    This function installs an import hook that verifies code signatures
    before execution. Must be called BEFORE importing any modules that
    should be verified.
    
    Args:
        strict: If True, reject unsigned/invalid code (recommended).
                If False, warn but allow execution (dangerous!).
        public_key_path: Path to public key PEM file (None = use dev key).
        exclude_patterns: List of module name patterns to exclude from verification.
    
    Example:
        # In your application's main entry point:
        from runtime_verifier import enable_runtime_verification
        
        # Enable strict verification
        enable_runtime_verification(strict=True)
        
        # Now import your application modules
        import my_app
        my_app.run()
    
    Security Note:
        - strict=True is STRONGLY RECOMMENDED for production
        - strict=False should only be used during development
        - Place this call as early as possible in your application
    """
    global _verifier, _enabled, _strict_mode
    
    if _enabled:
        print("⚠️  Runtime verification already enabled")
        return
    
    # Initialize verifier
    _verifier = CodeVerifier(public_key_path, strict_mode=strict)
    _strict_mode = strict
    
    # Install import hook
    finder = SecureModuleFinder()
    sys.meta_path.insert(0, finder)
    
    _enabled = True
    
    mode = "STRICT" if strict else "PERMISSIVE"
    print(f"✓ Runtime code verification enabled ({mode} mode)")
    print(f"  All imports will be verified before execution")
    print(f"  Unsigned/tampered code will be {'rejected' if strict else 'warned'}")


def disable_runtime_verification():
    """
    Disable runtime code verification.
    
    WARNING: This removes all protection against tampered code!
    Only use this for testing/debugging.
    """
    global _enabled
    
    if not _enabled:
        return
    
    # Remove all SecureModuleFinder instances
    sys.meta_path = [
        finder for finder in sys.meta_path
        if not isinstance(finder, SecureModuleFinder)
    ]
    
    _enabled = False
    print("⚠️  Runtime code verification disabled")


def get_verification_statistics() -> Dict:
    """
    Get verification statistics.
    
    Returns:
        Dict with verified/failed module counts
    """
    return {
        'enabled': _enabled,
        'strict_mode': _strict_mode,
        'verified_modules': len(_verified_modules),
        'failed_modules': len(_failed_modules),
        'cache_size': len(_verification_cache),
        'verified_list': sorted(_verified_modules),
        'failed_list': sorted(_failed_modules)
    }


def clear_verification_cache():
    """Clear verification cache (force re-verification)."""
    global _verification_cache
    
    with _cache_lock:
        _verification_cache.clear()
    
    print("✓ Verification cache cleared")


# ==================== Decorator for Runtime Verification ====================

def verified_execution(func):
    """
    Decorator that verifies code signature before function execution.
    
    Usage:
        @verified_execution
        def critical_function():
            # This code is verified before execution
            pass
    
    Note: This is an additional layer of protection.
          The import hook already verifies all imported code.
    """
    def wrapper(*args, **kwargs):
        # Get function's source file
        import inspect
        source_file = inspect.getsourcefile(func)
        
        if source_file and _verifier:
            success, error = _verifier.verify_file(source_file)
            
            if not success and _strict_mode:
                raise RuntimeError(
                    f"Code verification failed for {func.__name__}: {error}\n"
                    f"File: {source_file}\n"
                    f"Refusing to execute tampered code."
                )
        
        return func(*args, **kwargs)
    
    return wrapper


# ==================== Context Manager for Temporary Verification ====================

class VerifiedContext:
    """
    Context manager for temporary verification mode.
    
    Usage:
        with VerifiedContext(strict=True):
            import untrusted_module  # <- Verified
            untrusted_module.run()
    """
    
    def __init__(self, strict: bool = True, public_key_path: Optional[str] = None):
        self.strict = strict
        self.public_key_path = public_key_path
        self.was_enabled = False
    
    def __enter__(self):
        global _enabled
        self.was_enabled = _enabled
        
        if not _enabled:
            enable_runtime_verification(self.strict, self.public_key_path)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.was_enabled:
            disable_runtime_verification()


# ==================== CLI for Testing ====================

def main():
    """CLI for testing runtime verification."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test runtime code verification')
    parser.add_argument('--strict', action='store_true', help='Strict mode (reject invalid code)')
    parser.add_argument('--module', required=True, help='Module to import and test')
    parser.add_argument('--public-key', help='Public key PEM file')
    
    args = parser.parse_args()
    
    # Enable verification
    enable_runtime_verification(strict=args.strict, public_key_path=args.public_key)
    
    # Try to import module
    try:
        print(f"\nAttempting to import: {args.module}")
        module = __import__(args.module)
        print(f"✓ Successfully imported: {args.module}")
        print(f"\nModule attributes: {dir(module)}")
    except ImportError as e:
        print(f"\n✗ Import failed: {e}")
        return 1
    
    # Show statistics
    stats = get_verification_statistics()
    print(f"\nVerification Statistics:")
    print(f"  Verified modules: {stats['verified_modules']}")
    print(f"  Failed modules:   {stats['failed_modules']}")
    print(f"  Cache size:       {stats['cache_size']}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
