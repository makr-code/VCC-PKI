#!/usr/bin/env python3
"""
VCC PKI - Code Signing Integration Example

Example showing how to integrate code signing into an application.

This demonstrates:
1. Signing application code
2. Enabling runtime verification
3. Protecting critical functions
4. Handling verification failures

Author: VCC Team
Date: 2025-10-13
"""

import sys
import os

# Add src to path (adjust for your project structure)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from runtime_verifier import (
    enable_runtime_verification,
    get_verification_statistics,
    verified_execution,
    VerifiedContext
)


# ==================== Example 1: Basic Protection ====================

def example_basic_protection():
    """
    Example: Enable runtime verification for entire application.
    
    Place this at the very beginning of your main entry point.
    """
    print("\n" + "="*70)
    print("Example 1: Basic Runtime Protection")
    print("="*70)
    
    # Enable strict verification
    # This MUST be called BEFORE importing any application modules!
    enable_runtime_verification(strict=True)
    
    # Now all imports are automatically verified
    print("\n✓ Runtime verification enabled")
    print("  All subsequent imports will be verified")
    
    # Import your application modules here
    # import my_app
    # my_app.run()
    
    # Show statistics
    stats = get_verification_statistics()
    print(f"\nVerification Statistics:")
    print(f"  Mode: {'STRICT' if stats['strict_mode'] else 'PERMISSIVE'}")
    print(f"  Verified modules: {stats['verified_modules']}")
    print(f"  Failed modules:   {stats['failed_modules']}")


# ==================== Example 2: Protected Function ====================

@verified_execution
def critical_payment_function(amount: float):
    """
    Example: Protect critical function with decorator.
    
    This function will verify its source file signature before execution.
    """
    print(f"\n💰 Processing payment: €{amount:.2f}")
    print("   (This function's code was verified before execution)")
    return True


def example_protected_function():
    """Example: Use @verified_execution decorator."""
    print("\n" + "="*70)
    print("Example 2: Protected Critical Function")
    print("="*70)
    
    # Enable verification
    enable_runtime_verification(strict=True)
    
    # Call protected function
    try:
        result = critical_payment_function(1000.00)
        print(f"\n✓ Payment processed successfully: {result}")
    except RuntimeError as e:
        print(f"\n✗ Payment failed (code verification): {e}")


# ==================== Example 3: Temporary Verification ====================

def example_temporary_verification():
    """Example: Use context manager for temporary verification."""
    print("\n" + "="*70)
    print("Example 3: Temporary Verification (Context Manager)")
    print("="*70)
    
    print("\n1. Before verification context:")
    print("   Verification disabled")
    
    # Enable verification only for specific imports
    with VerifiedContext(strict=True):
        print("\n2. Inside verification context:")
        print("   Verification enabled")
        
        # Import untrusted module here
        # import untrusted_module
        # untrusted_module.process_data()
    
    print("\n3. After verification context:")
    print("   Verification disabled again")


# ==================== Example 4: Application Entry Point ====================

def example_application_entry_point():
    """
    Example: Proper application entry point with code verification.
    
    This is the recommended pattern for production applications.
    """
    print("\n" + "="*70)
    print("Example 4: Production Application Entry Point")
    print("="*70)
    
    # Step 1: Enable verification FIRST (before any imports)
    print("\n[STEP 1] Enabling runtime code verification...")
    enable_runtime_verification(
        strict=True,
        public_key_path=None  # Use dev key (replace with real key in production)
    )
    
    # Step 2: Import application modules (will be verified)
    print("\n[STEP 2] Importing application modules...")
    try:
        # In real application:
        # from my_app import main_application
        # from my_app.services import payment_service, user_service
        # from my_app.workers import background_worker
        
        print("   ✓ All imports verified successfully")
        
    except ImportError as e:
        print(f"   ✗ Import verification failed: {e}")
        print("\n   ACTION REQUIRED:")
        print("   1. Sign all application code:")
        print("      python src/code_manifest.py sign --directory . --recursive")
        print("   2. Restart application")
        sys.exit(1)
    
    # Step 3: Run application
    print("\n[STEP 3] Running application...")
    # main_application.run()
    
    # Step 4: Show verification statistics
    print("\n[STEP 4] Verification statistics:")
    stats = get_verification_statistics()
    print(f"   Verified modules: {stats['verified_modules']}")
    print(f"   Failed modules:   {stats['failed_modules']}")
    
    if stats['verified_list']:
        print("\n   Verified modules:")
        for module in stats['verified_list'][:5]:  # Show first 5
            print(f"      ✓ {module}")
        if len(stats['verified_list']) > 5:
            print(f"      ... and {len(stats['verified_list']) - 5} more")


# ==================== Example 5: Sign Application Code ====================

def example_sign_application():
    """
    Example: How to sign application code before deployment.
    
    Run this script to sign all Python files in your application.
    """
    print("\n" + "="*70)
    print("Example 5: Sign Application Code")
    print("="*70)
    
    print("\nTo sign your application code, run:")
    print("\n  # Sign all .py files in current directory")
    print("  python src/code_manifest.py sign --directory . --recursive")
    
    print("\n  # Sign specific file")
    print("  python src/code_manifest.py sign --file my_app.py")
    
    print("\n  # Generate production keys (DO THIS FIRST!)")
    print("  python src/code_manifest.py keygen \\")
    print("      --private-key production_private.pem \\")
    print("      --public-key production_public.pem")
    
    print("\n  # Sign with production key")
    print("  python src/code_manifest.py sign \\")
    print("      --directory . --recursive \\")
    print("      --private-key production_private.pem")
    
    print("\n⚠️  SECURITY NOTE:")
    print("   - Keep private key SECURE (HSM recommended)")
    print("   - Sign code in CI/CD pipeline")
    print("   - Never commit private key to git")
    print("   - Embed public key in application binary")


# ==================== Example 6: Verify Deployment ====================

def example_verify_deployment():
    """Example: Verify deployed application code."""
    print("\n" + "="*70)
    print("Example 6: Verify Deployed Application")
    print("="*70)
    
    print("\nTo verify deployed application code:")
    print("\n  # Verify all files")
    print("  python src/code_manifest.py verify --directory /app --recursive")
    
    print("\n  # Verify with production public key")
    print("  python src/code_manifest.py verify \\")
    print("      --directory /app --recursive \\")
    print("      --public-key production_public.pem \\")
    print("      --verbose")
    
    print("\nExpected output:")
    print("  ✓ Valid signature: /app/main.py")
    print("  ✓ Valid signature: /app/services/payment.py")
    print("  ✓ Valid signature: /app/workers/processor.py")
    print("  ...")
    print("  Verified 127/127 files")


# ==================== Example 7: CI/CD Integration ====================

def example_cicd_pipeline():
    """Example: CI/CD pipeline integration."""
    print("\n" + "="*70)
    print("Example 7: CI/CD Pipeline Integration")
    print("="*70)
    
    print("\nExample GitHub Actions workflow:")
    print("""
# .github/workflows/build.yml
name: Build and Sign

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Sign application code
        env:
          CODE_SIGNING_KEY: ${{ secrets.CODE_SIGNING_PRIVATE_KEY }}
        run: |
          echo "$CODE_SIGNING_KEY" > private_key.pem
          python src/code_manifest.py sign --directory . --recursive --private-key private_key.pem
          rm private_key.pem
      
      - name: Verify signatures
        run: |
          python src/code_manifest.py verify --directory . --recursive
      
      - name: Build Docker image
        run: docker build -t my-app:signed .
      
      - name: Push to registry
        run: docker push my-app:signed
    """)
    
    print("\n⚠️  SECURITY BEST PRACTICES:")
    print("   - Store private key in GitHub Secrets")
    print("   - Sign code in protected CI/CD environment")
    print("   - Verify signatures before deployment")
    print("   - Use separate keys for dev/staging/prod")


# ==================== Example 8: Handling Failures ====================

def example_handle_failures():
    """Example: How to handle verification failures."""
    print("\n" + "="*70)
    print("Example 8: Handling Verification Failures")
    print("="*70)
    
    print("\nScenario 1: Unsigned module")
    print("   Error: No manifest found")
    print("   Action: Sign the file")
    print("      python src/code_manifest.py sign --file module.py")
    
    print("\nScenario 2: Tampered module")
    print("   Error: Invalid signature (code tampered)")
    print("   Action: Re-sign with correct version")
    print("      git checkout module.py  # Restore original")
    print("      python src/code_manifest.py sign --file module.py")
    
    print("\nScenario 3: Development mode")
    print("   Solution: Use permissive mode during development")
    print("      enable_runtime_verification(strict=False)  # Warns only")
    
    print("\nScenario 4: Emergency bypass (NOT RECOMMENDED)")
    print("   Solution: Disable verification (DANGEROUS!)")
    print("      # Only for emergency debugging")
    print("      # disable_runtime_verification()")


# ==================== Main Menu ====================

def main():
    """Main example menu."""
    examples = [
        ("Basic Protection", example_basic_protection),
        ("Protected Function", example_protected_function),
        ("Temporary Verification", example_temporary_verification),
        ("Application Entry Point", example_application_entry_point),
        ("Sign Application", example_sign_application),
        ("Verify Deployment", example_verify_deployment),
        ("CI/CD Integration", example_cicd_pipeline),
        ("Handle Failures", example_handle_failures),
    ]
    
    print("\n" + "="*70)
    print("VCC PKI - Code Signing Integration Examples")
    print("="*70)
    print("\nAvailable examples:")
    
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    print(f"  {len(examples) + 1}. Run all examples")
    print("  0. Exit")
    
    try:
        choice = input("\nSelect example (0-{}): ".format(len(examples) + 1))
        choice = int(choice)
        
        if choice == 0:
            return
        elif 1 <= choice <= len(examples):
            _, func = examples[choice - 1]
            func()
        elif choice == len(examples) + 1:
            for name, func in examples:
                func()
        else:
            print("Invalid choice")
    
    except (ValueError, KeyboardInterrupt):
        print("\nExiting...")


if __name__ == '__main__':
    main()
