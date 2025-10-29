"""Simple Test Example for VCC PKI

This example demonstrates the basic PKI workflow:
1. Create certificate
2. Sign document
3. Verify signature
"""

from pathlib import Path
from vcc_pki.api import PKIService

def main():
    print("🔐 VCC PKI - Simple Test Example\n")
    
    # 1. Initialize PKI Service (Mock Mode)
    print("1️⃣ Initializing PKI Service...")
    pki = PKIService(mode="mock")
    print()
    
    # 2. Create Certificate
    print("2️⃣ Creating Certificate...")
    cert_result = pki.create_certificate(
        common_name="test.covina.local",
        organization="Covina Framework",
        organizational_unit="Testing",
        validity_days=365
    )
    print(f"   ✅ Certificate created")
    print(f"   Serial: {cert_result['info']['serial']}")
    print(f"   Subject: {cert_result['subject']}\n")
    
    # 3. Create test document
    print("3️⃣ Creating test document...")
    test_doc = Path("test_document.txt")
    test_doc.write_text("This is a test document for VCC PKI signing.")
    print(f"   ✅ Document created: {test_doc}\n")
    
    # 4. Sign document
    print("4️⃣ Signing document...")
    signature = pki.sign_document(
        document_path=test_doc,
        certificate=cert_result["certificate"],
        private_key=cert_result["private_key"],
        metadata={"purpose": "testing", "example": "simple"}
    )
    print(f"   ✅ Document signed\n")
    
    # 5. Get signature info
    print("5️⃣ Signature Information:")
    sig_info = pki.get_signature_info(signature)
    print(f"   Algorithm: {sig_info['algorithm']}")
    print(f"   Document Hash: {sig_info['document_hash'][:32]}...")
    print(f"   Signer: {sig_info['signer'].get('CN')}")
    print(f"   Timestamp: {sig_info['timestamp']}")
    print(f"   Metadata: {sig_info['metadata']}\n")
    
    # 6. Verify signature (without certificate validation for now)
    print("6️⃣ Verifying signature...")
    is_valid = pki.verify_document(
        document_path=test_doc,
        signature=signature,
        certificate=cert_result["certificate"],
        check_certificate_validity=False  # Skip cert validation for this test
    )
    
    if is_valid:
        print("   ✅ Signature VALID!\n")
    else:
        print("   ❌ Signature INVALID!\n")
    
    # 7. Test with modified document
    print("7️⃣ Testing with modified document...")
    test_doc.write_text("MODIFIED CONTENT")
    is_valid_modified = pki.verify_document(
        document_path=test_doc,
        signature=signature,
        certificate=cert_result["certificate"],
        check_certificate_validity=False
    )
    
    if not is_valid_modified:
        print("   ✅ Correctly detected modification!\n")
    else:
        print("   ❌ Failed to detect modification!\n")
    
    # 8. Restore document and test again
    print("8️⃣ Restoring document and verifying again...")
    test_doc.write_text("This is a test document for VCC PKI signing.")
    is_valid_restored = pki.verify_document(
        document_path=test_doc,
        signature=signature,
        certificate=cert_result["certificate"],
        check_certificate_validity=False
    )
    
    if is_valid_restored:
        print("   ✅ Signature valid after restoration!\n")
    else:
        print("   ❌ Signature invalid after restoration!\n")
    
    # 9. Get service info
    print("9️⃣ PKI Service Info:")
    service_info = pki.get_service_info()
    print(f"   Mode: {service_info['mode']}")
    print(f"   Version: {service_info['version']}")
    if 'ca_stats' in service_info:
        stats = service_info['ca_stats']
        print(f"   Total Certificates: {stats['total_certificates_issued']}")
        print(f"   Active Certificates: {stats['active_certificates']}\n")
    
    print("✅ Test complete!\n")

if __name__ == "__main__":
    main()
