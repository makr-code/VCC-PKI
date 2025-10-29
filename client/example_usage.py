"""
VCC PKI Client - Example Usage
===============================

This example demonstrates how to use the VCC PKI Client library
to integrate a service with the VCC PKI Server.

Usage:
    python example_usage.py
"""

import logging
import time
from vcc_pki_client import PKIClient, CertificateNotFoundError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Example: Complete PKI client workflow"""
    
    # 1. Initialize PKI Client
    logger.info("=" * 60)
    logger.info("VCC PKI Client - Example Usage")
    logger.info("=" * 60)
    
    pki = PKIClient(
        pki_server_url="https://localhost:8443",
        service_id="example-service",
        ca_password="vcc_intermediate_pw_2025",  # Use env var VCC_CA_PASSWORD in production
        verify_ssl=False  # Set to True in production with valid CA
    )
    
    logger.info(f"PKI Client initialized for service: example-service")
    logger.info(f"Storage path: {pki.storage_path}")
    logger.info(f"CA bundle: {pki.ca_bundle}")
    
    # 2. Check if certificate exists
    logger.info("\n" + "=" * 60)
    logger.info("Step 1: Check Certificate Status")
    logger.info("=" * 60)
    
    try:
        cert_info = pki.get_certificate_info()
        logger.info(f"Certificate found:")
        logger.info(f"  - Certificate ID: {cert_info['certificate_id']}")
        logger.info(f"  - Common Name: {cert_info['common_name']}")
        logger.info(f"  - Status: {cert_info['status']}")
        logger.info(f"  - Expires: {cert_info['not_after']}")
        logger.info(f"  - Days until expiry: {cert_info['days_until_expiry']}")
        logger.info(f"  - Needs renewal: {cert_info['days_until_expiry'] < 30}")
        
    except CertificateNotFoundError:
        logger.info("No certificate found - will request new one")
        
        # 3. Request new certificate
        logger.info("\n" + "=" * 60)
        logger.info("Step 2: Request New Certificate")
        logger.info("=" * 60)
        
        result = pki.request_certificate(
            common_name="example-service.vcc.local",
            san_dns=["example-service", "localhost", "example.local"],
            san_ip=["127.0.0.1", "::1"],
            validity_days=365
        )
        
        logger.info(f"Certificate requested successfully:")
        logger.info(f"  - Certificate ID: {result['certificate_id']}")
        logger.info(f"  - Expires at: {result['expires_at']}")
        logger.info(f"  - Certificate file: {pki.cert_file}")
        logger.info(f"  - Key file: {pki.key_file}")
    
    # 4. Register service
    logger.info("\n" + "=" * 60)
    logger.info("Step 3: Register Service")
    logger.info("=" * 60)
    
    try:
        service_result = pki.register_service(
            service_name="Example Service",
            endpoints=[
                "https://example-service.vcc.local:8000",
                "https://localhost:8000"
            ],
            health_check_url="https://example-service.vcc.local:8000/health",
            metadata={
                "version": "1.0.0",
                "environment": "development",
                "team": "platform"
            }
        )
        logger.info(f"Service registered successfully:")
        logger.info(f"  - Service ID: {service_result['service_id']}")
        logger.info(f"  - Registered at: {service_result['registered_at']}")
    except Exception as e:
        logger.warning(f"Service registration failed (may already exist): {e}")
    
    # 5. Enable auto-renewal
    logger.info("\n" + "=" * 60)
    logger.info("Step 4: Enable Auto-Renewal")
    logger.info("=" * 60)
    
    pki.enable_auto_renewal(
        check_interval_hours=6,
        renew_before_days=30
    )
    logger.info("Auto-renewal enabled:")
    logger.info("  - Check interval: 6 hours")
    logger.info("  - Renew threshold: 30 days")
    logger.info("  - Background thread: running")
    
    # 6. Demonstrate SSL contexts
    logger.info("\n" + "=" * 60)
    logger.info("Step 5: SSL Context Examples")
    logger.info("=" * 60)
    
    # Server SSL context (for FastAPI/uvicorn)
    ssl_context_server = pki.get_ssl_context(client_auth=False)
    logger.info(f"Server SSL context created:")
    logger.info(f"  - Protocol: {ssl_context_server.protocol}")
    logger.info(f"  - Verify mode: {ssl_context_server.verify_mode}")
    logger.info(f"  - Usage: uvicorn.run(app, ssl_context=ssl_context)")
    
    # Client SSL context
    ssl_context_client = pki.get_client_ssl_context()
    logger.info(f"Client SSL context created:")
    logger.info(f"  - Protocol: {ssl_context_client.protocol}")
    logger.info(f"  - Verify mode: {ssl_context_client.verify_mode}")
    logger.info(f"  - Usage: urllib.request.urlopen(url, context=ssl_context)")
    
    # httpx configuration
    verify, cert = pki.get_httpx_config()
    logger.info(f"httpx configuration:")
    logger.info(f"  - verify: {verify}")
    logger.info(f"  - cert: {cert}")
    logger.info(f"  - Usage: httpx.Client(verify=verify, cert=cert)")
    
    # requests configuration
    verify, cert = pki.get_requests_config()
    logger.info(f"requests configuration:")
    logger.info(f"  - verify: {verify}")
    logger.info(f"  - cert: {cert}")
    logger.info(f"  - Usage: session.verify=verify, session.cert=cert")
    
    # 7. Wait a bit, then cleanup
    logger.info("\n" + "=" * 60)
    logger.info("Step 6: Auto-Renewal Active")
    logger.info("=" * 60)
    logger.info("Auto-renewal is now running in background...")
    logger.info("Press Ctrl+C to stop")
    
    try:
        # In real application, this is where your service runs
        while True:
            time.sleep(10)
            
            # Periodically check certificate status
            cert_info = pki.get_certificate_info()
            logger.info(f"Certificate status: expires in {cert_info['days_until_expiry']} days")
            
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
    
    # 8. Cleanup
    pki.disable_auto_renewal()
    logger.info("Auto-renewal stopped")
    
    logger.info("\n" + "=" * 60)
    logger.info("Example Complete!")
    logger.info("=" * 60)
    logger.info(f"Certificate files stored in: {pki.storage_path}")
    logger.info("You can now use these certificates for mTLS communication")


if __name__ == "__main__":
    main()
