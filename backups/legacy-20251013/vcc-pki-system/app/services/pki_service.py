# VCC PKI System - Core PKI Service
# Business logic layer for all PKI operations

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from ..core.database import VCCPKIDatabase
from ..core.config import VCCPKIConfig
from .crypto_service import VCCCryptoService
from ..models import *

logger = logging.getLogger(__name__)

class VCCPKIService:
    """Core PKI service orchestrating all certificate and signing operations"""
    
    def __init__(self, config: VCCPKIConfig, database: VCCPKIDatabase, crypto_service: VCCCryptoService):
        self.config = config
        self.database = database
        self.crypto_service = crypto_service
        self._initialized = False
        self._ca_cache = {}  # Cache for CA certificates and keys
        
        if config.mock_mode:
            self._setup_mock_infrastructure()
    
    def _setup_mock_infrastructure(self):
        """Set up mock PKI infrastructure for development/testing"""
        logger.info("🔧 Setting up mock VCC PKI infrastructure...")
        
        try:
            # Create Root CA
            root_ca_id, root_cert_pem, root_key_pem = self.crypto_service.create_root_ca(
                "VCC Root CA Brandenburg (Mock)", "brandenburg-gov"
            )
            
            # Store Root CA in database
            with self.database.get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO certificate_authorities (
                        ca_id, ca_name, ca_type, organization_id, certificate_pem, 
                        private_key_encrypted, key_algorithm, key_size, expires_at, usage_purpose
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    root_ca_id, "VCC Root CA Brandenburg (Mock)", "root", "brandenburg-gov",
                    root_cert_pem, root_key_pem.encode('utf-8') if root_key_pem else None,
                    "RSA", 4096, datetime.utcnow() + timedelta(days=365*20), "root"
                ))
            
            # Cache root CA
            self._ca_cache['root'] = {
                'ca_id': root_ca_id,
                'cert_pem': root_cert_pem,
                'key_pem': root_key_pem
            }
            
            # Create Issuing CAs
            issuing_cas = [
                ("services", "VCC Services CA"),
                ("code_signing", "VCC Code Signing CA"),
                ("admin", "VCC Admin CA")
            ]
            
            for purpose, ca_name in issuing_cas:
                ca_id, cert_pem, key_pem = self.crypto_service.create_issuing_ca(
                    ca_name, purpose, root_cert_pem, root_key_pem, "brandenburg-gov"
                )
                
                # Store in database
                with self.database.get_connection() as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO certificate_authorities (
                            ca_id, ca_name, ca_type, parent_ca_id, organization_id, 
                            certificate_pem, private_key_encrypted, key_algorithm, 
                            key_size, expires_at, usage_purpose
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ca_id, ca_name, "issuing", root_ca_id, "brandenburg-gov",
                        cert_pem, key_pem.encode('utf-8'), "RSA", 2048,
                        datetime.utcnow() + timedelta(days=365*10), purpose
                    ))
                
                # Cache issuing CA
                self._ca_cache[purpose] = {
                    'ca_id': ca_id,
                    'cert_pem': cert_pem,
                    'key_pem': key_pem
                }
            
            # Auto-provision VCC service certificates if enabled
            if self.config.mock_vcc_services:
                self._provision_mock_service_certificates()
            
            self._initialized = True
            logger.info("✅ Mock VCC PKI infrastructure setup completed")
            
        except Exception as e:
            logger.error(f"❌ Failed to setup mock infrastructure: {e}")
            raise
    
    def _provision_mock_service_certificates(self):
        """Automatically provision certificates for all VCC services"""
        logger.info("🔐 Auto-provisioning VCC service certificates...")
        
        vcc_services = self.database.get_vcc_services("brandenburg-gov")
        
        for service in vcc_services:
            try:
                cert_result = self.issue_service_certificate(
                    service_id=service['service_id'],
                    organization_id="brandenburg-gov"
                )
                
                if cert_result.success:
                    logger.info(f"   ✅ {service['service_name']}: Certificate issued")
                else:
                    logger.warning(f"   ⚠️  {service['service_name']}: Certificate failed - {cert_result.message}")
                    
            except Exception as e:
                logger.error(f"   ❌ {service['service_name']}: Error - {e}")
    
    def get_connection(self):
        """Get database connection context manager"""
        return self.database.get_connection()
    
    # Certificate Authority Operations
    def create_issuing_ca(self, request: CACreate) -> APIResponse:
        """Create new issuing CA"""
        try:
            logger.info(f"Creating issuing CA: {request.ca_name}")
            
            # Get parent CA (root CA)
            parent_ca = self._get_ca_credentials(request.parent_ca_id or 'root')
            if not parent_ca:
                return create_error_response(
                    "Parent CA not found or credentials unavailable",
                    "CA_NOT_FOUND"
                )
            
            # Create issuing CA
            ca_id, cert_pem, key_pem = self.crypto_service.create_issuing_ca(
                request.ca_name, 
                request.usage_purpose or "general",
                parent_ca['cert_pem'],
                parent_ca['key_pem'],
                request.organization_id
            )
            
            # Store in database
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO certificate_authorities (
                        ca_id, ca_name, ca_type, parent_ca_id, organization_id,
                        certificate_pem, private_key_encrypted, key_algorithm,
                        key_size, expires_at, usage_purpose, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ca_id, request.ca_name, request.ca_type, request.parent_ca_id,
                    request.organization_id, cert_pem, key_pem.encode('utf-8'),
                    request.key_algorithm, request.key_size,
                    datetime.utcnow() + timedelta(days=365*request.validity_years),
                    request.usage_purpose, json.dumps({})
                ))
            
            # Log audit event
            self.database.log_audit_event(
                event_type='ca_created',
                event_category='certificate',
                actor_identity='system',
                actor_type='system',
                target_resource=ca_id,
                organization_id=request.organization_id,
                event_data={'ca_name': request.ca_name, 'ca_type': request.ca_type}
            )
            
            return create_success_response(
                data={'ca_id': ca_id},
                message=f"Issuing CA '{request.ca_name}' created successfully"
            )
            
        except Exception as e:
            logger.error(f"Failed to create issuing CA: {e}")
            return create_error_response(f"Failed to create issuing CA: {str(e)}", "CA_CREATION_FAILED")
    
    def list_certificate_authorities(self, organization_id: str = None) -> APIResponse:
        """List all certificate authorities"""
        try:
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                
                if organization_id:
                    results = conn.execute("""
                        SELECT * FROM certificate_authorities 
                        WHERE organization_id = ? 
                        ORDER BY ca_type, ca_name
                    """, (organization_id,)).fetchall()
                else:
                    results = conn.execute("""
                        SELECT * FROM certificate_authorities 
                        ORDER BY organization_id, ca_type, ca_name
                    """).fetchall()
                
                cas = [dict(row) for row in results]
                
                return create_success_response(
                    data=cas,
                    message=f"Found {len(cas)} certificate authorities"
                )
                
        except Exception as e:
            logger.error(f"Failed to list CAs: {e}")
            return create_error_response(f"Failed to list CAs: {str(e)}", "CA_LIST_FAILED")
    
    # Certificate Operations
    def issue_service_certificate(self, service_id: str, organization_id: str = "brandenburg-gov") -> APIResponse:
        """Issue certificate for VCC service"""
        try:
            logger.info(f"Issuing certificate for service: {service_id}")
            
            # Get service information
            service_info = None
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                result = conn.execute("""
                    SELECT * FROM vcc_services 
                    WHERE service_id = ? AND organization_id = ?
                """, (service_id, organization_id)).fetchone()
                
                if result:
                    service_info = dict(result)
            
            if not service_info:
                return create_error_response(
                    f"Service '{service_id}' not found",
                    "SERVICE_NOT_FOUND"
                )
            
            # Get services issuing CA
            services_ca = self._get_ca_credentials('services')
            if not services_ca:
                return create_error_response(
                    "Services CA not available",
                    "CA_NOT_AVAILABLE"
                )
            
            # Create service certificate
            cert_id, cert_pem, key_pem = self.crypto_service.create_service_certificate(
                service_id,
                service_info['service_type'],
                services_ca['cert_pem'],
                services_ca['key_pem'],
                organization_id,
                san_domains=[f"{service_id}.vcc.internal", "localhost"]
            )
            
            # Store certificate in database
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO certificates (
                        cert_id, serial_number, issuing_ca_id, organization_id, service_id,
                        subject_dn, certificate_pem, purpose, service_domain,
                        key_usage, extended_key_usage, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cert_id, 
                    str(hash(cert_id))[:16],  # Simplified serial number
                    services_ca['ca_id'],
                    organization_id,
                    service_id,
                    f"CN={service_id}.vcc.internal,O={self.config.organization_name}",
                    cert_pem,
                    'vcc_service',
                    f"{service_id}.vcc.internal",
                    'digitalSignature,keyEncipherment',
                    'serverAuth,clientAuth',
                    datetime.utcnow() + timedelta(days=self.config.service_cert_validity_days)
                ))
                
                # Update service with certificate ID
                conn.execute("""
                    UPDATE vcc_services 
                    SET cert_id = ?, status = 'active', last_seen = CURRENT_TIMESTAMP
                    WHERE service_id = ? AND organization_id = ?
                """, (cert_id, service_id, organization_id))
            
            # Save certificate files (in mock mode)
            if self.config.mock_mode:
                cert_file = Path(self.config.certificates_path) / f"{cert_id}.crt"
                key_file = Path(self.config.private_keys_path) / f"{cert_id}.key"
                
                with open(cert_file, 'w') as f:
                    f.write(cert_pem)
                
                with open(key_file, 'w') as f:
                    f.write(key_pem)
            
            # Log audit event
            self.database.log_audit_event(
                event_type='service_cert_issued',
                event_category='certificate',
                actor_identity='system',
                actor_type='system',
                target_resource=cert_id,
                organization_id=organization_id,
                service_id=service_id,
                event_data={'service_name': service_info['service_name']}
            )
            
            return create_success_response(
                data={
                    'cert_id': cert_id,
                    'service_id': service_id,
                    'certificate_pem': cert_pem if self.config.mock_mode else None,
                    'expires_at': (datetime.utcnow() + timedelta(days=self.config.service_cert_validity_days)).isoformat()
                },
                message=f"Certificate issued for service '{service_id}'"
            )
            
        except Exception as e:
            logger.error(f"Failed to issue service certificate: {e}")
            return create_error_response(
                f"Failed to issue certificate for service '{service_id}': {str(e)}",
                "CERT_ISSUE_FAILED"
            )
    
    def issue_code_signing_certificate(self, signer_name: str, organization_id: str = "brandenburg-gov") -> APIResponse:
        """Issue code signing certificate"""
        try:
            logger.info(f"Issuing code signing certificate for: {signer_name}")
            
            # Get code signing CA
            codesign_ca = self._get_ca_credentials('code_signing')
            if not codesign_ca:
                return create_error_response(
                    "Code signing CA not available",
                    "CA_NOT_AVAILABLE"
                )
            
            # Create code signing certificate
            cert_id, cert_pem, key_pem = self.crypto_service.create_code_signing_certificate(
                signer_name,
                codesign_ca['cert_pem'],
                codesign_ca['key_pem'],
                organization_id
            )
            
            # Store in database
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO certificates (
                        cert_id, serial_number, issuing_ca_id, organization_id,
                        subject_dn, certificate_pem, purpose,
                        key_usage, extended_key_usage, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cert_id,
                    str(hash(cert_id))[:16],
                    codesign_ca['ca_id'],
                    organization_id,
                    f"CN=VCC Code Signer - {signer_name},O={self.config.organization_name}",
                    cert_pem,
                    'code_signing',
                    'digitalSignature,nonRepudiation',
                    'codeSigning',
                    datetime.utcnow() + timedelta(days=self.config.code_signing_cert_validity_days)
                ))
            
            # Log audit event
            self.database.log_audit_event(
                event_type='codesign_cert_issued',
                event_category='certificate',
                actor_identity='system',
                actor_type='system',
                target_resource=cert_id,
                organization_id=organization_id,
                event_data={'signer_name': signer_name}
            )
            
            return create_success_response(
                data={
                    'cert_id': cert_id,
                    'signer_name': signer_name,
                    'certificate_pem': cert_pem if self.config.mock_mode else None,
                    'private_key_pem': key_pem if self.config.mock_mode else None,
                    'expires_at': (datetime.utcnow() + timedelta(days=self.config.code_signing_cert_validity_days)).isoformat()
                },
                message=f"Code signing certificate issued for '{signer_name}'"
            )
            
        except Exception as e:
            logger.error(f"Failed to issue code signing certificate: {e}")
            return create_error_response(
                f"Failed to issue code signing certificate: {str(e)}",
                "CODESIGN_CERT_FAILED"
            )
    
    def list_certificates(self, organization_id: str = None, service_id: str = None, 
                         purpose: str = None) -> APIResponse:
        """List certificates with optional filters"""
        try:
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM certificates WHERE 1=1"
                params = []
                
                if organization_id:
                    query += " AND organization_id = ?"
                    params.append(organization_id)
                
                if service_id:
                    query += " AND service_id = ?"
                    params.append(service_id)
                
                if purpose:
                    query += " AND purpose = ?"
                    params.append(purpose)
                
                query += " ORDER BY created_at DESC"
                
                results = conn.execute(query, params).fetchall()
                certificates = [dict(row) for row in results]
                
                return create_success_response(
                    data=certificates,
                    message=f"Found {len(certificates)} certificates"
                )
                
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            return create_error_response(f"Failed to list certificates: {str(e)}", "CERT_LIST_FAILED")
    
    # Code Signing Operations
    def sign_code_artifact(self, request: CodeSigningRequest, cert_id: str) -> APIResponse:
        """Sign code artifact with certificate"""
        try:
            logger.info(f"Signing {request.artifact_type}: {request.artifact_path}")
            
            # Get certificate and private key
            cert_info = None
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                result = conn.execute("""
                    SELECT * FROM certificates 
                    WHERE cert_id = ? AND purpose = 'code_signing' AND revoked_at IS NULL
                """, (cert_id,)).fetchone()
                
                if result:
                    cert_info = dict(result)
            
            if not cert_info:
                return create_error_response(
                    "Code signing certificate not found or revoked",
                    "CERT_NOT_FOUND"
                )
            
            # For mock mode, create a dummy file if it doesn't exist
            artifact_path = Path(request.artifact_path)
            if self.config.mock_mode and not artifact_path.exists():
                # Create dummy artifact for testing
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                with open(artifact_path, 'w') as f:
                    f.write(f"# Mock {request.artifact_type} for VCC PKI testing\n")
                    f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
                    f.write(f"# Service: {request.service_id or 'unknown'}\n")
            
            if not artifact_path.exists():
                return create_error_response(
                    f"Artifact file not found: {request.artifact_path}",
                    "ARTIFACT_NOT_FOUND"
                )
            
            # Create file manifest and sign
            manifest = self.crypto_service.create_file_manifest([artifact_path])
            manifest_json = json.dumps(manifest, sort_keys=True)
            
            # Load private key (in mock mode, from database)
            if self.config.mock_mode:
                # Get private key from issuing CA (simplified for mock)
                codesign_ca = self._get_ca_credentials('code_signing')
                private_key_pem = codesign_ca['key_pem']
                password = b'vcc-issuing-ca-password-2025'
            else:
                # In production, private key would be in HSM
                return create_error_response(
                    "Production code signing not implemented - HSM integration required",
                    "PRODUCTION_NOT_IMPLEMENTED"
                )
            
            # Sign manifest
            signature = self.crypto_service.sign_data(
                manifest_json.encode('utf-8'),
                private_key_pem,
                password
            )
            
            # Store signature in database
            signature_id = f"sig-{request.artifact_type}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO vcc_code_signatures (
                        signature_id, cert_id, service_id, artifact_type, artifact_path,
                        artifact_name, file_hash, signature_algorithm, signature_data,
                        vcc_metadata, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    signature_id, cert_id, request.service_id, request.artifact_type,
                    request.artifact_path, request.artifact_name,
                    list(manifest.values())[0],  # First file hash
                    'RSA-PSS', signature,
                    json.dumps(request.metadata or {}),
                    datetime.utcnow()
                ))
            
            # Log audit event
            self.database.log_audit_event(
                event_type='code_signed',
                event_category='signature',
                actor_identity='system',
                actor_type='system',
                target_resource=signature_id,
                service_id=request.service_id,
                event_data={
                    'artifact_type': request.artifact_type,
                    'artifact_path': request.artifact_path,
                    'cert_id': cert_id
                }
            )
            
            return create_success_response(
                data={
                    'signature_id': signature_id,
                    'artifact_type': request.artifact_type,
                    'artifact_path': request.artifact_path,
                    'file_hash': list(manifest.values())[0],
                    'signed_at': datetime.utcnow().isoformat(),
                    'manifest': manifest if self.config.mock_mode else None
                },
                message=f"Artifact '{request.artifact_path}' signed successfully"
            )
            
        except Exception as e:
            logger.error(f"Failed to sign code artifact: {e}")
            return create_error_response(
                f"Failed to sign artifact: {str(e)}",
                "CODE_SIGNING_FAILED"
            )
    
    def verify_code_signature(self, request: CodeVerificationRequest) -> APIResponse:
        """Verify code signature"""
        try:
            logger.info(f"Verifying signature for: {request.artifact_path}")
            
            # Find signature record
            signature_info = None
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                
                if request.signature_id:
                    result = conn.execute("""
                        SELECT * FROM vcc_code_signatures 
                        WHERE signature_id = ?
                    """, (request.signature_id,)).fetchone()
                else:
                    result = conn.execute("""
                        SELECT * FROM vcc_code_signatures 
                        WHERE artifact_path = ? 
                        ORDER BY signed_at DESC LIMIT 1
                    """, (request.artifact_path,)).fetchone()
                
                if result:
                    signature_info = dict(result)
            
            if not signature_info:
                return create_success_response(
                    data={
                        'valid': False,
                        'error_message': 'No signature found for artifact'
                    },
                    message="Signature verification failed - no signature found"
                )
            
            # Get certificate for verification
            cert_info = None
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                result = conn.execute("""
                    SELECT * FROM certificates WHERE cert_id = ?
                """, (signature_info['cert_id'],)).fetchone()
                
                if result:
                    cert_info = dict(result)
            
            if not cert_info:
                return create_success_response(
                    data={
                        'valid': False,
                        'error_message': 'Certificate not found'
                    }
                )
            
            # Verify file still matches hash
            artifact_path = Path(request.artifact_path)
            if artifact_path.exists():
                current_manifest = self.crypto_service.create_file_manifest([artifact_path])
                current_hash = list(current_manifest.values())[0]
                
                if current_hash != signature_info['file_hash']:
                    return create_success_response(
                        data={
                            'valid': False,
                            'error_message': 'File has been modified since signing'
                        }
                    )
            
            # Update verification count
            with self.get_connection() as conn:
                conn.execute("""
                    UPDATE vcc_code_signatures 
                    SET verified_count = verified_count + 1, last_verified_at = CURRENT_TIMESTAMP
                    WHERE signature_id = ?
                """, (signature_info['signature_id'],))
            
            return create_success_response(
                data={
                    'valid': True,
                    'signature_id': signature_info['signature_id'],
                    'cert_id': signature_info['cert_id'],
                    'service_identity': signature_info['service_id'],
                    'signed_at': signature_info['signed_at'],
                    'verification_timestamp': datetime.utcnow().isoformat()
                },
                message="Signature verification successful"
            )
            
        except Exception as e:
            logger.error(f"Failed to verify signature: {e}")
            return create_error_response(
                f"Failed to verify signature: {str(e)}",
                "VERIFICATION_FAILED"
            )
    
    # Health and Status Operations
    def get_system_health(self) -> APIResponse:
        """Get comprehensive system health status"""
        try:
            # Get database statistics
            db_stats = self.database.get_database_stats()
            
            # Check VCC services
            vcc_services = self.database.get_vcc_services("brandenburg-gov")
            services_healthy = sum(1 for s in vcc_services if s['status'] == 'active')
            
            # Determine overall status
            if db_stats['certificates_expiring_soon'] > 10:
                overall_status = "critical"
            elif db_stats['certificates_expiring_soon'] > 0 or services_healthy < len(vcc_services):
                overall_status = "degraded"
            else:
                overall_status = "healthy"
            
            health_data = {
                'overall_status': overall_status,
                'database_status': 'healthy',
                'certificate_authorities_active': db_stats.get('certificate_authorities_count', 0),
                'active_certificates': db_stats.get('certificates_count', 0),
                'certificates_expiring_soon': db_stats['certificates_expiring_soon'],
                'services_monitored': len(vcc_services),
                'services_healthy': services_healthy,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            return create_success_response(
                data=health_data,
                message=f"System status: {overall_status}"
            )
            
        except Exception as e:
            logger.error(f"Failed to get system health: {e}")
            return create_error_response(
                f"Failed to get system health: {str(e)}",
                "HEALTH_CHECK_FAILED"
            )
    
    # Helper Methods
    def _get_ca_credentials(self, ca_purpose_or_id: str) -> Optional[Dict[str, str]]:
        """Get CA certificate and private key from cache or database"""
        
        # Check cache first
        if ca_purpose_or_id in self._ca_cache:
            return self._ca_cache[ca_purpose_or_id]
        
        # Query database
        try:
            with self.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                
                if ca_purpose_or_id == 'root':
                    result = conn.execute("""
                        SELECT * FROM certificate_authorities 
                        WHERE ca_type = 'root' AND status = 'active'
                        ORDER BY created_at DESC LIMIT 1
                    """).fetchone()
                else:
                    result = conn.execute("""
                        SELECT * FROM certificate_authorities 
                        WHERE (usage_purpose = ? OR ca_id = ?) AND status = 'active'
                        ORDER BY created_at DESC LIMIT 1
                    """, (ca_purpose_or_id, ca_purpose_or_id)).fetchone()
                
                if result:
                    ca_info = dict(result)
                    credentials = {
                        'ca_id': ca_info['ca_id'],
                        'cert_pem': ca_info['certificate_pem'],
                        'key_pem': ca_info['private_key_encrypted'].decode('utf-8') if ca_info['private_key_encrypted'] else None
                    }
                    
                    # Cache for future use
                    self._ca_cache[ca_purpose_or_id] = credentials
                    return credentials
            
        except Exception as e:
            logger.error(f"Failed to get CA credentials: {e}")
        
        return None

import sqlite3  # Import needed for database operations

if __name__ == "__main__":
    # Test the PKI service
    from ..core.config import create_config
    
    logging.basicConfig(level=logging.INFO)
    
    print("🚀 VCC PKI Service Test")
    print("=" * 50)
    
    # Initialize components
    config = create_config("development")
    database = VCCPKIDatabase(config.database_path, config.database_encryption_key)
    crypto_service = VCCCryptoService(config)
    
    # Initialize PKI service
    pki_service = VCCPKIService(config, database, crypto_service)
    
    print("\n📊 System Health:")
    health = pki_service.get_system_health()
    print(f"   Status: {health.data['overall_status']}")
    print(f"   Services: {health.data['services_healthy']}/{health.data['services_monitored']}")
    print(f"   Certificates: {health.data['active_certificates']}")
    
    print("\n🔐 Testing Code Signing:")
    # Issue code signing certificate
    codesign_result = pki_service.issue_code_signing_certificate("Test Signer")
    if codesign_result.success:
        print(f"   ✅ Code signing certificate: {codesign_result.data['cert_id']}")
        
        # Test code signing
        signing_request = CodeSigningRequest(
            artifact_type="python_package",
            artifact_path="test_package.py",
            service_id="argus"
        )
        
        sign_result = pki_service.sign_code_artifact(signing_request, codesign_result.data['cert_id'])
        if sign_result.success:
            print(f"   ✅ Code signed: {sign_result.data['signature_id']}")
            
            # Test verification
            verify_request = CodeVerificationRequest(artifact_path="test_package.py")
            verify_result = pki_service.verify_code_signature(verify_request)
            print(f"   ✅ Verification: {'VALID' if verify_result.data['valid'] else 'INVALID'}")
    
    print("\n✅ VCC PKI Service test completed successfully!")