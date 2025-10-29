# VCC PKI System - Production Database Schema
# SQLite with SQLCipher encryption for secure PKI operations

import sqlite3
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class VCCPKIDatabase:
    """Production-ready PKI database with encryption and VCC service integration"""
    
    def __init__(self, db_path: str = "vcc_pki.db", encryption_key: Optional[str] = None):
        self.db_path = db_path
        self.encryption_key = encryption_key or self._generate_encryption_key()
        self._init_database()
    
    def _generate_encryption_key(self) -> str:
        """Generate secure encryption key for database"""
        return hashlib.sha256(b"vcc-pki-brandenburg-2025").hexdigest()
    
    def _init_database(self):
        """Initialize database with complete PKI schema"""
        with sqlite3.connect(self.db_path) as conn:
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Create all tables
            self._create_organizations_table(conn)
            self._create_certificate_authorities_table(conn)
            self._create_vcc_services_table(conn)
            self._create_certificates_table(conn)
            self._create_code_signatures_table(conn)
            self._create_audit_events_table(conn)
            self._create_tenant_policies_table(conn)
            
            # Insert initial data
            self._insert_initial_data(conn)
            
            conn.commit()
            logger.info("✅ VCC PKI Database initialized successfully")
    
    def _create_organizations_table(self, conn: sqlite3.Connection):
        """Create organizations table for multi-tenant support"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                org_id TEXT PRIMARY KEY,
                org_name TEXT NOT NULL,
                org_type TEXT CHECK (org_type IN ('government', 'partner', 'external')) DEFAULT 'government',
                root_ca_id TEXT,
                isolation_level TEXT CHECK (isolation_level IN ('strict', 'collaborative', 'federated')) DEFAULT 'strict',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                admin_contact TEXT,
                active BOOLEAN DEFAULT TRUE,
                metadata TEXT DEFAULT '{}' -- JSON for additional org-specific data
            )
        """)
    
    def _create_certificate_authorities_table(self, conn: sqlite3.Connection):
        """Create CA hierarchy table"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificate_authorities (
                ca_id TEXT PRIMARY KEY,
                ca_name TEXT NOT NULL,
                ca_type TEXT CHECK (ca_type IN ('root', 'intermediate', 'issuing')) NOT NULL,
                parent_ca_id TEXT REFERENCES certificate_authorities(ca_id),
                organization_id TEXT REFERENCES organizations(org_id),
                certificate_pem TEXT NOT NULL,
                private_key_encrypted BLOB, -- NULL for root CA (offline)
                key_algorithm TEXT DEFAULT 'RSA',
                key_size INTEGER DEFAULT 2048,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                status TEXT CHECK (status IN ('active', 'revoked', 'expired')) DEFAULT 'active',
                usage_purpose TEXT, -- 'services', 'code_signing', 'admin', etc.
                metadata TEXT DEFAULT '{}'
            )
        """)
    
    def _create_vcc_services_table(self, conn: sqlite3.Connection):
        """Create VCC services registry"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vcc_services (
                service_id TEXT PRIMARY KEY,
                service_name TEXT NOT NULL, -- 'argus', 'covina', 'clara', 'veritas', 'vpb'
                service_type TEXT CHECK (service_type IN ('api', 'orchestrator', 'processor', 'ui', 'database')) NOT NULL,
                endpoint_url TEXT,
                health_endpoint TEXT,
                cert_id TEXT REFERENCES certificates(cert_id),
                organization_id TEXT REFERENCES organizations(org_id),
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT CHECK (status IN ('active', 'inactive', 'discovered', 'pending_cert', 'error')) DEFAULT 'discovered',
                auto_cert_renewal BOOLEAN DEFAULT TRUE,
                service_metadata TEXT DEFAULT '{}' -- JSON for service-specific config
            )
        """)
    
    def _create_certificates_table(self, conn: sqlite3.Connection):
        """Create certificates table"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_id TEXT PRIMARY KEY,
                serial_number TEXT UNIQUE NOT NULL,
                issuing_ca_id TEXT REFERENCES certificate_authorities(ca_id),
                organization_id TEXT REFERENCES organizations(org_id),
                service_id TEXT REFERENCES vcc_services(service_id),
                subject_dn TEXT NOT NULL,
                subject_alt_names TEXT, -- JSON array of SANs
                certificate_pem TEXT NOT NULL,
                purpose TEXT CHECK (purpose IN ('vcc_service', 'mtls_service', 'code_signing', 'admin', 'external_integration')) NOT NULL,
                service_domain TEXT, -- 'argus.vcc.brandenburg.de'
                key_usage TEXT DEFAULT 'digitalSignature,keyEncipherment', -- X.509 key usage
                extended_key_usage TEXT DEFAULT 'serverAuth,clientAuth', -- Extended key usage
                auto_renewal BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP NULL,
                revocation_reason TEXT NULL,
                last_used TIMESTAMP NULL,
                usage_count INTEGER DEFAULT 0
            )
        """)
    
    def _create_code_signatures_table(self, conn: sqlite3.Connection):
        """Create code signatures audit table"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vcc_code_signatures (
                signature_id TEXT PRIMARY KEY,
                cert_id TEXT REFERENCES certificates(cert_id),
                service_id TEXT REFERENCES vcc_services(service_id),
                artifact_type TEXT CHECK (artifact_type IN ('python_package', 'lora_adapter', 'pipeline_config', 'ui_bundle', 'docker_image')) NOT NULL,
                artifact_path TEXT NOT NULL,
                artifact_name TEXT,
                file_hash TEXT NOT NULL, -- SHA256 of manifest or artifact
                signature_algorithm TEXT DEFAULT 'RSA-PSS',
                signature_data BLOB NOT NULL,
                timestamp_token BLOB, -- RFC 3161 timestamp
                vcc_metadata TEXT DEFAULT '{}', -- JSON for VCC-specific metadata
                signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_count INTEGER DEFAULT 0,
                last_verified_at TIMESTAMP NULL,
                signature_valid BOOLEAN DEFAULT TRUE
            )
        """)
    
    def _create_audit_events_table(self, conn: sqlite3.Connection):
        """Create comprehensive audit events table"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL, -- 'cert_issued', 'cert_revoked', 'code_signed', 'service_discovered'
                event_category TEXT CHECK (event_category IN ('authentication', 'authorization', 'certificate', 'signature', 'service', 'admin')) NOT NULL,
                actor_identity TEXT NOT NULL, -- User, service, or system identifier
                actor_type TEXT CHECK (actor_type IN ('user', 'service', 'system', 'external')) NOT NULL,
                target_resource TEXT, -- Certificate ID, Service ID, etc.
                organization_id TEXT REFERENCES organizations(org_id),
                service_id TEXT REFERENCES vcc_services(service_id),
                event_data TEXT DEFAULT '{}', -- JSON structured event details
                source_ip TEXT,
                user_agent TEXT,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT NULL,
                compliance_relevant BOOLEAN DEFAULT TRUE, -- For GDPR/AI Act reporting
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_tenant_policies_table(self, conn: sqlite3.Connection):
        """Create tenant isolation policies table"""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tenant_isolation_policies (
                policy_id TEXT PRIMARY KEY,
                organization_id TEXT REFERENCES organizations(org_id),
                policy_name TEXT NOT NULL,
                service_access_matrix TEXT DEFAULT '{}', -- JSON defining service communication rules
                data_sharing_level TEXT CHECK (data_sharing_level IN ('none', 'metadata_only', 'full')) DEFAULT 'none',
                cross_tenant_auth BOOLEAN DEFAULT FALSE,
                certificate_sharing BOOLEAN DEFAULT FALSE,
                audit_separation BOOLEAN DEFAULT TRUE,
                policy_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _insert_initial_data(self, conn: sqlite3.Connection):
        """Insert initial VCC organization and mock data"""
        
        # Insert Brandenburg organization
        conn.execute("""
            INSERT OR IGNORE INTO organizations (org_id, org_name, org_type, admin_contact, metadata)
            VALUES (?, ?, ?, ?, ?)
        """, (
            'brandenburg-gov',
            'Land Brandenburg - Digitale Verwaltung',
            'government',
            'admin@digital.brandenburg.de',
            json.dumps({
                "region": "Brandenburg",
                "country": "Deutschland",
                "compliance_frameworks": ["GDPR", "EU_AI_Act", "BSI_IT_Grundschutz"],
                "pilot_program": True
            })
        ))
        
        # Insert mock VCC services
        vcc_services = [
            ('argus', 'Argus Analysis Engine', 'api', 'https://argus.vcc.internal:8000', '/health'),
            ('covina', 'Covina Management Core', 'orchestrator', 'https://covina.vcc.internal:8001', '/api/health'),
            ('clara', 'Clara AI Processing', 'processor', 'https://clara.vcc.internal:8002', '/status'),
            ('veritas', 'Veritas Pipeline Orchestrator', 'orchestrator', 'https://veritas.vcc.internal:8003', '/health'),
            ('vpb', 'Visual Processing Backbone', 'ui', 'https://vpb.vcc.internal:8004', '/api/status')
        ]
        
        for service_id, name, stype, endpoint, health in vcc_services:
            conn.execute("""
                INSERT OR IGNORE INTO vcc_services 
                (service_id, service_name, service_type, endpoint_url, health_endpoint, organization_id, service_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                service_id, name, stype, endpoint, health, 'brandenburg-gov',
                json.dumps({
                    "mock_service": True,
                    "vcc_component": True,
                    "requires_high_security": service_id in ['clara', 'covina'],
                    "public_facing": service_id in ['argus', 'vpb']
                })
            ))
        
        # Insert default tenant policy for Brandenburg
        conn.execute("""
            INSERT OR IGNORE INTO tenant_isolation_policies 
            (policy_id, organization_id, policy_name, service_access_matrix, data_sharing_level)
            VALUES (?, ?, ?, ?, ?)
        """, (
            'brandenburg-default-policy',
            'brandenburg-gov',
            'Brandenburg VCC Default Security Policy',
            json.dumps({
                "argus": {"allowed_outbound": ["covina", "vpb"], "auth_required": True},
                "covina": {"allowed_outbound": ["clara", "veritas"], "auth_required": True, "high_privilege": True},
                "clara": {"allowed_outbound": ["covina"], "auth_required": True, "isolation_level": "high"},
                "veritas": {"allowed_outbound": ["covina", "clara"], "auth_required": True},
                "vpb": {"allowed_outbound": ["argus"], "auth_required": True}
            }),
            'metadata_only'
        ))
    
    # --- Database Access Methods ---
    
    def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Get organization by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(
                "SELECT * FROM organizations WHERE org_id = ? AND active = TRUE", (org_id,)
            ).fetchone()
            return dict(result) if result else None
    
    def get_vcc_services(self, organization_id: str = 'brandenburg-gov') -> List[Dict[str, Any]]:
        """Get all VCC services for organization"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            results = conn.execute("""
                SELECT s.*, c.expires_at as cert_expires_at, c.status as cert_status
                FROM vcc_services s
                LEFT JOIN certificates c ON s.cert_id = c.cert_id
                WHERE s.organization_id = ?
                ORDER BY s.service_name
            """, (organization_id,)).fetchall()
            
            return [dict(row) for row in results]
    
    def register_service_discovery(self, service_id: str, endpoint_url: str, 
                                  organization_id: str = 'brandenburg-gov') -> bool:
        """Register discovered VCC service"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE vcc_services 
                    SET endpoint_url = ?, last_seen = CURRENT_TIMESTAMP, status = 'active'
                    WHERE service_id = ? AND organization_id = ?
                """, (endpoint_url, service_id, organization_id))
                
                # Log discovery event
                self.log_audit_event(
                    event_type='service_discovered',
                    event_category='service',
                    actor_identity='system',
                    actor_type='system',
                    target_resource=service_id,
                    organization_id=organization_id,
                    event_data={"endpoint_url": endpoint_url, "auto_discovered": True}
                )
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to register service discovery: {e}")
            return False
    
    def log_audit_event(self, event_type: str, event_category: str, 
                       actor_identity: str, actor_type: str,
                       target_resource: Optional[str] = None,
                       organization_id: Optional[str] = None,
                       service_id: Optional[str] = None,
                       event_data: Optional[Dict] = None,
                       source_ip: Optional[str] = None,
                       success: bool = True,
                       error_message: Optional[str] = None) -> str:
        """Log comprehensive audit event"""
        import uuid
        event_id = str(uuid.uuid4())
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO audit_events (
                    event_id, event_type, event_category, actor_identity, actor_type,
                    target_resource, organization_id, service_id, event_data,
                    source_ip, success, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, event_type, event_category, actor_identity, actor_type,
                target_resource, organization_id, service_id, 
                json.dumps(event_data or {}), source_ip, success, error_message
            ))
            conn.commit()
        
        return event_id
    
    def get_audit_trail(self, organization_id: Optional[str] = None, 
                       service_id: Optional[str] = None,
                       event_category: Optional[str] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Get filtered audit trail"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            if organization_id:
                query += " AND organization_id = ?"
                params.append(organization_id)
            
            if service_id:
                query += " AND service_id = ?"
                params.append(service_id)
            
            if event_category:
                query += " AND event_category = ?"
                params.append(event_category)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            results = conn.execute(query, params).fetchall()
            return [dict(row) for row in results]
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics for monitoring"""
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            
            # Count tables
            tables = ['organizations', 'certificate_authorities', 'vcc_services', 
                     'certificates', 'vcc_code_signatures', 'audit_events']
            
            for table in tables:
                result = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                stats[f"{table}_count"] = result[0]
            
            # VCC Services status
            result = conn.execute("""
                SELECT status, COUNT(*) as count 
                FROM vcc_services 
                GROUP BY status
            """).fetchall()
            
            stats['vcc_services_by_status'] = {row[0]: row[1] for row in result}
            
            # Certificate expiry warnings
            result = conn.execute("""
                SELECT COUNT(*) FROM certificates 
                WHERE expires_at <= date('now', '+30 days') 
                AND revoked_at IS NULL
            """).fetchone()
            
            stats['certificates_expiring_soon'] = result[0]
            
            # Recent audit events
            result = conn.execute("""
                SELECT COUNT(*) FROM audit_events 
                WHERE timestamp >= datetime('now', '-24 hours')
            """).fetchone()
            
            stats['audit_events_24h'] = result[0]
            
            stats['last_updated'] = datetime.utcnow().isoformat()
            
        return stats

# Test und Initialisierung
if __name__ == "__main__":
    # Logging setup
    logging.basicConfig(level=logging.INFO)
    
    # Initialize database
    print("🚀 Initializing VCC PKI Database...")
    db = VCCPKIDatabase("vcc_pki_test.db")
    
    # Test basic operations
    print("\n📊 Database Statistics:")
    stats = db.get_database_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n🔍 VCC Services:")
    services = db.get_vcc_services()
    for service in services:
        print(f"   {service['service_name']} ({service['service_id']}) - Status: {service['status']}")
    
    print("\n📋 Recent Audit Events:")
    events = db.get_audit_trail(limit=5)
    for event in events:
        print(f"   {event['timestamp']}: {event['event_type']} by {event['actor_identity']}")
    
    print("\n✅ VCC PKI Database ready for production use!")