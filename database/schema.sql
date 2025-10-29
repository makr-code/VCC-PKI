-- VCC PKI Server - Database Schema
-- SQLite Database Schema for PKI Server
-- Version: 1.0.0
-- Date: 2025-10-13

-- ============================================================================
-- Services Table
-- ============================================================================
-- Stores registered microservices in the VCC ecosystem

CREATE TABLE IF NOT EXISTS services (
    service_id TEXT PRIMARY KEY,              -- Unique service identifier (e.g., 'veritas-backend')
    service_name TEXT NOT NULL,               -- Human-readable service name
    description TEXT,                         -- Service description
    endpoints TEXT,                           -- JSON array of service endpoints
    health_check_url TEXT,                    -- Health check endpoint URL
    service_metadata TEXT,                    -- JSON object with service metadata (renamed to avoid conflicts)
    status TEXT DEFAULT 'active',             -- Service status: active, inactive, maintenance
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,                      -- Last health check success timestamp
    
    CHECK (status IN ('active', 'inactive', 'maintenance'))
);

CREATE INDEX IF NOT EXISTS idx_services_status ON services(status);
CREATE INDEX IF NOT EXISTS idx_services_last_seen ON services(last_seen);

-- ============================================================================
-- Certificates Table
-- ============================================================================
-- Tracks all issued certificates

CREATE TABLE IF NOT EXISTS certificates (
    certificate_id TEXT PRIMARY KEY,          -- Unique certificate ID (e.g., 'cert_veritas-backend_20251013_155844')
    service_id TEXT NOT NULL,                 -- Foreign key to services table
    common_name TEXT NOT NULL,                -- Certificate CN (e.g., 'veritas-backend.vcc.local')
    serial_number TEXT UNIQUE NOT NULL,       -- X.509 serial number (bigint as text)
    fingerprint TEXT NOT NULL,                -- SHA-256 fingerprint
    subject_dn TEXT NOT NULL,                 -- Subject Distinguished Name
    issuer_dn TEXT NOT NULL,                  -- Issuer Distinguished Name
    san_dns TEXT,                             -- JSON array of DNS SANs
    san_ip TEXT,                              -- JSON array of IP SANs
    key_size INTEGER DEFAULT 2048,            -- RSA key size
    signature_algorithm TEXT DEFAULT 'SHA256',-- Signature algorithm
    not_before TIMESTAMP NOT NULL,            -- Certificate validity start
    not_after TIMESTAMP NOT NULL,             -- Certificate validity end
    status TEXT DEFAULT 'active',             -- Status: active, revoked, expired
    revoked_at TIMESTAMP,                     -- Revocation timestamp
    revocation_reason TEXT,                   -- Revocation reason (RFC 5280)
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cert_file_path TEXT,                      -- Path to certificate file
    key_file_path TEXT,                       -- Path to private key file
    
    FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CHECK (status IN ('active', 'revoked', 'expired')),
    CHECK (revocation_reason IN (
        'unspecified', 'key_compromise', 'ca_compromise', 
        'affiliation_changed', 'superseded', 'cessation_of_operation',
        'certificate_hold', 'remove_from_crl', 'privilege_withdrawn', 
        'aa_compromise', NULL
    ))
);

CREATE INDEX IF NOT EXISTS idx_certificates_service_id ON certificates(service_id);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number);

-- ============================================================================
-- Certificate Revocation List (CRL)
-- ============================================================================
-- Tracks revoked certificates for CRL generation

CREATE TABLE IF NOT EXISTS crl_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id TEXT NOT NULL,             -- Reference to certificates table
    serial_number TEXT NOT NULL,              -- Certificate serial number
    revoked_at TIMESTAMP NOT NULL,            -- Revocation timestamp
    revocation_reason TEXT NOT NULL,          -- Revocation reason
    invalidity_date TIMESTAMP,                -- Optional: when cert became invalid
    
    FOREIGN KEY (certificate_id) REFERENCES certificates(certificate_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_crl_serial ON crl_entries(serial_number);
CREATE INDEX IF NOT EXISTS idx_crl_revoked_at ON crl_entries(revoked_at);

-- ============================================================================
-- Audit Log
-- ============================================================================
-- Records all PKI operations for security auditing

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,                     -- Action type (e.g., 'CERTIFICATE_ISSUED')
    service_id TEXT,                          -- Service involved in action
    certificate_id TEXT,                      -- Certificate involved in action
    user_id TEXT,                             -- User/service that performed action
    ip_address TEXT,                          -- Client IP address
    details TEXT,                             -- JSON object with action details
    success BOOLEAN DEFAULT 1,                -- Action success/failure
    error_message TEXT,                       -- Error message if failed
    
    CHECK (action IN (
        'CERTIFICATE_ISSUED', 'CERTIFICATE_RENEWED', 'CERTIFICATE_REVOKED',
        'CERTIFICATE_DOWNLOADED', 'SERVICE_REGISTERED', 'SERVICE_UPDATED',
        'SERVICE_DEREGISTERED', 'HEALTH_CHECK_FAILED', 'CA_ACCESS'
    ))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_service_id ON audit_log(service_id);
CREATE INDEX IF NOT EXISTS idx_audit_success ON audit_log(success);

-- ============================================================================
-- Certificate Rotation Schedule
-- ============================================================================
-- Tracks automatic certificate renewal schedules

CREATE TABLE IF NOT EXISTS rotation_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id TEXT NOT NULL,             -- Certificate to rotate
    service_id TEXT NOT NULL,                 -- Service owning the certificate
    scheduled_renewal_date TIMESTAMP NOT NULL,-- When to renew (30 days before expiry)
    status TEXT DEFAULT 'pending',            -- Status: pending, completed, failed
    last_attempt TIMESTAMP,                   -- Last renewal attempt
    attempt_count INTEGER DEFAULT 0,          -- Number of renewal attempts
    error_message TEXT,                       -- Error message if failed
    completed_at TIMESTAMP,                   -- Completion timestamp
    
    FOREIGN KEY (certificate_id) REFERENCES certificates(certificate_id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CHECK (status IN ('pending', 'completed', 'failed', 'skipped'))
);

CREATE INDEX IF NOT EXISTS idx_rotation_scheduled_date ON rotation_schedule(scheduled_renewal_date);
CREATE INDEX IF NOT EXISTS idx_rotation_status ON rotation_schedule(status);
CREATE INDEX IF NOT EXISTS idx_rotation_service_id ON rotation_schedule(service_id);

-- ============================================================================
-- Service Health History
-- ============================================================================
-- Tracks service health check results over time

CREATE TABLE IF NOT EXISTS service_health_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id TEXT NOT NULL,                 -- Service being checked
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL,                     -- Health status: healthy, unhealthy, unknown
    response_time_ms INTEGER,                 -- Health check response time
    http_status_code INTEGER,                 -- HTTP status code from health check
    error_message TEXT,                       -- Error message if unhealthy
    
    FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CHECK (status IN ('healthy', 'unhealthy', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_health_service_id ON service_health_history(service_id);
CREATE INDEX IF NOT EXISTS idx_health_timestamp ON service_health_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_health_status ON service_health_history(status);

-- ============================================================================
-- Views for Common Queries
-- ============================================================================

-- View: Active Certificates with Service Info
CREATE VIEW IF NOT EXISTS v_active_certificates AS
SELECT 
    c.certificate_id,
    c.service_id,
    s.service_name,
    c.common_name,
    c.serial_number,
    c.not_before,
    c.not_after,
    CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) AS days_until_expiry,
    CASE 
        WHEN julianday(c.not_after) - julianday('now') < 30 THEN 1 
        ELSE 0 
    END AS needs_renewal,
    c.status,
    s.status AS service_status
FROM certificates c
JOIN services s ON c.service_id = s.service_id
WHERE c.status = 'active';

-- View: Service Status with Certificate Info
CREATE VIEW IF NOT EXISTS v_service_status AS
SELECT 
    s.service_id,
    s.service_name,
    s.status AS service_status,
    s.last_seen,
    COUNT(c.certificate_id) AS total_certificates,
    SUM(CASE WHEN c.status = 'active' THEN 1 ELSE 0 END) AS active_certificates,
    MIN(c.not_after) AS earliest_expiry,
    s.health_check_url,
    s.endpoints
FROM services s
LEFT JOIN certificates c ON s.service_id = c.service_id
GROUP BY s.service_id;

-- View: Certificates Expiring Soon (within 30 days)
CREATE VIEW IF NOT EXISTS v_expiring_certificates AS
SELECT 
    c.certificate_id,
    c.service_id,
    s.service_name,
    c.common_name,
    c.not_after,
    CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) AS days_until_expiry
FROM certificates c
JOIN services s ON c.service_id = s.service_id
WHERE c.status = 'active'
  AND julianday(c.not_after) - julianday('now') < 30
ORDER BY c.not_after ASC;

-- View: Recent Audit Events
CREATE VIEW IF NOT EXISTS v_recent_audit AS
SELECT 
    a.id,
    a.timestamp,
    a.action,
    a.service_id,
    s.service_name,
    a.certificate_id,
    a.user_id,
    a.success,
    a.error_message
FROM audit_log a
LEFT JOIN services s ON a.service_id = s.service_id
ORDER BY a.timestamp DESC
LIMIT 100;

-- ============================================================================
-- Triggers for Automatic Updates
-- ============================================================================

-- Trigger: Update services.updated_at on modification
CREATE TRIGGER IF NOT EXISTS trg_services_updated_at
AFTER UPDATE ON services
FOR EACH ROW
BEGIN
    UPDATE services SET updated_at = CURRENT_TIMESTAMP WHERE service_id = NEW.service_id;
END;

-- Trigger: Mark certificate as expired when not_after passes
CREATE TRIGGER IF NOT EXISTS trg_certificates_auto_expire
AFTER INSERT ON certificates
FOR EACH ROW
WHEN NEW.not_after < datetime('now')
BEGIN
    UPDATE certificates SET status = 'expired' WHERE certificate_id = NEW.certificate_id;
END;

-- Trigger: Create CRL entry when certificate is revoked
CREATE TRIGGER IF NOT EXISTS trg_certificates_revoke_crl
AFTER UPDATE OF status ON certificates
FOR EACH ROW
WHEN NEW.status = 'revoked' AND OLD.status != 'revoked'
BEGIN
    INSERT INTO crl_entries (certificate_id, serial_number, revoked_at, revocation_reason)
    VALUES (NEW.certificate_id, NEW.serial_number, CURRENT_TIMESTAMP, NEW.revocation_reason);
END;

-- Trigger: Schedule certificate rotation on issuance
CREATE TRIGGER IF NOT EXISTS trg_certificates_schedule_rotation
AFTER INSERT ON certificates
FOR EACH ROW
WHEN NEW.status = 'active'
BEGIN
    INSERT INTO rotation_schedule (certificate_id, service_id, scheduled_renewal_date)
    VALUES (
        NEW.certificate_id, 
        NEW.service_id, 
        datetime(NEW.not_after, '-30 days')  -- Schedule renewal 30 days before expiry
    );
END;

-- ============================================================================
-- Initial Data (Optional)
-- ============================================================================

-- Insert PKI Server itself as a service
INSERT OR IGNORE INTO services (
    service_id, 
    service_name, 
    description,
    endpoints,
    health_check_url,
    service_metadata,
    status
) VALUES (
    'pki-server',
    'VCC PKI Server',
    'Global PKI Certificate Management Server',
    '["https://127.0.0.1:8443/api/v1"]',
    'https://127.0.0.1:8443/health',
    '{"version": "1.0.0", "team": "VCC Core", "type": "infrastructure"}',
    'active'
);

-- ============================================================================
-- Database Statistics and Maintenance
-- ============================================================================

-- Create table for database metadata
CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO db_metadata (key, value) VALUES ('schema_version', '1.0.0');
INSERT OR IGNORE INTO db_metadata (key, value) VALUES ('created_at', datetime('now'));
INSERT OR IGNORE INTO db_metadata (key, value) VALUES ('description', 'VCC PKI Server Database');

-- ============================================================================
-- Indexes for Performance
-- ============================================================================

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_cert_service_status ON certificates(service_id, status);
CREATE INDEX IF NOT EXISTS idx_cert_expiry_status ON certificates(not_after, status);
CREATE INDEX IF NOT EXISTS idx_rotation_service_status ON rotation_schedule(service_id, status);

-- ============================================================================
-- Comments (for documentation)
-- ============================================================================

-- This schema supports:
-- 1. Service registration and discovery
-- 2. Certificate lifecycle management (issue, renew, revoke)
-- 3. Certificate Revocation Lists (CRL)
-- 4. Audit logging for security compliance
-- 5. Automatic certificate rotation scheduling
-- 6. Service health monitoring
-- 7. Views for common queries and reporting
-- 8. Triggers for automatic updates

-- Tables: 6 core tables + 1 metadata
-- Views: 4 convenience views
-- Triggers: 4 automation triggers
-- Indexes: 20+ for performance

-- Total Lines: 300+

-- Usage:
-- sqlite3 database/pki_server.db < database/schema.sql
