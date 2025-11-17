# VCC PKI Server - Database Schema

**Database:** SQLite  
**ORM:** SQLAlchemy  
**Location:** `database/pki_server.db`  
**Last Updated:** 17.11.2025

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Entity Relationship Diagram](#entity-relationship-diagram)
3. [Tables](#tables)
   - [services](#services)
   - [certificates](#certificates)
   - [crl_entries](#crl_entries)
   - [audit_log](#audit_log)
   - [rotation_schedule](#rotation_schedule)
   - [service_health_history](#service_health_history)
   - [db_metadata](#db_metadata)
4. [Relationships](#relationships)
5. [Indexes & Constraints](#indexes--constraints)
6. [Data Types & Validation](#data-types--validation)
7. [Usage Examples](#usage-examples)
8. [Migrations](#migrations)

---

## Overview

The VCC PKI Server uses a SQLite database with SQLAlchemy ORM for managing:
- Service registrations
- Certificate lifecycle (issue, renew, revoke)
- Certificate Revocation Lists (CRL)
- Audit logging
- Automated certificate rotation
- Service health monitoring

**Key Features:**
- Referential integrity with foreign keys
- Cascade deletions for data consistency
- Check constraints for data validation
- Audit trail for all operations
- Automated timestamp tracking

---

## Entity Relationship Diagram

```
┌─────────────────┐
│    services     │
└────────┬────────┘
         │
         │ 1:N
         ├─────────────────────────────────┐
         │                                 │
         │                                 │
         ▼                                 ▼
┌─────────────────┐              ┌──────────────────────┐
│  certificates   │              │ rotation_schedule    │
└────────┬────────┘              └──────────────────────┘
         │
         │ 1:1                   ┌──────────────────────┐
         ├───────────────────────│ service_health_hist  │
         │                       └──────────────────────┘
         │ 1:1
         ▼
┌─────────────────┐
│   crl_entries   │
└─────────────────┘

┌─────────────────┐
│   audit_log     │  (standalone)
└─────────────────┘

┌─────────────────┐
│   db_metadata   │  (standalone)
└─────────────────┘
```

---

## Tables

### services

Stores registered microservices that use the PKI infrastructure.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `service_id` | String | NO | - | **Primary Key**. Service identifier (e.g., "covina-backend") |
| `service_name` | String | NO | - | Human-readable service name |
| `description` | Text | YES | NULL | Service description |
| `endpoints` | Text | YES | NULL | JSON array of service endpoints |
| `health_check_url` | String | YES | NULL | Health check endpoint URL |
| `service_metadata` | Text | YES | NULL | JSON object with custom metadata |
| `status` | String | YES | 'active' | Service status: 'active', 'inactive', 'maintenance' |
| `registered_at` | DateTime | YES | UTC now | Service registration timestamp |
| `updated_at` | DateTime | YES | UTC now | Last update timestamp (auto-updated) |
| `last_seen` | DateTime | YES | NULL | Last health check timestamp |

**Constraints:**
- Primary Key: `service_id`
- Check: `status IN ('active', 'inactive', 'maintenance')`

**Relationships:**
- 1:N → `certificates`
- 1:N → `rotation_schedule`
- 1:N → `service_health_history`

---

### certificates

Stores X.509 certificates issued by the PKI system.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `certificate_id` | String | NO | - | **Primary Key**. Unique certificate identifier |
| `service_id` | String | NO | - | **Foreign Key** → services.service_id |
| `common_name` | String | NO | - | Certificate Common Name (CN) |
| `serial_number` | String | NO | - | X.509 serial number (unique) |
| `fingerprint` | String | NO | - | SHA-256 fingerprint |
| `subject_dn` | String | NO | - | Subject Distinguished Name |
| `issuer_dn` | String | NO | - | Issuer Distinguished Name |
| `san_dns` | Text | YES | NULL | JSON array of DNS Subject Alternative Names |
| `san_ip` | Text | YES | NULL | JSON array of IP Subject Alternative Names |
| `key_size` | Integer | YES | 2048 | RSA key size in bits |
| `signature_algorithm` | String | YES | 'SHA256' | Signature algorithm |
| `not_before` | DateTime | NO | - | Certificate validity start date |
| `not_after` | DateTime | NO | - | Certificate expiry date |
| `status` | String | YES | 'active' | Certificate status: 'active', 'revoked', 'expired' |
| `revoked_at` | DateTime | YES | NULL | Revocation timestamp |
| `revocation_reason` | String | YES | NULL | RFC 5280 revocation reason |
| `issued_at` | DateTime | YES | UTC now | Certificate issuance timestamp |
| `cert_file_path` | String | YES | NULL | Path to certificate PEM file |
| `key_file_path` | String | YES | NULL | Path to private key PEM file |

**Constraints:**
- Primary Key: `certificate_id`
- Foreign Key: `service_id` → `services.service_id` (CASCADE DELETE)
- Unique: `serial_number`
- Check: `status IN ('active', 'revoked', 'expired')`
- Check: `revocation_reason IN (...RFC 5280 reasons...) OR NULL`

**Computed Properties:**
- `days_until_expiry`: Days until certificate expires (calculated)
- `needs_renewal`: True if < 30 days until expiry (calculated)

**Relationships:**
- N:1 → `services`
- 1:1 → `crl_entries`
- 1:1 → `rotation_schedule`

---

### crl_entries

Certificate Revocation List entries for revoked certificates.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | Integer | NO | Auto | **Primary Key** (auto-increment) |
| `certificate_id` | String | NO | - | **Foreign Key** → certificates.certificate_id |
| `serial_number` | String | NO | - | Certificate serial number |
| `revoked_at` | DateTime | NO | - | Revocation timestamp |
| `revocation_reason` | String | NO | - | RFC 5280 revocation reason |
| `invalidity_date` | DateTime | YES | NULL | Date when certificate became invalid |

**Constraints:**
- Primary Key: `id`
- Foreign Key: `certificate_id` → `certificates.certificate_id` (CASCADE DELETE)

**Relationships:**
- N:1 → `certificates`

---

### audit_log

Comprehensive audit trail for all PKI operations.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | Integer | NO | Auto | **Primary Key** (auto-increment) |
| `timestamp` | DateTime | YES | UTC now | Event timestamp |
| `action` | String | NO | - | Action performed (see allowed actions below) |
| `service_id` | String | YES | NULL | Service involved in action |
| `certificate_id` | String | YES | NULL | Certificate involved in action |
| `user_id` | String | YES | NULL | User who performed action |
| `ip_address` | String | YES | NULL | Client IP address |
| `details` | Text | YES | NULL | JSON object with additional details |
| `success` | Boolean | YES | TRUE | Whether action succeeded |
| `error_message` | Text | YES | NULL | Error message if action failed |

**Allowed Actions:**
- `CERTIFICATE_ISSUED`
- `CERTIFICATE_RENEWED`
- `CERTIFICATE_REVOKED`
- `CERTIFICATE_DOWNLOADED`
- `SERVICE_REGISTERED`
- `SERVICE_UPDATED`
- `SERVICE_DEREGISTERED`
- `HEALTH_CHECK_FAILED`
- `CA_ACCESS`

**Constraints:**
- Primary Key: `id`
- Check: `action IN (...allowed actions...)`

**Relationships:**
- None (standalone table)

---

### rotation_schedule

Automated certificate renewal scheduling.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | Integer | NO | Auto | **Primary Key** (auto-increment) |
| `certificate_id` | String | NO | - | **Foreign Key** → certificates.certificate_id |
| `service_id` | String | NO | - | **Foreign Key** → services.service_id |
| `scheduled_renewal_date` | DateTime | NO | - | When renewal should occur |
| `status` | String | YES | 'pending' | Renewal status: 'pending', 'completed', 'failed', 'skipped' |
| `last_attempt` | DateTime | YES | NULL | Last renewal attempt timestamp |
| `attempt_count` | Integer | YES | 0 | Number of renewal attempts |
| `error_message` | Text | YES | NULL | Error message if renewal failed |
| `completed_at` | DateTime | YES | NULL | Completion timestamp |

**Constraints:**
- Primary Key: `id`
- Foreign Key: `certificate_id` → `certificates.certificate_id` (CASCADE DELETE)
- Foreign Key: `service_id` → `services.service_id` (CASCADE DELETE)
- Check: `status IN ('pending', 'completed', 'failed', 'skipped')`

**Relationships:**
- N:1 → `certificates`
- N:1 → `services`

---

### service_health_history

Historical health check results for services.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | Integer | NO | Auto | **Primary Key** (auto-increment) |
| `service_id` | String | NO | - | **Foreign Key** → services.service_id |
| `timestamp` | DateTime | YES | UTC now | Health check timestamp |
| `status` | String | NO | - | Health status: 'healthy', 'unhealthy', 'unknown' |
| `response_time_ms` | Integer | YES | NULL | Response time in milliseconds |
| `http_status_code` | Integer | YES | NULL | HTTP status code |
| `error_message` | Text | YES | NULL | Error message if unhealthy |

**Constraints:**
- Primary Key: `id`
- Foreign Key: `service_id` → `services.service_id` (CASCADE DELETE)
- Check: `status IN ('healthy', 'unhealthy', 'unknown')`

**Relationships:**
- N:1 → `services`

---

### db_metadata

Database metadata and configuration.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `key` | String | NO | - | **Primary Key**. Metadata key |
| `value` | Text | YES | NULL | Metadata value (can be JSON) |
| `updated_at` | DateTime | YES | UTC now | Last update timestamp (auto-updated) |

**Constraints:**
- Primary Key: `key`

**Relationships:**
- None (standalone table)

**Example Keys:**
- `schema_version`: Database schema version
- `last_crl_generation`: Last CRL generation timestamp
- `ca_initialized`: Whether CA has been initialized

---

## Relationships

### services → certificates (1:N)

- One service can have multiple certificates (current + historical)
- Deleting a service cascades to all its certificates
- Access via: `service.certificates` or `certificate.service`

### services → rotation_schedule (1:N)

- One service can have multiple scheduled renewals
- Deleting a service cascades to all its rotation schedules
- Access via: `service.rotation_schedules`

### services → service_health_history (1:N)

- One service has multiple health check records
- Deleting a service cascades to all its health history
- Access via: `service.health_history`

### certificates → crl_entries (1:1)

- One certificate can have one CRL entry (if revoked)
- Deleting a certificate cascades to its CRL entry
- Access via: `certificate.crl_entry`

### certificates → rotation_schedule (1:1)

- One certificate has one active rotation schedule
- Deleting a certificate cascades to its rotation schedule
- Access via: `certificate.rotation_schedule`

---

## Indexes & Constraints

### Primary Keys

- All tables have a primary key (either `id` auto-increment or custom string)

### Foreign Keys

All foreign keys use `CASCADE DELETE` to maintain data integrity:

```sql
-- certificates
service_id → services.service_id (ON DELETE CASCADE)

-- crl_entries
certificate_id → certificates.certificate_id (ON DELETE CASCADE)

-- rotation_schedule
certificate_id → certificates.certificate_id (ON DELETE CASCADE)
service_id → services.service_id (ON DELETE CASCADE)

-- service_health_history
service_id → services.service_id (ON DELETE CASCADE)
```

### Unique Constraints

- `certificates.serial_number`: Each X.509 serial number is unique

### Check Constraints

Status field validation using CHECK constraints:

```sql
-- services
CHECK (status IN ('active', 'inactive', 'maintenance'))

-- certificates
CHECK (status IN ('active', 'revoked', 'expired'))
CHECK (revocation_reason IN (...RFC 5280 reasons...) OR NULL)

-- audit_log
CHECK (action IN (...allowed actions...))

-- rotation_schedule
CHECK (status IN ('pending', 'completed', 'failed', 'skipped'))

-- service_health_history
CHECK (status IN ('healthy', 'unhealthy', 'unknown'))
```

### Recommended Indexes (Future Optimization)

For production deployments, consider adding:

```sql
CREATE INDEX idx_certificates_service_id ON certificates(service_id);
CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_expiry ON certificates(not_after);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_service_id ON audit_log(service_id);
CREATE INDEX idx_rotation_schedule_date ON rotation_schedule(scheduled_renewal_date);
```

---

## Data Types & Validation

### String Fields

- `service_id`: 3-64 chars, lowercase alphanumeric + hyphens
- `common_name`: 3-64 chars
- `serial_number`: Hexadecimal string
- `fingerprint`: SHA-256 hex string (64 chars)

### DateTime Fields

- All stored in UTC timezone
- SQLAlchemy automatically handles timezone conversion
- Format: ISO 8601 (e.g., "2025-11-17T10:30:00+00:00")

### JSON Fields (stored as Text)

Fields that store JSON:
- `services.endpoints`: `["https://service.vcc.local:8080"]`
- `services.service_metadata`: `{"owner": "team@vcc.local", ...}`
- `certificates.san_dns`: `["service.vcc.local", "localhost"]`
- `certificates.san_ip`: `["127.0.0.1", "::1"]`
- `audit_log.details`: `{"action": "...", "details": {...}}`

**Note:** JSON validation and serialization handled in application code.

### Enums

Implemented as CHECK constraints:

**Service Status:**
- `active`: Service is running
- `inactive`: Service is stopped
- `maintenance`: Service is under maintenance

**Certificate Status:**
- `active`: Certificate is valid and in use
- `revoked`: Certificate has been revoked
- `expired`: Certificate has expired

**Rotation Status:**
- `pending`: Renewal scheduled, not yet attempted
- `completed`: Renewal completed successfully
- `failed`: Renewal attempted but failed
- `skipped`: Renewal skipped (e.g., certificate already renewed)

**Health Status:**
- `healthy`: Health check passed
- `unhealthy`: Health check failed
- `unknown`: Health check could not be performed

---

## Usage Examples

### Query Service with Certificates

```python
from database import get_db, Service, Certificate

db = next(get_db())

# Get service with all certificates
service = db.query(Service).filter(Service.service_id == "covina-backend").first()
print(f"Service: {service.service_name}")
print(f"Certificates: {len(service.certificates)}")

for cert in service.certificates:
    print(f"  - {cert.common_name} (expires in {cert.days_until_expiry} days)")
```

### Find Certificates Needing Renewal

```python
from datetime import datetime, timedelta
from database import get_db, Certificate

db = next(get_db())

# Find certificates expiring in next 30 days
threshold = datetime.utcnow() + timedelta(days=30)
expiring_certs = db.query(Certificate).filter(
    Certificate.status == "active",
    Certificate.not_after <= threshold
).all()

for cert in expiring_certs:
    print(f"⚠️ {cert.service_id}: expires in {cert.days_until_expiry} days")
```

### Add Audit Log Entry

```python
from database import get_db, AuditLog

db = next(get_db())

audit_entry = AuditLog(
    action="CERTIFICATE_ISSUED",
    service_id="my-service",
    certificate_id="cert_abc123",
    user_id="admin",
    ip_address="192.168.1.100",
    details='{"common_name": "my-service.vcc.local"}',
    success=True
)

db.add(audit_entry)
db.commit()
```

### Schedule Certificate Renewal

```python
from datetime import datetime, timedelta
from database import get_db, RotationSchedule

db = next(get_db())

# Schedule renewal 30 days before expiry
renewal_date = certificate.not_after - timedelta(days=30)

schedule = RotationSchedule(
    certificate_id=certificate.certificate_id,
    service_id=certificate.service_id,
    scheduled_renewal_date=renewal_date,
    status="pending"
)

db.add(schedule)
db.commit()
```

### Query Audit Logs

```python
from database import get_db, AuditLog
from datetime import datetime, timedelta

db = next(get_db())

# Get audit logs from last 24 hours
since = datetime.utcnow() - timedelta(days=1)
recent_logs = db.query(AuditLog).filter(
    AuditLog.timestamp >= since
).order_by(AuditLog.timestamp.desc()).all()

for log in recent_logs:
    status = "✅" if log.success else "❌"
    print(f"{status} {log.action} - {log.service_id} at {log.timestamp}")
```

---

## Migrations

### Initial Setup

```bash
# Initialize database (creates all tables)
python scripts/init_database.py
```

### Schema Evolution

Currently, the system does not use a formal migration framework (e.g., Alembic). For schema changes:

1. **Development:** Drop and recreate database
   ```python
   from database import drop_all_tables, create_all_tables
   drop_all_tables()  # WARNING: Deletes all data!
   create_all_tables()
   ```

2. **Production:** Manual migration scripts
   - Create backup before migration
   - Write SQL ALTER TABLE statements
   - Test on staging environment first
   - Apply to production with downtime window

### Recommended: Add Alembic (Future)

For production deployments, consider adding Alembic for database migrations:

```bash
pip install alembic
alembic init alembic
# Configure alembic.ini and env.py
alembic revision --autogenerate -m "Initial schema"
alembic upgrade head
```

---

## Database File Management

### Location

- **Development:** `database/pki_server.db`
- **Production:** Configure via environment variable

### Backup

```bash
# Simple file copy (SQLite)
cp database/pki_server.db database/backups/pki_server_$(date +%Y%m%d).db

# Using SQLite command
sqlite3 database/pki_server.db ".backup 'database/backups/backup.db'"
```

### Restore

```bash
# Stop PKI server first
cp database/backups/pki_server_20251117.db database/pki_server.db
# Restart PKI server
```

### Database Size Monitoring

```bash
# Check database size
ls -lh database/pki_server.db

# Check table sizes (in SQLite shell)
sqlite3 database/pki_server.db
> .tables
> SELECT name, COUNT(*) FROM sqlite_master GROUP BY name;
```

---

## Security Considerations

### Sensitive Data

The following fields contain sensitive information:

- `certificates.key_file_path`: Path to private keys
- `rotation_schedule.error_message`: May contain passwords in errors
- `audit_log.details`: May contain sensitive operation details

**Recommendations:**
- Encrypt database file at rest (SQLCipher)
- Restrict file system permissions (chmod 600)
- Use environment-specific encryption keys
- Audit log access and modifications

### Private Key Storage

Private keys are stored separately in file system:
- Not stored in database (only file paths)
- Encrypted with CA password
- Restricted file permissions

### Audit Trail

All security-relevant operations are logged in `audit_log`:
- Certificate issuance/renewal/revocation
- Service registration/deregistration
- CA access
- Failed operations

---

## Troubleshooting

### Common Issues

**Database locked:**
```
SQLite error: database is locked
```
- Cause: Another process has write lock
- Solution: Ensure only one PKI server instance running

**Foreign key constraint failed:**
```
FOREIGN KEY constraint failed
```
- Cause: Trying to insert certificate without service
- Solution: Register service first

**Unique constraint failed:**
```
UNIQUE constraint failed: certificates.serial_number
```
- Cause: Duplicate certificate serial number
- Solution: This should never happen; indicates CA issue

### Debugging Queries

```python
# Enable SQLAlchemy query logging
import logging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Queries will now be printed to console
```

---

## Future Enhancements

### Planned Improvements

1. **Database Encryption:** Implement SQLCipher for at-rest encryption
2. **Multi-Tenant Support:** Add organization/tenant tables
3. **Code Signing Tables:** Tables for code signature verification
4. **HSM Integration:** Track HSM key references
5. **Certificate Templates:** Reusable certificate configuration templates
6. **OCSP Responses:** Cache OCSP responses
7. **Metrics Tables:** Performance and usage metrics

### Schema Version Tracking

Future versions will include:

```sql
-- Example future table
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME NOT NULL,
    description TEXT
);
```

---

## References

- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [RFC 5280 - X.509 Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [Database Models Source](../src/database.py)

---

*Last Updated: 17.11.2025*
