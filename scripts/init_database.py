#!/usr/bin/env python3
"""
VCC PKI Server - Database Initialization Script

Initializes the SQLite database with schema and optionally migrates
existing JSON data to the database.

Usage:
    python scripts/init_database.py [--migrate]
    
Options:
    --migrate    Migrate existing JSON data to database
"""

import os
import sys
import sqlite3
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def create_database(db_path: str, schema_path: str):
    """Create database and execute schema"""
    print(f"📁 Creating database: {db_path}")
    
    # Read schema
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
    
    # Create database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Execute schema
        cursor.executescript(schema_sql)
        conn.commit()
        print("✅ Database schema created successfully")
        
        # Verify tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = cursor.fetchall()
        
        print(f"\n📊 Created {len(tables)} tables:")
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
            count = cursor.fetchone()[0]
            print(f"   - {table[0]}: {count} rows")
        
        # Verify views
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")
        views = cursor.fetchall()
        
        print(f"\n👁️  Created {len(views)} views:")
        for view in views:
            print(f"   - {view[0]}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False
        
    finally:
        conn.close()


def migrate_service_registry(db_path: str, json_path: str):
    """Migrate service registry from JSON to database"""
    print(f"\n🔄 Migrating service registry from: {json_path}")
    
    if not os.path.exists(json_path):
        print("⚠️  No service registry JSON file found. Skipping migration.")
        return True
    
    # Read JSON data
    with open(json_path, 'r', encoding='utf-8') as f:
        services = json.load(f)
    
    if not services:
        print("ℹ️  Service registry is empty. Nothing to migrate.")
        return True
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        migrated = 0
        for service_id, service_data in services.items():
            # Insert service
            cursor.execute("""
                INSERT OR REPLACE INTO services (
                    service_id,
                    service_name,
                    endpoints,
                    health_check_url,
                    metadata,
                    status,
                    registered_at,
                    updated_at,
                    last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                service_id,
                service_data.get('service_name', service_id),
                json.dumps(service_data.get('endpoints', [])),
                service_data.get('health_check_url'),
                json.dumps(service_data.get('metadata', {})),
                service_data.get('status', 'active'),
                service_data.get('registered_at'),
                service_data.get('updated_at', service_data.get('registered_at')),
                service_data.get('last_seen')
            ))
            
            migrated += 1
        
        conn.commit()
        print(f"✅ Migrated {migrated} services to database")
        return True
        
    except Exception as e:
        print(f"❌ Error migrating services: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()


def migrate_certificates(db_path: str, cert_registry_path: str):
    """Migrate certificate registry from JSON to database"""
    print(f"\n🔄 Migrating certificates from: {cert_registry_path}")
    
    if not os.path.exists(cert_registry_path):
        print("⚠️  No certificate registry JSON file found. Skipping migration.")
        return True
    
    # Read JSON data
    with open(cert_registry_path, 'r', encoding='utf-8') as f:
        cert_data = json.load(f)
    
    certificates = cert_data.get('certificates', [])
    
    if not certificates:
        print("ℹ️  Certificate registry is empty. Nothing to migrate.")
        return True
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        migrated = 0
        for cert in certificates:
            # Insert certificate
            cursor.execute("""
                INSERT OR REPLACE INTO certificates (
                    certificate_id,
                    service_id,
                    common_name,
                    serial_number,
                    fingerprint,
                    subject_dn,
                    issuer_dn,
                    san_dns,
                    san_ip,
                    not_before,
                    not_after,
                    status,
                    cert_file_path,
                    key_file_path,
                    issued_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cert.get('certificate_id'),
                cert.get('service_id'),
                cert.get('common_name'),
                str(cert.get('serial_number')),
                cert.get('fingerprint'),
                cert.get('subject', ''),
                cert.get('issuer', 'CN=VCC Intermediate CA'),
                json.dumps(cert.get('san_dns', [])),
                json.dumps(cert.get('san_ip', [])),
                cert.get('not_before'),
                cert.get('not_after'),
                cert.get('status', 'active'),
                cert.get('cert_file'),
                cert.get('key_file'),
                cert.get('created_at', cert.get('not_before'))
            ))
            
            migrated += 1
        
        conn.commit()
        print(f"✅ Migrated {migrated} certificates to database")
        return True
        
    except Exception as e:
        print(f"❌ Error migrating certificates: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()


def verify_migration(db_path: str):
    """Verify database after migration"""
    print("\n🔍 Verifying database...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Count services
        cursor.execute("SELECT COUNT(*) FROM services")
        service_count = cursor.fetchone()[0]
        
        # Count certificates
        cursor.execute("SELECT COUNT(*) FROM certificates")
        cert_count = cursor.fetchone()[0]
        
        # Count active certificates
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE status = 'active'")
        active_cert_count = cursor.fetchone()[0]
        
        # Get expiring certificates
        cursor.execute("SELECT COUNT(*) FROM v_expiring_certificates")
        expiring_count = cursor.fetchone()[0]
        
        print(f"\n📊 Database Statistics:")
        print(f"   Services: {service_count}")
        print(f"   Certificates: {cert_count}")
        print(f"   Active Certificates: {active_cert_count}")
        print(f"   Expiring Soon (< 30 days): {expiring_count}")
        
        if cert_count > 0:
            print(f"\n📋 Certificate Summary:")
            cursor.execute("""
                SELECT service_id, common_name, not_after, status
                FROM certificates
                ORDER BY not_after ASC
            """)
            for row in cursor.fetchall():
                service_id, cn, not_after, status = row
                print(f"   - {service_id}: {cn} (expires {not_after}, {status})")
        
        return True
        
    except Exception as e:
        print(f"❌ Error verifying database: {e}")
        return False
        
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='Initialize VCC PKI Server Database')
    parser.add_argument('--migrate', action='store_true', help='Migrate existing JSON data to database')
    parser.add_argument('--force', action='store_true', help='Force recreation (delete existing database)')
    args = parser.parse_args()
    
    # Paths
    base_dir = Path(__file__).parent.parent
    db_path = base_dir / "database" / "pki_server.db"
    schema_path = base_dir / "database" / "schema.sql"
    service_registry_json = base_dir / "database" / "service_registry.json"
    cert_registry_json = base_dir / "service_certificates" / "certificate_registry.json"
    
    print("=" * 70)
    print("VCC PKI Server - Database Initialization")
    print("=" * 70)
    
    # Check if database exists
    if db_path.exists():
        if args.force:
            print(f"⚠️  Deleting existing database: {db_path}")
            os.remove(db_path)
        else:
            print(f"⚠️  Database already exists: {db_path}")
            response = input("Delete and recreate? (y/n): ")
            if response.lower() != 'y':
                print("❌ Aborted")
                return 1
            os.remove(db_path)
    
    # Create database directory
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create database
    if not create_database(str(db_path), str(schema_path)):
        return 1
    
    # Migrate data if requested
    if args.migrate:
        print("\n" + "=" * 70)
        print("Migrating Existing Data")
        print("=" * 70)
        
        # Migrate services
        if not migrate_service_registry(str(db_path), str(service_registry_json)):
            print("⚠️  Service migration failed, but continuing...")
        
        # Migrate certificates
        if not migrate_certificates(str(db_path), str(cert_registry_json)):
            print("⚠️  Certificate migration failed, but continuing...")
    
    # Verify database
    verify_migration(str(db_path))
    
    print("\n" + "=" * 70)
    print("✅ Database initialization complete!")
    print("=" * 70)
    print(f"\nDatabase location: {db_path}")
    print(f"Schema version: 1.0.0")
    print(f"\nTo query the database:")
    print(f"  python -c \"import sqlite3; conn = sqlite3.connect('{db_path}'); print(conn.execute('SELECT * FROM services').fetchall())\"")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
