#!/usr/bin/env python3
"""
VCC PKI System - Advanced Administration CLI
Enhanced command-line tool for system administration, maintenance, and monitoring
"""

import argparse
import asyncio
import json
import sqlite3
import os
import sys
import logging
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vcc-pki-admin.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VCCPKIAdmin:
    """Advanced VCC PKI Administration Tool"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.db_path = "data/vcc_pki.db"
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)
        
        # Ensure data directory exists
        Path("data").mkdir(exist_ok=True)
        
        # Initialize database if not exists
        self.init_database()
    
    def init_database(self):
        """Initialize database with basic schema if not exists"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if tables exist
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='certificates'
                """)
                
                if not cursor.fetchone():
                    # Create basic schema for admin operations
                    cursor.executescript("""
                        CREATE TABLE certificates (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            subject TEXT NOT NULL,
                            serial_number TEXT UNIQUE NOT NULL,
                            status TEXT DEFAULT 'valid',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            expires_at TIMESTAMP NOT NULL,
                            certificate_pem TEXT,
                            metadata TEXT
                        );
                        
                        CREATE TABLE audit_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            action TEXT NOT NULL,
                            user_id TEXT,
                            resource_type TEXT,
                            resource_id TEXT,
                            details TEXT,
                            ip_address TEXT
                        );
                        
                        CREATE TABLE vcc_services (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT UNIQUE NOT NULL,
                            url TEXT NOT NULL,
                            status TEXT DEFAULT 'unknown',
                            last_check TIMESTAMP,
                            metadata TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        
                        CREATE TABLE system_config (
                            key TEXT PRIMARY KEY,
                            value TEXT,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    
                    # Insert sample data
                    sample_data = [
                        ("CN=web-portal.brandenburg.de", "1001", "valid", 
                         datetime.now() + timedelta(days=365)),
                        ("CN=service-auth.vcc.local", "1002", "valid", 
                         datetime.now() + timedelta(days=180)),
                        ("CN=payment-gateway.vcc.local", "1003", "expiring", 
                         datetime.now() + timedelta(days=30)),
                        ("CN=old-service.vcc.local", "1004", "revoked", 
                         datetime.now() + timedelta(days=90))
                    ]
                    
                    for subject, serial, status, expires in sample_data:
                        cursor.execute("""
                            INSERT INTO certificates (subject, serial_number, status, expires_at)
                            VALUES (?, ?, ?, ?)
                        """, (subject, serial, status, expires))
                    
                    # Sample VCC services
                    vcc_services = [
                        ("Authentication Service", "https://auth.vcc.local", "online"),
                        ("Payment Gateway", "https://pay.vcc.local", "online"),
                        ("Document Service", "https://docs.vcc.local", "offline"),
                        ("Notification Hub", "https://notify.vcc.local", "online"),
                        ("Argus Monitoring", "https://argus.vcc.local", "online"),
                        ("Covina Analytics", "https://covina.vcc.local", "maintenance"),
                        ("Clara Compliance", "https://clara.vcc.local", "online"),
                        ("Veritas Verification", "https://veritas.vcc.local", "online")
                    ]
                    
                    for name, url, status in vcc_services:
                        cursor.execute("""
                            INSERT INTO vcc_services (name, url, status, last_check)
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        """, (name, url, status))
                    
                    conn.commit()
                    logger.info("Database initialized with sample data")
                
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

    # =================== BACKUP & RECOVERY ===================
    
    async def create_backup(self, backup_name: Optional[str] = None) -> str:
        """Create complete system backup"""
        try:
            if not backup_name:
                backup_name = f"vcc-pki-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            
            backup_path = self.backup_dir / f"{backup_name}.zip"
            
            logger.info(f"Creating backup: {backup_path}")
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as backup_zip:
                # Backup database
                if Path(self.db_path).exists():
                    backup_zip.write(self.db_path, "database/vcc_pki.db")
                
                # Backup configuration
                config_files = [
                    "config/config.yaml",
                    "config/ca.yaml", 
                    "config/security.yaml"
                ]
                
                for config_file in config_files:
                    if Path(config_file).exists():
                        backup_zip.write(config_file, f"config/{Path(config_file).name}")
                
                # Backup certificates directory
                cert_dir = Path("certificates")
                if cert_dir.exists():
                    for cert_file in cert_dir.rglob("*"):
                        if cert_file.is_file():
                            rel_path = cert_file.relative_to(cert_dir)
                            backup_zip.write(cert_file, f"certificates/{rel_path}")
                
                # Backup private keys (if accessible)
                keys_dir = Path("private")
                if keys_dir.exists():
                    for key_file in keys_dir.rglob("*"):
                        if key_file.is_file():
                            rel_path = key_file.relative_to(keys_dir)
                            backup_zip.write(key_file, f"private/{rel_path}")
                
                # Create backup manifest
                manifest = {
                    "backup_name": backup_name,
                    "created_at": datetime.now().isoformat(),
                    "version": "1.0",
                    "components": ["database", "config", "certificates", "private_keys"],
                    "checksum": self.calculate_backup_checksum(backup_path)
                }
                
                backup_zip.writestr("manifest.json", json.dumps(manifest, indent=2))
            
            # Verify backup integrity
            if self.verify_backup(backup_path):
                logger.info(f"✅ Backup created successfully: {backup_path}")
                
                # Log backup event
                await self.log_audit_event("backup_created", details={
                    "backup_name": backup_name,
                    "backup_path": str(backup_path),
                    "size_bytes": backup_path.stat().st_size
                })
                
                return str(backup_path)
            else:
                logger.error("❌ Backup verification failed")
                return None
                
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            raise
    
    def calculate_backup_checksum(self, backup_path: Path) -> str:
        """Calculate SHA-256 checksum of backup file"""
        sha256_hash = hashlib.sha256()
        
        with open(backup_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def verify_backup(self, backup_path: Path) -> bool:
        """Verify backup integrity"""
        try:
            with zipfile.ZipFile(backup_path, 'r') as backup_zip:
                # Check if all required files exist
                required_files = ["manifest.json"]
                
                for required_file in required_files:
                    if required_file not in backup_zip.namelist():
                        logger.error(f"Missing required file in backup: {required_file}")
                        return False
                
                # Test ZIP integrity
                bad_files = backup_zip.testzip()
                if bad_files:
                    logger.error(f"Corrupt files in backup: {bad_files}")
                    return False
                
                # Verify manifest
                manifest_data = backup_zip.read("manifest.json")
                manifest = json.loads(manifest_data)
                
                if not all(key in manifest for key in ["backup_name", "created_at", "version"]):
                    logger.error("Invalid manifest structure")
                    return False
                
                return True
                
        except Exception as e:
            logger.error(f"Backup verification error: {e}")
            return False
    
    async def restore_backup(self, backup_path: str, confirm: bool = False) -> bool:
        """Restore system from backup"""
        try:
            backup_file = Path(backup_path)
            
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            if not confirm:
                logger.warning("⚠️  DANGER: This will overwrite current system data!")
                logger.warning("Use --confirm flag to proceed with restoration")
                return False
            
            # Verify backup before restoration
            if not self.verify_backup(backup_file):
                logger.error("Backup verification failed. Restoration aborted.")
                return False
            
            logger.info(f"Starting restoration from: {backup_path}")
            
            # Create temporary restoration directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract backup
                with zipfile.ZipFile(backup_file, 'r') as backup_zip:
                    backup_zip.extractall(temp_path)
                
                # Read manifest
                manifest_path = temp_path / "manifest.json"
                with open(manifest_path) as f:
                    manifest = json.load(f)
                
                logger.info(f"Restoring backup: {manifest['backup_name']}")
                logger.info(f"Created: {manifest['created_at']}")
                
                # Restore database
                db_backup = temp_path / "database" / "vcc_pki.db"
                if db_backup.exists():
                    # Create backup of current database
                    if Path(self.db_path).exists():
                        backup_current = f"{self.db_path}.restore-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                        shutil.copy2(self.db_path, backup_current)
                        logger.info(f"Current database backed up to: {backup_current}")
                    
                    # Restore database
                    shutil.copy2(db_backup, self.db_path)
                    logger.info("✅ Database restored")
                
                # Restore configuration
                config_backup = temp_path / "config"
                if config_backup.exists():
                    config_dir = Path("config")
                    config_dir.mkdir(exist_ok=True)
                    
                    for config_file in config_backup.iterdir():
                        if config_file.is_file():
                            shutil.copy2(config_file, config_dir / config_file.name)
                            logger.info(f"✅ Restored config: {config_file.name}")
                
                # Restore certificates
                cert_backup = temp_path / "certificates"
                if cert_backup.exists():
                    cert_dir = Path("certificates")
                    if cert_dir.exists():
                        shutil.rmtree(cert_dir)
                    
                    shutil.copytree(cert_backup, cert_dir)
                    logger.info("✅ Certificates restored")
                
                # Restore private keys
                keys_backup = temp_path / "private"
                if keys_backup.exists():
                    keys_dir = Path("private")
                    if keys_dir.exists():
                        shutil.rmtree(keys_dir)
                    
                    shutil.copytree(keys_backup, keys_dir)
                    logger.info("✅ Private keys restored")
            
            # Log restoration event
            await self.log_audit_event("system_restored", details={
                "backup_path": backup_path,
                "backup_name": manifest['backup_name'],
                "restored_at": datetime.now().isoformat()
            })
            
            logger.info("🎉 System restoration completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Restoration failed: {e}")
            return False

    # =================== DATABASE MAINTENANCE ===================
    
    async def vacuum_database(self) -> bool:
        """Optimize database by reclaiming space and rebuilding indexes"""
        try:
            logger.info("Starting database maintenance...")
            
            # Get database stats before vacuum
            stats_before = await self.get_database_stats()
            
            with sqlite3.connect(self.db_path) as conn:
                # Enable WAL mode for better performance
                conn.execute("PRAGMA journal_mode=WAL")
                
                # Analyze tables for query optimization
                conn.execute("ANALYZE")
                
                # Vacuum database to reclaim space
                conn.execute("VACUUM")
                
                # Rebuild indexes
                conn.execute("REINDEX")
                
                conn.commit()
            
            # Get stats after maintenance
            stats_after = await self.get_database_stats()
            
            # Calculate space savings
            space_saved = stats_before.get('size_mb', 0) - stats_after.get('size_mb', 0)
            
            logger.info(f"✅ Database maintenance completed")
            logger.info(f"Space reclaimed: {space_saved:.2f} MB")
            
            # Log maintenance event
            await self.log_audit_event("database_maintenance", details={
                "space_saved_mb": space_saved,
                "before_stats": stats_before,
                "after_stats": stats_after
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Database maintenance failed: {e}")
            return False
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        try:
            stats = {}
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get file size
                db_path_obj = Path(self.db_path)
                if db_path_obj.exists():
                    stats['size_bytes'] = db_path_obj.stat().st_size
                    stats['size_mb'] = stats['size_bytes'] / (1024 * 1024)
                
                # Get table counts
                tables = ['certificates', 'audit_log', 'vcc_services', 'system_config']
                
                for table in tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        stats[f'{table}_count'] = count
                    except sqlite3.OperationalError:
                        stats[f'{table}_count'] = 0
                
                # Get database info
                cursor.execute("PRAGMA database_list")
                db_info = cursor.fetchall()
                stats['databases'] = db_info
                
                # Get page info
                cursor.execute("PRAGMA page_count")
                page_count = cursor.fetchone()[0]
                stats['page_count'] = page_count
                
                cursor.execute("PRAGMA page_size") 
                page_size = cursor.fetchone()[0]
                stats['page_size'] = page_size
                
                # Get integrity check
                cursor.execute("PRAGMA integrity_check(1)")
                integrity = cursor.fetchone()[0]
                stats['integrity'] = integrity
                
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}

    # =================== CERTIFICATE MONITORING ===================
    
    async def check_certificate_expiry(self, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Check for certificates expiring within specified days"""
        try:
            expiring_certs = []
            cutoff_date = datetime.now() + timedelta(days=days_ahead)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, subject, serial_number, status, expires_at, created_at
                    FROM certificates 
                    WHERE expires_at <= ? AND status = 'valid'
                    ORDER BY expires_at ASC
                """, (cutoff_date,))
                
                for row in cursor.fetchall():
                    cert_id, subject, serial, status, expires_str, created_str = row
                    
                    expires_at = datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
                    days_until_expiry = (expires_at - datetime.now()).days
                    
                    expiring_certs.append({
                        'id': cert_id,
                        'subject': subject,
                        'serial_number': serial,
                        'status': status,
                        'expires_at': expires_str,
                        'days_until_expiry': days_until_expiry,
                        'urgency': 'critical' if days_until_expiry <= 7 else 'warning'
                    })
            
            logger.info(f"Found {len(expiring_certs)} certificates expiring within {days_ahead} days")
            
            return expiring_certs
            
        except Exception as e:
            logger.error(f"Certificate expiry check failed: {e}")
            return []
    
    async def generate_expiry_report(self, output_file: Optional[str] = None) -> str:
        """Generate detailed certificate expiry report"""
        try:
            if not output_file:
                output_file = f"certificate-expiry-report-{datetime.now().strftime('%Y%m%d')}.json"
            
            # Check different time periods
            periods = [7, 30, 90, 180, 365]
            report = {
                'generated_at': datetime.now().isoformat(),
                'summary': {},
                'details': {}
            }
            
            for period in periods:
                expiring_certs = await self.check_certificate_expiry(period)
                
                report['summary'][f'expiring_in_{period}_days'] = len(expiring_certs)
                report['details'][f'expiring_in_{period}_days'] = expiring_certs
            
            # Get all certificate statistics
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT status, COUNT(*) as count
                    FROM certificates
                    GROUP BY status
                """)
                
                status_counts = dict(cursor.fetchall())
                report['summary']['by_status'] = status_counts
                
                # Total certificates
                cursor.execute("SELECT COUNT(*) FROM certificates")
                total_certs = cursor.fetchone()[0]
                report['summary']['total_certificates'] = total_certs
            
            # Write report to file
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"✅ Certificate expiry report generated: {output_file}")
            
            # Print summary to console
            print("\n📋 Certificate Expiry Report Summary")
            print("=" * 40)
            print(f"Total Certificates: {report['summary']['total_certificates']}")
            print("\nBy Status:")
            for status, count in report['summary']['by_status'].items():
                print(f"  {status.capitalize()}: {count}")
            
            print("\nExpiring Soon:")
            for period in [7, 30, 90]:
                count = report['summary'].get(f'expiring_in_{period}_days', 0)
                urgency = "🔴" if period <= 7 else "🟡" if period <= 30 else "🟢"
                print(f"  {urgency} Within {period} days: {count}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise

    # =================== HEALTH MONITORING ===================
    
    async def system_health_check(self, verbose: bool = False) -> Dict[str, Any]:
        """Comprehensive system health check"""
        try:
            health_status = {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'healthy',
                'components': {},
                'warnings': [],
                'errors': []
            }
            
            # Check database health
            try:
                db_stats = await self.get_database_stats()
                
                db_health = {
                    'status': 'healthy',
                    'size_mb': db_stats.get('size_mb', 0),
                    'integrity': db_stats.get('integrity', 'unknown'),
                    'total_records': sum([
                        db_stats.get('certificates_count', 0),
                        db_stats.get('audit_log_count', 0),
                        db_stats.get('vcc_services_count', 0)
                    ])
                }
                
                # Check for database issues
                if db_stats.get('integrity') != 'ok':
                    db_health['status'] = 'error'
                    health_status['errors'].append('Database integrity check failed')
                
                if db_stats.get('size_mb', 0) > 1000:  # 1GB threshold
                    db_health['status'] = 'warning'
                    health_status['warnings'].append(f"Large database size: {db_stats.get('size_mb', 0):.1f} MB")
                
                health_status['components']['database'] = db_health
                
            except Exception as e:
                health_status['components']['database'] = {
                    'status': 'error',
                    'error': str(e)
                }
                health_status['errors'].append(f"Database check failed: {e}")
            
            # Check certificate health
            try:
                expiring_certs = await self.check_certificate_expiry(30)
                critical_certs = [c for c in expiring_certs if c['days_until_expiry'] <= 7]
                
                cert_health = {
                    'status': 'healthy',
                    'expiring_soon': len(expiring_certs),
                    'critical': len(critical_certs)
                }
                
                if critical_certs:
                    cert_health['status'] = 'critical'
                    health_status['errors'].append(f"{len(critical_certs)} certificates expiring within 7 days")
                elif expiring_certs:
                    cert_health['status'] = 'warning'
                    health_status['warnings'].append(f"{len(expiring_certs)} certificates expiring within 30 days")
                
                health_status['components']['certificates'] = cert_health
                
            except Exception as e:
                health_status['components']['certificates'] = {
                    'status': 'error',
                    'error': str(e)
                }
                health_status['errors'].append(f"Certificate check failed: {e}")
            
            # Check file system health
            try:
                fs_health = await self.check_filesystem_health()
                health_status['components']['filesystem'] = fs_health
                
                if fs_health['status'] != 'healthy':
                    if fs_health['status'] == 'error':
                        health_status['errors'].extend(fs_health.get('issues', []))
                    else:
                        health_status['warnings'].extend(fs_health.get('issues', []))
                
            except Exception as e:
                health_status['components']['filesystem'] = {
                    'status': 'error',
                    'error': str(e)
                }
                health_status['errors'].append(f"Filesystem check failed: {e}")
            
            # Check VCC services health
            try:
                vcc_health = await self.check_vcc_services_health()
                health_status['components']['vcc_services'] = vcc_health
                
                if vcc_health['offline_count'] > 0:
                    health_status['warnings'].append(f"{vcc_health['offline_count']} VCC services are offline")
                
            except Exception as e:
                health_status['components']['vcc_services'] = {
                    'status': 'error',
                    'error': str(e)
                }
                health_status['errors'].append(f"VCC services check failed: {e}")
            
            # Determine overall status
            if health_status['errors']:
                health_status['overall_status'] = 'critical'
            elif health_status['warnings']:
                health_status['overall_status'] = 'warning'
            
            # Log health check
            await self.log_audit_event("health_check", details={
                'overall_status': health_status['overall_status'],
                'warnings_count': len(health_status['warnings']),
                'errors_count': len(health_status['errors'])
            })
            
            if verbose:
                self.print_health_report(health_status)
            
            return health_status
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'error',
                'error': str(e)
            }
    
    async def check_filesystem_health(self) -> Dict[str, Any]:
        """Check filesystem health and disk usage"""
        try:
            fs_health = {
                'status': 'healthy',
                'issues': []
            }
            
            # Check critical directories
            critical_dirs = ['data', 'certificates', 'private', 'backups', 'logs']
            
            for dir_name in critical_dirs:
                dir_path = Path(dir_name)
                
                if not dir_path.exists():
                    fs_health['issues'].append(f"Missing directory: {dir_name}")
                    fs_health['status'] = 'warning'
                elif not os.access(dir_path, os.R_OK | os.W_OK):
                    fs_health['issues'].append(f"No read/write access to: {dir_name}")
                    fs_health['status'] = 'error'
            
            # Check disk space
            try:
                import shutil
                total, used, free = shutil.disk_usage('.')
                
                free_gb = free / (1024**3)
                usage_percent = (used / total) * 100
                
                fs_health['disk_space'] = {
                    'total_gb': total / (1024**3),
                    'used_gb': used / (1024**3),
                    'free_gb': free_gb,
                    'usage_percent': usage_percent
                }
                
                if free_gb < 1:  # Less than 1GB free
                    fs_health['issues'].append(f"Low disk space: {free_gb:.1f}GB remaining")
                    fs_health['status'] = 'critical' if free_gb < 0.5 else 'warning'
                
                if usage_percent > 90:
                    fs_health['issues'].append(f"High disk usage: {usage_percent:.1f}%")
                    fs_health['status'] = 'warning'
                
            except Exception as e:
                fs_health['issues'].append(f"Could not check disk space: {e}")
            
            return fs_health
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def check_vcc_services_health(self) -> Dict[str, Any]:
        """Check VCC services health and connectivity"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT name, url, status, last_check
                    FROM vcc_services
                """)
                
                services = cursor.fetchall()
                
                service_health = {
                    'status': 'healthy',
                    'total_count': len(services),
                    'online_count': 0,
                    'offline_count': 0,
                    'maintenance_count': 0,
                    'services': []
                }
                
                for name, url, status, last_check in services:
                    service_info = {
                        'name': name,
                        'url': url,
                        'status': status,
                        'last_check': last_check
                    }
                    
                    if status == 'online':
                        service_health['online_count'] += 1
                    elif status == 'offline':
                        service_health['offline_count'] += 1
                    elif status == 'maintenance':
                        service_health['maintenance_count'] += 1
                    
                    service_health['services'].append(service_info)
                
                # Determine overall VCC services health
                if service_health['offline_count'] > service_health['online_count']:
                    service_health['status'] = 'critical'
                elif service_health['offline_count'] > 0:
                    service_health['status'] = 'warning'
                
                return service_health
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def print_health_report(self, health_status: Dict[str, Any]):
        """Print formatted health report to console"""
        print("\n🏥 VCC PKI System Health Report")
        print("=" * 50)
        print(f"Generated: {health_status['timestamp']}")
        
        # Overall status
        status_emoji = {
            'healthy': '🟢',
            'warning': '🟡', 
            'critical': '🔴',
            'error': '❌'
        }
        
        overall = health_status['overall_status']
        print(f"Overall Status: {status_emoji.get(overall, '❓')} {overall.upper()}")
        
        # Components status
        print("\n📊 Component Status:")
        for component, details in health_status.get('components', {}).items():
            comp_status = details.get('status', 'unknown')
            emoji = status_emoji.get(comp_status, '❓')
            print(f"  {emoji} {component.replace('_', ' ').title()}: {comp_status}")
            
            # Show component details
            if comp_status != 'healthy':
                error = details.get('error')
                if error:
                    print(f"    Error: {error}")
        
        # Warnings
        if health_status.get('warnings'):
            print("\n⚠️  Warnings:")
            for warning in health_status['warnings']:
                print(f"  • {warning}")
        
        # Errors  
        if health_status.get('errors'):
            print("\n❌ Errors:")
            for error in health_status['errors']:
                print(f"  • {error}")
        
        print()

    # =================== AUDIT & LOGGING ===================
    
    async def log_audit_event(self, action: str, user_id: str = "system", 
                             resource_type: str = None, resource_id: str = None,
                             details: Dict[str, Any] = None, ip_address: str = "localhost"):
        """Log audit event to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO audit_log (action, user_id, resource_type, resource_id, details, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (action, user_id, resource_type, resource_id, 
                     json.dumps(details) if details else None, ip_address))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    async def cleanup_old_logs(self, days_to_keep: int = 90) -> int:
        """Clean up old audit logs"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Count logs to be deleted
                cursor.execute("""
                    SELECT COUNT(*) FROM audit_log 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                count_to_delete = cursor.fetchone()[0]
                
                # Delete old logs
                cursor.execute("""
                    DELETE FROM audit_log 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                conn.commit()
                
                logger.info(f"✅ Cleaned up {count_to_delete} old audit log entries")
                
                # Log cleanup event
                await self.log_audit_event("log_cleanup", details={
                    'deleted_count': count_to_delete,
                    'cutoff_date': cutoff_date.isoformat(),
                    'days_to_keep': days_to_keep
                })
                
                return count_to_delete
                
        except Exception as e:
            logger.error(f"Log cleanup failed: {e}")
            return 0

# =================== CLI INTERFACE ===================

async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="VCC PKI System - Advanced Administration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s backup --name monthly-backup
  %(prog)s restore backups/backup-20241002.zip --confirm
  %(prog)s health --verbose
  %(prog)s expiry-check --days 30
  %(prog)s expiry-report
  %(prog)s db-maintenance
  %(prog)s cleanup-logs --days 90
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Create system backup')
    backup_parser.add_argument('--name', help='Backup name (auto-generated if not provided)')
    
    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore from backup')
    restore_parser.add_argument('backup_path', help='Path to backup file')
    restore_parser.add_argument('--confirm', action='store_true', help='Confirm restoration')
    
    # Health check command
    health_parser = subparsers.add_parser('health', help='System health check')
    health_parser.add_argument('--verbose', action='store_true', help='Detailed output')
    health_parser.add_argument('--output', help='Save report to file')
    
    # Certificate expiry check
    expiry_parser = subparsers.add_parser('expiry-check', help='Check certificate expiry')
    expiry_parser.add_argument('--days', type=int, default=30, help='Days ahead to check (default: 30)')
    
    # Expiry report
    report_parser = subparsers.add_parser('expiry-report', help='Generate expiry report')
    report_parser.add_argument('--output', help='Output file name')
    
    # Database maintenance
    subparsers.add_parser('db-maintenance', help='Database maintenance (vacuum, analyze, reindex)')
    
    # Log cleanup
    cleanup_parser = subparsers.add_parser('cleanup-logs', help='Clean up old audit logs')
    cleanup_parser.add_argument('--days', type=int, default=90, help='Days to keep (default: 90)')
    
    # Database stats
    subparsers.add_parser('db-stats', help='Show database statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        admin = VCCPKIAdmin()
        
        if args.command == 'backup':
            backup_path = await admin.create_backup(args.name)
            if backup_path:
                print(f"✅ Backup created: {backup_path}")
            else:
                print("❌ Backup failed")
                sys.exit(1)
        
        elif args.command == 'restore':
            success = await admin.restore_backup(args.backup_path, args.confirm)
            if success:
                print("✅ Restoration completed successfully")
            else:
                print("❌ Restoration failed")
                sys.exit(1)
        
        elif args.command == 'health':
            health_status = await admin.system_health_check(verbose=args.verbose)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(health_status, f, indent=2, default=str)
                print(f"✅ Health report saved to: {args.output}")
            
            # Exit with error code if system is not healthy
            if health_status['overall_status'] in ['critical', 'error']:
                sys.exit(1)
        
        elif args.command == 'expiry-check':
            expiring_certs = await admin.check_certificate_expiry(args.days)
            
            if expiring_certs:
                print(f"\n⚠️  {len(expiring_certs)} certificates expiring within {args.days} days:")
                print("-" * 80)
                
                for cert in expiring_certs:
                    urgency_emoji = "🔴" if cert['urgency'] == 'critical' else "🟡"
                    print(f"{urgency_emoji} {cert['subject']}")
                    print(f"   Serial: {cert['serial_number']}")
                    print(f"   Expires: {cert['expires_at']} ({cert['days_until_expiry']} days)")
                    print()
            else:
                print(f"✅ No certificates expiring within {args.days} days")
        
        elif args.command == 'expiry-report':
            report_file = await admin.generate_expiry_report(args.output)
            print(f"✅ Report generated: {report_file}")
        
        elif args.command == 'db-maintenance':
            success = await admin.vacuum_database()
            if success:
                print("✅ Database maintenance completed")
            else:
                print("❌ Database maintenance failed")
                sys.exit(1)
        
        elif args.command == 'cleanup-logs':
            deleted_count = await admin.cleanup_old_logs(args.days)
            print(f"✅ Cleaned up {deleted_count} old log entries")
        
        elif args.command == 'db-stats':
            stats = await admin.get_database_stats()
            
            print("\n📊 Database Statistics")
            print("=" * 30)
            print(f"Size: {stats.get('size_mb', 0):.2f} MB")
            print(f"Pages: {stats.get('page_count', 0)}")
            print(f"Page Size: {stats.get('page_size', 0)} bytes")
            print(f"Integrity: {stats.get('integrity', 'unknown')}")
            
            print("\nTable Counts:")
            for key, value in stats.items():
                if key.endswith('_count'):
                    table_name = key.replace('_count', '').replace('_', ' ').title()
                    print(f"  {table_name}: {value}")
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())