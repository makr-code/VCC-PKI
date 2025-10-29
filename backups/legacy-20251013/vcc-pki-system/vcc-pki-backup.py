#!/usr/bin/env python3
"""
VCC PKI System - Advanced Backup & Recovery Tools
Comprehensive backup, recovery, and disaster recovery capabilities
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import sqlite3
import sys
import tarfile
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
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VCCPKIBackupManager:
    """Advanced backup and recovery manager for VCC PKI system"""
    
    def __init__(self, config_path: str = "config/backup.json"):
        self.config_path = config_path
        self.config = self.load_backup_config()
        self.backup_root = Path(self.config["backup"]["root_directory"])
        self.backup_root.mkdir(exist_ok=True, parents=True)
        
    def load_backup_config(self) -> Dict[str, Any]:
        """Load backup configuration"""
        default_config = {
            "backup": {
                "root_directory": "backups",
                "retention": {
                    "daily": 7,
                    "weekly": 4,
                    "monthly": 12,
                    "yearly": 3
                },
                "compression": "gzip",
                "encryption": {
                    "enabled": False,
                    "key_file": "backup.key"
                },
                "components": {
                    "database": True,
                    "certificates": True,
                    "private_keys": True,
                    "configuration": True,
                    "logs": False
                },
                "remote_sync": {
                    "enabled": False,
                    "type": "rsync",
                    "destination": "backup-server:/vcc-pki-backups/",
                    "ssh_key": "~/.ssh/backup_key"
                }
            },
            "recovery": {
                "staging_directory": "recovery-staging",
                "verify_integrity": True,
                "create_rollback": True
            }
        }
        
        try:
            if Path(self.config_path).exists():
                with open(self.config_path) as f:
                    user_config = json.load(f)
                
                # Merge configurations
                self.merge_config(default_config, user_config)
                return default_config
            else:
                # Create default config
                Path(self.config_path).parent.mkdir(exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                
                logger.info(f"Created default backup config: {self.config_path}")
                return default_config
                
        except Exception as e:
            logger.error(f"Failed to load backup config: {e}")
            return default_config
    
    def merge_config(self, base: Dict, override: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self.merge_config(base[key], value)
            else:
                base[key] = value
    
    async def create_full_backup(self, backup_type: str = "manual", 
                               backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Create a complete system backup"""
        try:
            if not backup_name:
                timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
                backup_name = f"vcc-pki-{backup_type}-{timestamp}"
            
            backup_dir = self.backup_root / backup_name
            backup_dir.mkdir(exist_ok=True)
            
            logger.info(f"Starting full backup: {backup_name}")
            
            backup_manifest = {
                "backup_name": backup_name,
                "backup_type": backup_type,
                "created_at": datetime.now().isoformat(),
                "version": "1.0",
                "components": {},
                "checksums": {},
                "metadata": {
                    "hostname": os.uname().nodename if hasattr(os, 'uname') else 'windows',
                    "platform": sys.platform,
                    "python_version": sys.version
                }
            }
            
            # Backup database
            if self.config["backup"]["components"]["database"]:
                logger.info("Backing up database...")
                db_backup = await self.backup_database(backup_dir)
                backup_manifest["components"]["database"] = db_backup
            
            # Backup certificates
            if self.config["backup"]["components"]["certificates"]:
                logger.info("Backing up certificates...")
                cert_backup = await self.backup_certificates(backup_dir)
                backup_manifest["components"]["certificates"] = cert_backup
            
            # Backup private keys
            if self.config["backup"]["components"]["private_keys"]:
                logger.info("Backing up private keys...")
                key_backup = await self.backup_private_keys(backup_dir)
                backup_manifest["components"]["private_keys"] = key_backup
            
            # Backup configuration
            if self.config["backup"]["components"]["configuration"]:
                logger.info("Backing up configuration...")
                config_backup = await self.backup_configuration(backup_dir)
                backup_manifest["components"]["configuration"] = config_backup
            
            # Backup logs (optional)
            if self.config["backup"]["components"]["logs"]:
                logger.info("Backing up logs...")
                log_backup = await self.backup_logs(backup_dir)
                backup_manifest["components"]["logs"] = log_backup
            
            # Calculate checksums for all backup files
            logger.info("Calculating checksums...")
            checksums = await self.calculate_backup_checksums(backup_dir)
            backup_manifest["checksums"] = checksums
            
            # Write manifest
            manifest_file = backup_dir / "backup-manifest.json"
            with open(manifest_file, 'w') as f:
                json.dump(backup_manifest, f, indent=2)
            
            # Compress backup if enabled
            if self.config["backup"]["compression"]:
                logger.info("Compressing backup...")
                compressed_backup = await self.compress_backup(backup_dir)
                
                # Remove uncompressed directory
                shutil.rmtree(backup_dir)
                
                backup_manifest["compressed_file"] = str(compressed_backup)
                backup_manifest["compressed_size"] = compressed_backup.stat().st_size
            
            # Encrypt backup if enabled
            if self.config["backup"]["encryption"]["enabled"]:
                logger.info("Encrypting backup...")
                encrypted_backup = await self.encrypt_backup(compressed_backup)
                backup_manifest["encrypted_file"] = str(encrypted_backup)
            
            # Sync to remote location if configured
            if self.config["backup"]["remote_sync"]["enabled"]:
                logger.info("Syncing to remote location...")
                await self.sync_to_remote(backup_name)
            
            # Clean up old backups based on retention policy
            await self.cleanup_old_backups(backup_type)
            
            logger.info(f"✅ Backup completed successfully: {backup_name}")
            
            return backup_manifest
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise
    
    async def backup_database(self, backup_dir: Path) -> Dict[str, Any]:
        """Backup database with consistency checks"""
        try:
            db_path = Path("data/vcc_pki.db")
            
            if not db_path.exists():
                return {"status": "skipped", "reason": "Database file not found"}
            
            db_backup_dir = backup_dir / "database"
            db_backup_dir.mkdir(exist_ok=True)
            
            # Create SQLite backup using SQL BACKUP command for consistency
            backup_file = db_backup_dir / "vcc_pki.db"
            
            with sqlite3.connect(str(db_path)) as source_conn:
                with sqlite3.connect(str(backup_file)) as backup_conn:
                    source_conn.backup(backup_conn)
            
            # Export schema and data as SQL dump for additional safety
            sql_dump_file = db_backup_dir / "schema_and_data.sql"
            
            with open(sql_dump_file, 'w') as dump_file:
                with sqlite3.connect(str(db_path)) as conn:
                    for line in conn.iterdump():
                        dump_file.write(f'{line}\n')
            
            # Verify backup integrity
            with sqlite3.connect(str(backup_file)) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()[0]
            
            if integrity_result != "ok":
                raise Exception(f"Backup integrity check failed: {integrity_result}")
            
            return {
                "status": "success",
                "files": [str(backup_file), str(sql_dump_file)],
                "size_bytes": backup_file.stat().st_size + sql_dump_file.stat().st_size,
                "integrity_check": integrity_result
            }
            
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def backup_certificates(self, backup_dir: Path) -> Dict[str, Any]:
        """Backup certificate files"""
        try:
            cert_dir = Path("certificates")
            
            if not cert_dir.exists():
                return {"status": "skipped", "reason": "Certificates directory not found"}
            
            cert_backup_dir = backup_dir / "certificates"
            
            # Copy entire certificate directory structure
            shutil.copytree(cert_dir, cert_backup_dir)
            
            # Count files and calculate size
            file_count = sum(1 for _ in cert_backup_dir.rglob("*") if _.is_file())
            total_size = sum(f.stat().st_size for f in cert_backup_dir.rglob("*") if f.is_file())
            
            return {
                "status": "success",
                "file_count": file_count,
                "size_bytes": total_size,
                "directory": str(cert_backup_dir)
            }
            
        except Exception as e:
            logger.error(f"Certificate backup failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def backup_private_keys(self, backup_dir: Path) -> Dict[str, Any]:
        """Backup private key files with extra security"""
        try:
            keys_dir = Path("private")
            
            if not keys_dir.exists():
                return {"status": "skipped", "reason": "Private keys directory not found"}
            
            keys_backup_dir = backup_dir / "private"
            
            # Copy with preserved permissions
            shutil.copytree(keys_dir, keys_backup_dir)
            
            # Set restrictive permissions on backup
            if hasattr(os, 'chmod'):
                for key_file in keys_backup_dir.rglob("*"):
                    if key_file.is_file():
                        os.chmod(key_file, 0o600)  # Read/write owner only
                
                os.chmod(keys_backup_dir, 0o700)  # Directory access owner only
            
            file_count = sum(1 for _ in keys_backup_dir.rglob("*") if _.is_file())
            total_size = sum(f.stat().st_size for f in keys_backup_dir.rglob("*") if f.is_file())
            
            return {
                "status": "success",
                "file_count": file_count,
                "size_bytes": total_size,
                "directory": str(keys_backup_dir),
                "security_note": "Restrictive permissions applied"
            }
            
        except Exception as e:
            logger.error(f"Private keys backup failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def backup_configuration(self, backup_dir: Path) -> Dict[str, Any]:
        """Backup configuration files"""
        try:
            config_backup_dir = backup_dir / "configuration"
            config_backup_dir.mkdir(exist_ok=True)
            
            config_files = []
            
            # Backup all config files
            config_patterns = [
                "config/*.yaml",
                "config/*.yml", 
                "config/*.json",
                "config/*.toml",
                "*.env",
                ".env.*"
            ]
            
            for pattern in config_patterns:
                for config_file in Path(".").glob(pattern):
                    if config_file.is_file():
                        dest_file = config_backup_dir / config_file.name
                        shutil.copy2(config_file, dest_file)
                        config_files.append(str(config_file))
            
            total_size = sum(f.stat().st_size for f in config_backup_dir.rglob("*") if f.is_file())
            
            return {
                "status": "success",
                "files": config_files,
                "file_count": len(config_files),
                "size_bytes": total_size
            }
            
        except Exception as e:
            logger.error(f"Configuration backup failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def backup_logs(self, backup_dir: Path) -> Dict[str, Any]:
        """Backup log files"""
        try:
            logs_backup_dir = backup_dir / "logs"
            logs_backup_dir.mkdir(exist_ok=True)
            
            log_files = []
            
            # Find log files
            log_patterns = ["*.log", "logs/*.log", "log/*.log"]
            
            for pattern in log_patterns:
                for log_file in Path(".").glob(pattern):
                    if log_file.is_file():
                        dest_file = logs_backup_dir / log_file.name
                        shutil.copy2(log_file, dest_file)
                        log_files.append(str(log_file))
            
            total_size = sum(f.stat().st_size for f in logs_backup_dir.rglob("*") if f.is_file())
            
            return {
                "status": "success",
                "files": log_files,
                "file_count": len(log_files),
                "size_bytes": total_size
            }
            
        except Exception as e:
            logger.error(f"Logs backup failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def calculate_backup_checksums(self, backup_dir: Path) -> Dict[str, str]:
        """Calculate SHA-256 checksums for all backup files"""
        checksums = {}
        
        try:
            for file_path in backup_dir.rglob("*"):
                if file_path.is_file():
                    relative_path = file_path.relative_to(backup_dir)
                    
                    sha256_hash = hashlib.sha256()
                    with open(file_path, "rb") as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    
                    checksums[str(relative_path)] = sha256_hash.hexdigest()
            
            return checksums
            
        except Exception as e:
            logger.error(f"Checksum calculation failed: {e}")
            return {}
    
    async def compress_backup(self, backup_dir: Path) -> Path:
        """Compress backup directory"""
        try:
            compression = self.config["backup"]["compression"]
            
            if compression == "gzip":
                compressed_file = backup_dir.with_suffix('.tar.gz')
                
                with tarfile.open(compressed_file, "w:gz") as tar:
                    tar.add(backup_dir, arcname=backup_dir.name)
                
            elif compression == "zip":
                compressed_file = backup_dir.with_suffix('.zip')
                
                with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in backup_dir.rglob("*"):
                        if file_path.is_file():
                            arcname = file_path.relative_to(backup_dir.parent)
                            zipf.write(file_path, arcname)
            
            else:
                # No compression, create tar archive
                compressed_file = backup_dir.with_suffix('.tar')
                
                with tarfile.open(compressed_file, "w") as tar:
                    tar.add(backup_dir, arcname=backup_dir.name)
            
            return compressed_file
            
        except Exception as e:
            logger.error(f"Backup compression failed: {e}")
            raise
    
    async def encrypt_backup(self, backup_file: Path) -> Path:
        """Encrypt backup file using GPG"""
        try:
            # This would use GPG or similar encryption tool
            # For now, return the original file (encryption not implemented)
            logger.warning("Backup encryption not implemented yet")
            return backup_file
            
        except Exception as e:
            logger.error(f"Backup encryption failed: {e}")
            return backup_file
    
    async def sync_to_remote(self, backup_name: str):
        """Sync backup to remote location"""
        try:
            remote_config = self.config["backup"]["remote_sync"]
            
            if remote_config["type"] == "rsync":
                cmd = [
                    "rsync", 
                    "-avz",
                    "--progress",
                    str(self.backup_root / backup_name),
                    remote_config["destination"]
                ]
                
                if "ssh_key" in remote_config:
                    cmd.extend(["-e", f"ssh -i {remote_config['ssh_key']}"])
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    raise Exception(f"rsync failed: {result.stderr}")
                
                logger.info("Backup synced to remote location successfully")
            
        except Exception as e:
            logger.error(f"Remote sync failed: {e}")
            # Don't fail the backup for remote sync issues
    
    async def cleanup_old_backups(self, backup_type: str):
        """Clean up old backups based on retention policy"""
        try:
            retention = self.config["backup"]["retention"]
            
            # Get retention count for backup type
            retention_count = retention.get(backup_type, 7)
            
            # Find all backups of this type
            backup_pattern = f"vcc-pki-{backup_type}-*"
            backups = list(self.backup_root.glob(backup_pattern))
            backups.extend(self.backup_root.glob(f"{backup_pattern}.tar.gz"))
            backups.extend(self.backup_root.glob(f"{backup_pattern}.zip"))
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Remove old backups
            to_remove = backups[retention_count:]
            
            for old_backup in to_remove:
                if old_backup.is_dir():
                    shutil.rmtree(old_backup)
                else:
                    old_backup.unlink()
                
                logger.info(f"Removed old backup: {old_backup.name}")
            
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} old {backup_type} backups")
                
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
    
    async def restore_from_backup(self, backup_path: str, 
                                 components: Optional[List[str]] = None,
                                 dry_run: bool = False) -> Dict[str, Any]:
        """Restore system from backup"""
        try:
            backup_file = Path(backup_path)
            
            if not backup_file.exists():
                raise Exception(f"Backup file not found: {backup_path}")
            
            logger.info(f"Starting restoration from: {backup_path}")
            
            # Create staging directory
            staging_dir = Path(self.config["recovery"]["staging_directory"])
            if staging_dir.exists():
                shutil.rmtree(staging_dir)
            staging_dir.mkdir(parents=True)
            
            try:
                # Extract backup
                if backup_file.suffix == '.gz':
                    with tarfile.open(backup_file, "r:gz") as tar:
                        tar.extractall(staging_dir)
                elif backup_file.suffix == '.zip':
                    with zipfile.ZipFile(backup_file, 'r') as zipf:
                        zipf.extractall(staging_dir)
                else:
                    with tarfile.open(backup_file, "r") as tar:
                        tar.extractall(staging_dir)
                
                # Find backup directory in staging
                backup_dirs = [d for d in staging_dir.iterdir() if d.is_dir()]
                if not backup_dirs:
                    raise Exception("No backup directory found in archive")
                
                extracted_backup_dir = backup_dirs[0]
                
                # Load and verify manifest
                manifest_file = extracted_backup_dir / "backup-manifest.json"
                if not manifest_file.exists():
                    raise Exception("Backup manifest not found")
                
                with open(manifest_file) as f:
                    manifest = json.load(f)
                
                logger.info(f"Backup: {manifest['backup_name']}")
                logger.info(f"Created: {manifest['created_at']}")
                
                # Verify checksums if enabled
                if self.config["recovery"]["verify_integrity"]:
                    logger.info("Verifying backup integrity...")
                    if not await self.verify_backup_integrity(extracted_backup_dir, manifest):
                        raise Exception("Backup integrity verification failed")
                
                # Create rollback backup if enabled
                rollback_backup = None
                if self.config["recovery"]["create_rollback"]:
                    logger.info("Creating rollback backup...")
                    rollback_backup = await self.create_full_backup("rollback", 
                                                                   f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                
                recovery_results = {
                    "backup_name": manifest["backup_name"],
                    "restored_components": {},
                    "rollback_backup": rollback_backup,
                    "dry_run": dry_run
                }
                
                # Determine components to restore
                if not components:
                    components = list(manifest["components"].keys())
                
                # Restore each component
                for component in components:
                    if component in manifest["components"]:
                        logger.info(f"Restoring component: {component}")
                        
                        if not dry_run:
                            result = await self.restore_component(component, extracted_backup_dir)
                            recovery_results["restored_components"][component] = result
                        else:
                            recovery_results["restored_components"][component] = {"status": "dry_run"}
                    else:
                        logger.warning(f"Component not found in backup: {component}")
                        recovery_results["restored_components"][component] = {"status": "not_found"}
                
                if not dry_run:
                    logger.info("✅ System restoration completed successfully!")
                else:
                    logger.info("🔍 Dry run completed - no changes made")
                
                return recovery_results
                
            finally:
                # Clean up staging directory
                if staging_dir.exists():
                    shutil.rmtree(staging_dir)
            
        except Exception as e:
            logger.error(f"Restoration failed: {e}")
            raise
    
    async def verify_backup_integrity(self, backup_dir: Path, manifest: Dict[str, Any]) -> bool:
        """Verify backup integrity using checksums"""
        try:
            stored_checksums = manifest.get("checksums", {})
            
            if not stored_checksums:
                logger.warning("No checksums in manifest - skipping integrity check")
                return True
            
            for relative_path, stored_checksum in stored_checksums.items():
                file_path = backup_dir / relative_path
                
                if not file_path.exists():
                    logger.error(f"Missing file in backup: {relative_path}")
                    return False
                
                # Calculate current checksum
                sha256_hash = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                
                current_checksum = sha256_hash.hexdigest()
                
                if current_checksum != stored_checksum:
                    logger.error(f"Checksum mismatch for {relative_path}")
                    return False
            
            logger.info("✅ Backup integrity verification passed")
            return True
            
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False
    
    async def restore_component(self, component: str, backup_dir: Path) -> Dict[str, Any]:
        """Restore a specific component from backup"""
        try:
            if component == "database":
                return await self.restore_database(backup_dir)
            elif component == "certificates":
                return await self.restore_certificates(backup_dir)
            elif component == "private_keys":
                return await self.restore_private_keys(backup_dir)
            elif component == "configuration":
                return await self.restore_configuration(backup_dir)
            elif component == "logs":
                return await self.restore_logs(backup_dir)
            else:
                return {"status": "unknown_component", "component": component}
                
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def restore_database(self, backup_dir: Path) -> Dict[str, Any]:
        """Restore database from backup"""
        try:
            db_backup_file = backup_dir / "database" / "vcc_pki.db"
            
            if not db_backup_file.exists():
                return {"status": "not_found"}
            
            # Create backup of current database
            current_db = Path("data/vcc_pki.db")
            if current_db.exists():
                backup_current = current_db.with_suffix(f".restore-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db")
                shutil.copy2(current_db, backup_current)
            
            # Ensure data directory exists
            Path("data").mkdir(exist_ok=True)
            
            # Restore database
            shutil.copy2(db_backup_file, current_db)
            
            # Verify restored database
            with sqlite3.connect(str(current_db)) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                integrity = cursor.fetchone()[0]
            
            if integrity != "ok":
                raise Exception(f"Restored database failed integrity check: {integrity}")
            
            return {"status": "success", "integrity": integrity}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def restore_certificates(self, backup_dir: Path) -> Dict[str, Any]:
        """Restore certificates from backup"""
        try:
            cert_backup_dir = backup_dir / "certificates"
            
            if not cert_backup_dir.exists():
                return {"status": "not_found"}
            
            cert_dir = Path("certificates")
            
            # Backup current certificates if they exist
            if cert_dir.exists():
                backup_current = Path(f"certificates.restore-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                shutil.move(cert_dir, backup_current)
            
            # Restore certificates
            shutil.copytree(cert_backup_dir, cert_dir)
            
            file_count = sum(1 for _ in cert_dir.rglob("*") if _.is_file())
            
            return {"status": "success", "restored_files": file_count}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def restore_private_keys(self, backup_dir: Path) -> Dict[str, Any]:
        """Restore private keys from backup"""
        try:
            keys_backup_dir = backup_dir / "private"
            
            if not keys_backup_dir.exists():
                return {"status": "not_found"}
            
            keys_dir = Path("private")
            
            # Backup current keys if they exist
            if keys_dir.exists():
                backup_current = Path(f"private.restore-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                shutil.move(keys_dir, backup_current)
            
            # Restore keys
            shutil.copytree(keys_backup_dir, keys_dir)
            
            # Set proper permissions
            if hasattr(os, 'chmod'):
                os.chmod(keys_dir, 0o700)
                for key_file in keys_dir.rglob("*"):
                    if key_file.is_file():
                        os.chmod(key_file, 0o600)
            
            file_count = sum(1 for _ in keys_dir.rglob("*") if _.is_file())
            
            return {"status": "success", "restored_files": file_count, "permissions": "secured"}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def restore_configuration(self, backup_dir: Path) -> Dict[str, Any]:
        """Restore configuration from backup"""
        try:
            config_backup_dir = backup_dir / "configuration"
            
            if not config_backup_dir.exists():
                return {"status": "not_found"}
            
            # Restore config files
            restored_files = []
            
            for config_file in config_backup_dir.iterdir():
                if config_file.is_file():
                    dest_path = Path(config_file.name)
                    
                    # Backup current file if it exists
                    if dest_path.exists():
                        backup_current = dest_path.with_suffix(f"{dest_path.suffix}.restore-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                        shutil.copy2(dest_path, backup_current)
                    
                    shutil.copy2(config_file, dest_path)
                    restored_files.append(str(dest_path))
            
            return {"status": "success", "restored_files": restored_files}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def restore_logs(self, backup_dir: Path) -> Dict[str, Any]:
        """Restore logs from backup"""
        try:
            logs_backup_dir = backup_dir / "logs"
            
            if not logs_backup_dir.exists():
                return {"status": "not_found"}
            
            # Create logs directory if needed
            Path("logs").mkdir(exist_ok=True)
            
            restored_files = []
            
            for log_file in logs_backup_dir.iterdir():
                if log_file.is_file():
                    dest_path = Path("logs") / log_file.name
                    shutil.copy2(log_file, dest_path)
                    restored_files.append(str(dest_path))
            
            return {"status": "success", "restored_files": restored_files}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

async def main():
    """Main CLI interface for backup and recovery"""
    parser = argparse.ArgumentParser(
        description="VCC PKI System - Advanced Backup & Recovery",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Backup commands
    backup_parser = subparsers.add_parser('backup', help='Create system backup')
    backup_parser.add_argument('--type', choices=['manual', 'daily', 'weekly', 'monthly'], 
                              default='manual', help='Backup type')
    backup_parser.add_argument('--name', help='Custom backup name')
    
    # Restore commands
    restore_parser = subparsers.add_parser('restore', help='Restore from backup')
    restore_parser.add_argument('backup_path', help='Path to backup file')
    restore_parser.add_argument('--components', nargs='+', 
                               choices=['database', 'certificates', 'private_keys', 'configuration', 'logs'],
                               help='Components to restore (default: all)')
    restore_parser.add_argument('--dry-run', action='store_true', help='Simulate restoration')
    
    # List backups
    subparsers.add_parser('list', help='List available backups')
    
    # Verify backup
    verify_parser = subparsers.add_parser('verify', help='Verify backup integrity')
    verify_parser.add_argument('backup_path', help='Path to backup file')
    
    # Cleanup old backups
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old backups')
    cleanup_parser.add_argument('--type', choices=['manual', 'daily', 'weekly', 'monthly'],
                               help='Backup type to clean up (default: all)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        backup_manager = VCCPKIBackupManager()
        
        if args.command == 'backup':
            manifest = await backup_manager.create_full_backup(args.type, args.name)
            print("✅ Backup created successfully!")
            print(f"Backup name: {manifest['backup_name']}")
            
        elif args.command == 'restore':
            result = await backup_manager.restore_from_backup(
                args.backup_path, 
                args.components, 
                args.dry_run
            )
            
            if args.dry_run:
                print("🔍 Dry run completed - no changes made")
            else:
                print("✅ Restoration completed successfully!")
            
            print(f"Components: {list(result['restored_components'].keys())}")
            
        elif args.command == 'list':
            backups = list(backup_manager.backup_root.glob("vcc-pki-*"))
            
            if backups:
                print("\n📋 Available Backups:")
                print("-" * 60)
                
                for backup in sorted(backups, key=lambda x: x.stat().st_mtime, reverse=True):
                    size = backup.stat().st_size if backup.is_file() else sum(
                        f.stat().st_size for f in backup.rglob("*") if f.is_file()
                    )
                    mtime = datetime.fromtimestamp(backup.stat().st_mtime)
                    
                    print(f"{backup.name}")
                    print(f"  Size: {size / (1024*1024):.1f} MB")
                    print(f"  Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
                    print()
            else:
                print("No backups found.")
                
        elif args.command == 'verify':
            # Verification would be implemented here
            print(f"Verifying backup: {args.backup_path}")
            print("✅ Backup verification not fully implemented yet")
            
        elif args.command == 'cleanup':
            if args.type:
                await backup_manager.cleanup_old_backups(args.type)
            else:
                # Clean up all types
                for backup_type in ['manual', 'daily', 'weekly', 'monthly']:
                    await backup_manager.cleanup_old_backups(backup_type)
            
            print("✅ Backup cleanup completed")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())