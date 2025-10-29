# VCC PKI System - Production Backup & Recovery Procedures
# Comprehensive Disaster Recovery & Business Continuity für Brandenburg Government PKI

import os
import shutil
import subprocess
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import tarfile
import gzip
import hashlib
import json
import yaml

logger = logging.getLogger(__name__)

class BackupType(Enum):
    """Backup Types für verschiedene Recovery-Szenarien"""
    FULL = "full"                    # Complete system backup
    INCREMENTAL = "incremental"      # Changes since last backup  
    DIFFERENTIAL = "differential"    # Changes since last full backup
    DATABASE_ONLY = "database_only"  # Database dump only
    HSM_KEYS = "hsm_keys"           # HSM key backup (encrypted)
    CONFIGURATION = "configuration"  # System configuration only
    CERTIFICATES = "certificates"    # Certificate store backup

class BackupFrequency(Enum):
    """Backup Frequency Scheduling"""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_DEMAND = "on_demand"

class RecoveryType(Enum):
    """Recovery Scenarios"""
    POINT_IN_TIME = "point_in_time"      # Restore to specific timestamp
    FULL_SYSTEM = "full_system"          # Complete system restoration
    DATABASE_ONLY = "database_only"      # Database restoration only
    PARTIAL_RESTORE = "partial_restore"   # Selective restoration
    DISASTER_RECOVERY = "disaster_recovery"  # DR site activation

@dataclass
class BackupMetadata:
    """Backup Metadata für Tracking und Validation"""
    backup_id: str
    backup_type: BackupType
    created_at: datetime
    size_bytes: int
    checksum_sha256: str
    
    # Content Information
    database_included: bool
    certificates_included: bool
    hsm_keys_included: bool
    configuration_included: bool
    
    # Backup Source
    environment: str
    hostname: str
    pki_version: str
    
    # Encryption
    encrypted: bool = True
    encryption_key_id: Optional[str] = None
    
    # Validation
    validated: bool = False
    validation_date: Optional[datetime] = None
    
    # Retention
    expires_at: Optional[datetime] = None
    retention_policy: str = "default"

@dataclass
class BackupConfiguration:
    """Backup Configuration für verschiedene Backup-Typen"""
    
    # Storage Configuration
    backup_root_path: Path
    remote_backup_enabled: bool = False
    remote_backup_url: Optional[str] = None
    
    # Encryption
    encryption_enabled: bool = True
    encryption_key_path: str = "/etc/vcc-pki/backup-encryption.key"
    
    # Compression
    compression_enabled: bool = True
    compression_level: int = 6
    
    # Schedules
    full_backup_schedule: str = "0 2 * * 0"      # Weekly on Sunday 2 AM
    incremental_schedule: str = "0 2 * * 1-6"    # Daily except Sunday
    database_backup_schedule: str = "0 */6 * * *" # Every 6 hours
    
    # Retention Policies (days)
    full_backup_retention: int = 90
    incremental_retention: int = 30  
    database_retention: int = 14
    hsm_key_retention: int = 2555  # 7 years for compliance
    
    # Performance
    max_parallel_jobs: int = 4
    backup_timeout_hours: int = 24
    
    # Notification
    notify_on_success: bool = True
    notify_on_failure: bool = True
    notification_recipients: List[str] = field(default_factory=list)

class VCCPKIBackupManager:
    """Production Backup Manager für VCC PKI System"""
    
    def __init__(self, config: BackupConfiguration):
        self.config = config
        self.backup_index: Dict[str, BackupMetadata] = {}
        
        # Ensure backup directory exists
        self.config.backup_root_path.mkdir(parents=True, exist_ok=True)
        
        # Load existing backup index
        self._load_backup_index()
    
    async def create_full_backup(self, 
                               backup_id: Optional[str] = None,
                               include_hsm_keys: bool = True) -> BackupMetadata:
        """
        Create comprehensive full system backup
        """
        try:
            if not backup_id:
                backup_id = f"full_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            logger.info(f"Starting full backup: {backup_id}")
            
            backup_path = self.config.backup_root_path / backup_id
            backup_path.mkdir(exist_ok=True)
            
            # Create backup metadata
            metadata = BackupMetadata(
                backup_id=backup_id,
                backup_type=BackupType.FULL,
                created_at=datetime.now(),
                size_bytes=0,
                checksum_sha256="",
                database_included=True,
                certificates_included=True,
                hsm_keys_included=include_hsm_keys,
                configuration_included=True,
                environment=os.getenv("VCC_PKI_ENVIRONMENT", "unknown"),
                hostname=os.uname().nodename,
                pki_version=await self._get_pki_version()
            )
            
            # Backup Database
            logger.info("Backing up database...")
            db_backup_path = await self._backup_database(backup_path / "database")
            
            # Backup Certificate Store
            logger.info("Backing up certificate store...")
            cert_backup_path = await self._backup_certificates(backup_path / "certificates")
            
            # Backup Configuration
            logger.info("Backing up configuration...")
            config_backup_path = await self._backup_configuration(backup_path / "configuration")
            
            # Backup HSM Keys (if enabled and available)
            hsm_backup_path = None
            if include_hsm_keys:
                logger.info("Backing up HSM key metadata...")
                hsm_backup_path = await self._backup_hsm_metadata(backup_path / "hsm")
            
            # Backup Application Files
            logger.info("Backing up application files...")
            app_backup_path = await self._backup_application_files(backup_path / "application")
            
            # Create archive
            logger.info("Creating compressed archive...")
            archive_path = await self._create_backup_archive(backup_path, backup_id)
            
            # Calculate checksum
            metadata.checksum_sha256 = await self._calculate_checksum(archive_path)
            metadata.size_bytes = archive_path.stat().st_size
            
            # Encrypt if enabled
            if self.config.encryption_enabled:
                logger.info("Encrypting backup archive...")
                archive_path = await self._encrypt_backup(archive_path)
                metadata.encrypted = True
            
            # Set expiration
            metadata.expires_at = datetime.now() + timedelta(days=self.config.full_backup_retention)
            
            # Validate backup
            logger.info("Validating backup...")
            validation_result = await self._validate_backup(archive_path, metadata)
            metadata.validated = validation_result.valid
            metadata.validation_date = datetime.now()
            
            # Update index
            self.backup_index[backup_id] = metadata
            await self._save_backup_index()
            
            # Cleanup temporary files
            if backup_path.exists():
                shutil.rmtree(backup_path)
            
            logger.info(f"Full backup completed: {backup_id} ({metadata.size_bytes} bytes)")
            
            # Send notification
            if self.config.notify_on_success:
                await self._send_notification(
                    f"VCC PKI Full Backup Successful: {backup_id}",
                    f"Backup completed successfully\nSize: {metadata.size_bytes / 1024 / 1024:.2f} MB\nValidated: {metadata.validated}"
                )
            
            return metadata
            
        except Exception as e:
            logger.error(f"Full backup failed: {e}")
            
            # Send failure notification
            if self.config.notify_on_failure:
                await self._send_notification(
                    f"VCC PKI Backup Failed: {backup_id}",
                    f"Backup failed with error: {str(e)}"
                )
            
            raise
    
    async def create_incremental_backup(self, 
                                      since_backup_id: Optional[str] = None) -> BackupMetadata:
        """
        Create incremental backup since last backup or specified backup
        """
        try:
            backup_id = f"inc_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Find reference backup
            if not since_backup_id:
                since_backup_id = self._find_latest_full_backup()
            
            if not since_backup_id:
                raise ValueError("No reference backup found for incremental backup")
            
            logger.info(f"Creating incremental backup since: {since_backup_id}")
            
            # Get changes since reference backup
            reference_metadata = self.backup_index[since_backup_id]
            since_date = reference_metadata.created_at
            
            backup_path = self.config.backup_root_path / backup_id
            backup_path.mkdir(exist_ok=True)
            
            metadata = BackupMetadata(
                backup_id=backup_id,
                backup_type=BackupType.INCREMENTAL,
                created_at=datetime.now(),
                size_bytes=0,
                checksum_sha256="",
                database_included=True,
                certificates_included=True,
                hsm_keys_included=False,  # Not included in incremental
                configuration_included=True,
                environment=os.getenv("VCC_PKI_ENVIRONMENT", "unknown"),
                hostname=os.uname().nodename,
                pki_version=await self._get_pki_version()
            )
            
            # Incremental database backup
            await self._backup_database_incremental(backup_path / "database", since_date)
            
            # Incremental certificate backup  
            await self._backup_certificates_incremental(backup_path / "certificates", since_date)
            
            # Configuration changes
            await self._backup_configuration_incremental(backup_path / "configuration", since_date)
            
            # Create and encrypt archive
            archive_path = await self._create_backup_archive(backup_path, backup_id)
            
            if self.config.encryption_enabled:
                archive_path = await self._encrypt_backup(archive_path)
                metadata.encrypted = True
            
            metadata.checksum_sha256 = await self._calculate_checksum(archive_path)
            metadata.size_bytes = archive_path.stat().st_size
            metadata.expires_at = datetime.now() + timedelta(days=self.config.incremental_retention)
            
            # Update index
            self.backup_index[backup_id] = metadata
            await self._save_backup_index()
            
            # Cleanup
            if backup_path.exists():
                shutil.rmtree(backup_path)
            
            logger.info(f"Incremental backup completed: {backup_id}")
            return metadata
            
        except Exception as e:
            logger.error(f"Incremental backup failed: {e}")
            raise
    
    async def restore_from_backup(self,
                                backup_id: str,
                                recovery_type: RecoveryType = RecoveryType.FULL_SYSTEM,
                                target_path: Optional[Path] = None) -> bool:
        """
        Restore VCC PKI System from backup
        """
        try:
            logger.info(f"Starting restoration from backup: {backup_id}")
            
            if backup_id not in self.backup_index:
                raise ValueError(f"Backup not found: {backup_id}")
            
            metadata = self.backup_index[backup_id]
            
            # Validate backup before restoration
            backup_file_path = self._get_backup_file_path(backup_id)
            if not backup_file_path.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_file_path}")
            
            # Create restoration workspace
            restore_path = target_path or Path("/tmp/vcc-pki-restore")
            restore_path.mkdir(parents=True, exist_ok=True)
            
            # Decrypt backup if necessary
            if metadata.encrypted:
                logger.info("Decrypting backup...")
                decrypted_path = await self._decrypt_backup(backup_file_path)
                backup_file_path = decrypted_path
            
            # Extract backup
            logger.info("Extracting backup archive...")
            await self._extract_backup_archive(backup_file_path, restore_path)
            
            # Perform restoration based on recovery type
            if recovery_type == RecoveryType.FULL_SYSTEM:
                await self._restore_full_system(restore_path, metadata)
            elif recovery_type == RecoveryType.DATABASE_ONLY:
                await self._restore_database_only(restore_path, metadata)
            elif recovery_type == RecoveryType.PARTIAL_RESTORE:
                await self._restore_partial_system(restore_path, metadata)
            else:
                raise ValueError(f"Unsupported recovery type: {recovery_type}")
            
            logger.info(f"Restoration completed successfully from backup: {backup_id}")
            
            # Send notification
            await self._send_notification(
                f"VCC PKI System Restoration Completed",
                f"Successfully restored from backup: {backup_id}\nRecovery Type: {recovery_type.value}"
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Restoration failed: {e}")
            
            await self._send_notification(
                f"VCC PKI Restoration Failed", 
                f"Failed to restore from backup {backup_id}: {str(e)}"
            )
            
            raise
    
    async def verify_backup_integrity(self, backup_id: str) -> Dict[str, Any]:
        """
        Comprehensive backup integrity verification
        """
        try:
            logger.info(f"Verifying backup integrity: {backup_id}")
            
            if backup_id not in self.backup_index:
                raise ValueError(f"Backup not found: {backup_id}")
            
            metadata = self.backup_index[backup_id]
            backup_file_path = self._get_backup_file_path(backup_id)
            
            verification_result = {
                "backup_id": backup_id,
                "file_exists": backup_file_path.exists(),
                "checksum_valid": False,
                "size_matches": False,
                "archive_intact": False,
                "content_valid": False,
                "errors": []
            }
            
            if not verification_result["file_exists"]:
                verification_result["errors"].append("Backup file not found")
                return verification_result
            
            # Verify file size
            actual_size = backup_file_path.stat().st_size
            verification_result["size_matches"] = actual_size == metadata.size_bytes
            
            if not verification_result["size_matches"]:
                verification_result["errors"].append(
                    f"Size mismatch: expected {metadata.size_bytes}, got {actual_size}"
                )
            
            # Verify checksum
            actual_checksum = await self._calculate_checksum(backup_file_path)
            verification_result["checksum_valid"] = actual_checksum == metadata.checksum_sha256
            
            if not verification_result["checksum_valid"]:
                verification_result["errors"].append("Checksum verification failed")
            
            # Verify archive integrity
            try:
                # Decrypt if necessary for archive test
                test_file = backup_file_path
                if metadata.encrypted:
                    test_file = await self._decrypt_backup(backup_file_path, verify_only=True)
                
                # Test archive extraction
                with tarfile.open(test_file, 'r:gz') as tar:
                    tar.getmembers()  # This will fail if archive is corrupted
                
                verification_result["archive_intact"] = True
                
            except Exception as e:
                verification_result["errors"].append(f"Archive integrity check failed: {str(e)}")
            
            # Content validation (selective)
            if verification_result["archive_intact"]:
                try:
                    content_validation = await self._validate_backup_content(backup_file_path, metadata)
                    verification_result["content_valid"] = content_validation.all_valid
                    
                    if not content_validation.all_valid:
                        verification_result["errors"].extend(content_validation.errors)
                        
                except Exception as e:
                    verification_result["errors"].append(f"Content validation failed: {str(e)}")
            
            # Overall verification status
            verification_result["overall_valid"] = (
                verification_result["file_exists"] and
                verification_result["checksum_valid"] and
                verification_result["size_matches"] and
                verification_result["archive_intact"] and
                verification_result["content_valid"]
            )
            
            logger.info(f"Backup verification completed: {backup_id} - Valid: {verification_result['overall_valid']}")
            return verification_result
            
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return {
                "backup_id": backup_id,
                "overall_valid": False,
                "errors": [str(e)]
            }
    
    async def cleanup_expired_backups(self) -> Dict[str, Any]:
        """
        Clean up expired backups based on retention policies
        """
        cleanup_result = {
            "deleted_backups": [],
            "freed_space_bytes": 0,
            "errors": []
        }
        
        try:
            current_time = datetime.now()
            
            for backup_id, metadata in list(self.backup_index.items()):
                if metadata.expires_at and metadata.expires_at < current_time:
                    try:
                        backup_file_path = self._get_backup_file_path(backup_id)
                        
                        if backup_file_path.exists():
                            file_size = backup_file_path.stat().st_size
                            backup_file_path.unlink()
                            cleanup_result["freed_space_bytes"] += file_size
                        
                        # Remove from index
                        del self.backup_index[backup_id]
                        cleanup_result["deleted_backups"].append(backup_id)
                        
                        logger.info(f"Deleted expired backup: {backup_id}")
                        
                    except Exception as e:
                        error_msg = f"Failed to delete backup {backup_id}: {str(e)}"
                        cleanup_result["errors"].append(error_msg)
                        logger.error(error_msg)
            
            # Save updated index
            await self._save_backup_index()
            
            logger.info(f"Backup cleanup completed: {len(cleanup_result['deleted_backups'])} backups deleted, "
                       f"{cleanup_result['freed_space_bytes'] / 1024 / 1024:.2f} MB freed")
            
            return cleanup_result
            
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            cleanup_result["errors"].append(str(e))
            return cleanup_result
    
    # Private Helper Methods
    
    async def _backup_database(self, backup_path: Path) -> Path:
        """Backup PostgreSQL database"""
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Get database configuration
        from .environment_config import get_environment_manager
        env_manager = get_environment_manager()
        db_config = env_manager.config.database
        
        # Create database dump
        dump_file = backup_path / "database_dump.sql"
        
        cmd = [
            "pg_dump",
            f"--host={db_config.host}",
            f"--port={db_config.port}",
            f"--username={db_config.username}",
            f"--dbname={db_config.database}",
            "--verbose",
            "--clean",
            "--create",
            "--if-exists",
            f"--file={dump_file}"
        ]
        
        # Set password via environment
        env = os.environ.copy()
        env["PGPASSWORD"] = db_config.password
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Database backup failed: {stderr.decode()}")
        
        return dump_file
    
    async def _backup_certificates(self, backup_path: Path) -> Path:
        """Backup certificate store"""
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Certificate files directory
        cert_store_path = Path("/var/lib/vcc-pki/certificates")
        
        if cert_store_path.exists():
            # Create certificate archive
            cert_archive = backup_path / "certificates.tar.gz"
            
            with tarfile.open(cert_archive, "w:gz") as tar:
                tar.add(cert_store_path, arcname="certificates")
        
        return backup_path
    
    async def _backup_configuration(self, backup_path: Path) -> Path:
        """Backup system configuration"""
        backup_path.mkdir(parents=True, exist_ok=True)
        
        config_files = [
            "/etc/vcc-pki/",
            "/opt/vcc-pki/config/",
            "/var/lib/vcc-pki/config/"
        ]
        
        config_archive = backup_path / "configuration.tar.gz"
        
        with tarfile.open(config_archive, "w:gz") as tar:
            for config_path in config_files:
                if Path(config_path).exists():
                    tar.add(config_path, arcname=Path(config_path).name)
        
        return backup_path
    
    async def _backup_hsm_metadata(self, backup_path: Path) -> Path:
        """Backup HSM key metadata (not actual keys)"""
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # HSM metadata (key labels, slot info, etc.)
        # Actual keys stay in HSM for security
        hsm_metadata = {
            "backup_date": datetime.now().isoformat(),
            "hsm_slots": {},
            "key_metadata": {}
        }
        
        metadata_file = backup_path / "hsm_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(hsm_metadata, f, indent=2)
        
        return backup_path
    
    def _get_backup_file_path(self, backup_id: str) -> Path:
        """Get backup file path"""
        return self.config.backup_root_path / f"{backup_id}.tar.gz"
    
    async def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _load_backup_index(self):
        """Load backup index from disk"""
        index_file = self.config.backup_root_path / "backup_index.json"
        
        if index_file.exists():
            try:
                with open(index_file) as f:
                    index_data = json.load(f)
                
                # Convert to BackupMetadata objects
                for backup_id, metadata_dict in index_data.items():
                    # Convert datetime strings back to datetime objects
                    metadata_dict["created_at"] = datetime.fromisoformat(metadata_dict["created_at"])
                    if metadata_dict.get("validation_date"):
                        metadata_dict["validation_date"] = datetime.fromisoformat(metadata_dict["validation_date"])
                    if metadata_dict.get("expires_at"):
                        metadata_dict["expires_at"] = datetime.fromisoformat(metadata_dict["expires_at"])
                    
                    # Convert backup_type string to enum
                    metadata_dict["backup_type"] = BackupType(metadata_dict["backup_type"])
                    
                    self.backup_index[backup_id] = BackupMetadata(**metadata_dict)
                    
            except Exception as e:
                logger.warning(f"Failed to load backup index: {e}")
                self.backup_index = {}

if __name__ == "__main__":
    # Test backup configuration
    backup_config = BackupConfiguration(
        backup_root_path=Path("/var/backups/vcc-pki"),
        encryption_enabled=True,
        notification_recipients=["backup-admin@vcc.brandenburg.de"]
    )
    
    backup_manager = VCCPKIBackupManager(backup_config)
    print("VCC PKI Backup Manager initialized")
    print(f"Backup root: {backup_config.backup_root_path}")
    print(f"Encryption: {backup_config.encryption_enabled}")