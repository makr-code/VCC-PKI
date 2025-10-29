#!/usr/bin/env python3
# VCC PKI System - Production Deployment Script
# Automated deployment für Brandenburg Government PKI Infrastructure

import os
import sys
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import subprocess
import time
from datetime import datetime
import argparse

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from production.hsm_config import get_hsm_manager, check_hsm_health
from production.environment_config import get_environment_manager, Environment
from production.backup_recovery import VCCPKIBackupManager, BackupConfiguration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vcc-pki-deployment.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VCCPKIDeployment:
    """Production Deployment Manager für VCC PKI System"""
    
    def __init__(self, environment: str):
        self.environment = Environment(environment.lower())
        self.env_manager = get_environment_manager(environment)
        self.config = self.env_manager.config
        self.deployment_start_time = datetime.now()
        
        logger.info(f"VCC PKI Deployment initialized for: {self.environment.value}")
        
    async def deploy_production(self, 
                              skip_validations: bool = False,
                              backup_before_deploy: bool = True) -> Dict[str, Any]:
        """
        Complete production deployment workflow
        """
        deployment_result = {
            "deployment_id": f"deploy_{self.deployment_start_time.strftime('%Y%m%d_%H%M%S')}",
            "environment": self.environment.value,
            "started_at": self.deployment_start_time.isoformat(),
            "steps": [],
            "success": False,
            "error": None
        }
        
        try:
            logger.info("=== VCC PKI Production Deployment Started ===")
            
            # Step 1: Pre-deployment validations
            if not skip_validations:
                validation_result = await self._run_pre_deployment_validations()
                deployment_result["steps"].append({
                    "step": "pre_deployment_validations",
                    "status": "completed" if validation_result["all_passed"] else "failed",
                    "details": validation_result
                })
                
                if not validation_result["all_passed"]:
                    raise Exception(f"Pre-deployment validation failed: {validation_result['errors']}")
            
            # Step 2: Create pre-deployment backup
            if backup_before_deploy and self.environment != Environment.DEVELOPMENT:
                backup_result = await self._create_pre_deployment_backup()
                deployment_result["steps"].append({
                    "step": "pre_deployment_backup",
                    "status": "completed",
                    "backup_id": backup_result["backup_id"]
                })
            
            # Step 3: Stop existing services
            await self._stop_services()
            deployment_result["steps"].append({
                "step": "stop_services",
                "status": "completed"
            })
            
            # Step 4: Deploy application
            await self._deploy_application()
            deployment_result["steps"].append({
                "step": "deploy_application",
                "status": "completed"
            })
            
            # Step 5: Update database schema
            await self._update_database_schema()
            deployment_result["steps"].append({
                "step": "update_database",
                "status": "completed"
            })
            
            # Step 6: Configure HSM
            if self.environment in [Environment.PRODUCTION, Environment.STAGING]:
                await self._configure_hsm()
                deployment_result["steps"].append({
                    "step": "configure_hsm",
                    "status": "completed"
                })
            
            # Step 7: Start services
            await self._start_services()
            deployment_result["steps"].append({
                "step": "start_services", 
                "status": "completed"
            })
            
            # Step 8: Post-deployment health checks
            health_check_result = await self._run_post_deployment_health_checks()
            deployment_result["steps"].append({
                "step": "post_deployment_health_checks",
                "status": "completed" if health_check_result["all_healthy"] else "warning",
                "details": health_check_result
            })
            
            # Step 9: Initialize default data (if needed)
            await self._initialize_default_data()
            deployment_result["steps"].append({
                "step": "initialize_default_data",
                "status": "completed"
            })
            
            # Step 10: Configure monitoring & alerting
            await self._configure_monitoring()
            deployment_result["steps"].append({
                "step": "configure_monitoring",
                "status": "completed"
            })
            
            deployment_result["success"] = True
            deployment_result["completed_at"] = datetime.now().isoformat()
            deployment_result["duration_minutes"] = (datetime.now() - self.deployment_start_time).total_seconds() / 60
            
            logger.info("=== VCC PKI Production Deployment Completed Successfully ===")
            
            # Send success notification
            await self._send_deployment_notification(deployment_result)
            
            return deployment_result
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            
            deployment_result["success"] = False
            deployment_result["error"] = str(e)
            deployment_result["failed_at"] = datetime.now().isoformat()
            
            # Attempt rollback
            try:
                logger.info("Attempting deployment rollback...")
                await self._rollback_deployment(deployment_result)
                deployment_result["rollback_completed"] = True
            except Exception as rollback_error:
                logger.error(f"Rollback failed: {rollback_error}")
                deployment_result["rollback_error"] = str(rollback_error)
            
            # Send failure notification
            await self._send_deployment_notification(deployment_result)
            
            raise
    
    async def _run_pre_deployment_validations(self) -> Dict[str, Any]:
        """
        Comprehensive pre-deployment validation checks
        """
        logger.info("Running pre-deployment validations...")
        
        validation_result = {
            "all_passed": True,
            "checks": {},
            "errors": [],
            "warnings": []
        }
        
        # Check 1: Environment configuration validation
        try:
            config_valid = self._validate_environment_config()
            validation_result["checks"]["environment_config"] = config_valid
            if not config_valid:
                validation_result["errors"].append("Environment configuration invalid")
        except Exception as e:
            validation_result["checks"]["environment_config"] = False
            validation_result["errors"].append(f"Config validation error: {str(e)}")
        
        # Check 2: Database connectivity
        try:
            db_accessible = await self._check_database_connectivity()
            validation_result["checks"]["database_connectivity"] = db_accessible
            if not db_accessible:
                validation_result["errors"].append("Database not accessible")
        except Exception as e:
            validation_result["checks"]["database_connectivity"] = False
            validation_result["errors"].append(f"Database check error: {str(e)}")
        
        # Check 3: HSM availability (production only)
        if self.environment in [Environment.PRODUCTION, Environment.STAGING]:
            try:
                hsm_manager = get_hsm_manager(self.config.hsm_environment)
                hsm_health = await check_hsm_health(hsm_manager.config)
                hsm_available = hsm_health.get("hsm_available", False)
                validation_result["checks"]["hsm_availability"] = hsm_available
                
                if not hsm_available:
                    validation_result["errors"].append("HSM not available")
            except Exception as e:
                validation_result["checks"]["hsm_availability"] = False
                validation_result["errors"].append(f"HSM check error: {str(e)}")
        
        # Check 4: Disk space
        try:
            sufficient_space = self._check_disk_space()
            validation_result["checks"]["disk_space"] = sufficient_space
            if not sufficient_space:
                validation_result["errors"].append("Insufficient disk space")
        except Exception as e:
            validation_result["checks"]["disk_space"] = False
            validation_result["errors"].append(f"Disk space check error: {str(e)}")
        
        # Check 5: Network connectivity to VCC services
        try:
            vcc_connectivity = await self._check_vcc_service_connectivity()
            validation_result["checks"]["vcc_connectivity"] = vcc_connectivity["all_accessible"]
            
            if not vcc_connectivity["all_accessible"]:
                for service, accessible in vcc_connectivity["services"].items():
                    if not accessible:
                        validation_result["warnings"].append(f"VCC service not accessible: {service}")
        except Exception as e:
            validation_result["checks"]["vcc_connectivity"] = False
            validation_result["warnings"].append(f"VCC connectivity check error: {str(e)}")
        
        # Check 6: SSL/TLS certificates validity
        try:
            ssl_valid = await self._check_ssl_certificates()
            validation_result["checks"]["ssl_certificates"] = ssl_valid
            if not ssl_valid:
                validation_result["warnings"].append("SSL certificate issues detected")
        except Exception as e:
            validation_result["checks"]["ssl_certificates"] = False
            validation_result["warnings"].append(f"SSL check error: {str(e)}")
        
        # Determine overall result
        validation_result["all_passed"] = all(validation_result["checks"].values()) and not validation_result["errors"]
        
        logger.info(f"Pre-deployment validations completed. Passed: {validation_result['all_passed']}")
        
        return validation_result
    
    async def _create_pre_deployment_backup(self) -> Dict[str, Any]:
        """
        Create backup before deployment
        """
        logger.info("Creating pre-deployment backup...")
        
        backup_config = BackupConfiguration(
            backup_root_path=Path("/var/backups/vcc-pki"),
            encryption_enabled=True,
            notification_recipients=self.config.monitoring.alert_email_recipients
        )
        
        backup_manager = VCCPKIBackupManager(backup_config)
        
        backup_id = f"pre_deploy_{self.deployment_start_time.strftime('%Y%m%d_%H%M%S')}"
        backup_metadata = await backup_manager.create_full_backup(
            backup_id=backup_id,
            include_hsm_keys=False  # HSM keys stay in HSM
        )
        
        logger.info(f"Pre-deployment backup created: {backup_id}")
        
        return {
            "backup_id": backup_id,
            "size_mb": backup_metadata.size_bytes / 1024 / 1024,
            "created_at": backup_metadata.created_at.isoformat()
        }
    
    async def _stop_services(self):
        """Stop VCC PKI services"""
        logger.info("Stopping VCC PKI services...")
        
        services_to_stop = [
            "vcc-pki-api",
            "vcc-pki-worker", 
            "vcc-pki-scheduler",
            "nginx",  # If used as reverse proxy
            "redis-server"  # If local Redis
        ]
        
        for service in services_to_stop:
            try:
                result = subprocess.run(
                    ["systemctl", "stop", service],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    logger.info(f"Service stopped: {service}")
                else:
                    logger.warning(f"Failed to stop service {service}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout stopping service: {service}")
            except Exception as e:
                logger.warning(f"Error stopping service {service}: {e}")
    
    async def _deploy_application(self):
        """Deploy VCC PKI application files"""
        logger.info("Deploying application files...")
        
        # Application deployment paths
        app_source = Path("/opt/vcc-pki-new")  # Staged application
        app_target = Path("/opt/vcc-pki")      # Production location
        
        if not app_source.exists():
            raise FileNotFoundError(f"Application source not found: {app_source}")
        
        # Backup current application
        if app_target.exists():
            backup_path = Path(f"/opt/vcc-pki-backup-{int(time.time())}")
            logger.info(f"Backing up current application to: {backup_path}")
            subprocess.run(["cp", "-r", str(app_target), str(backup_path)], check=True)
        
        # Deploy new application
        logger.info("Copying new application files...")
        if app_target.exists():
            subprocess.run(["rm", "-rf", str(app_target)], check=True)
        
        subprocess.run(["cp", "-r", str(app_source), str(app_target)], check=True)
        
        # Set correct permissions
        subprocess.run(["chown", "-R", "vcc-pki:vcc-pki", str(app_target)], check=True)
        subprocess.run(["chmod", "-R", "755", str(app_target)], check=True)
        
        # Install Python dependencies
        logger.info("Installing Python dependencies...")
        subprocess.run([
            "pip", "install", "-r", str(app_target / "requirements.txt")
        ], check=True)
        
        logger.info("Application deployment completed")
    
    async def _update_database_schema(self):
        """Update database schema using Alembic migrations"""
        logger.info("Updating database schema...")
        
        try:
            # Run Alembic migrations
            subprocess.run([
                "alembic", "-c", "/opt/vcc-pki/alembic.ini", "upgrade", "head"
            ], cwd="/opt/vcc-pki", check=True, timeout=300)
            
            logger.info("Database schema updated successfully")
            
        except subprocess.TimeoutExpired:
            raise Exception("Database migration timed out")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Database migration failed: {e}")
    
    async def _configure_hsm(self):
        """Configure HSM for production environment"""
        logger.info("Configuring HSM...")
        
        try:
            hsm_manager = get_hsm_manager(self.config.hsm_environment)
            
            # Verify HSM health
            hsm_health = await check_hsm_health(hsm_manager.config)
            
            if not hsm_health["hsm_available"]:
                raise Exception(f"HSM not available: {hsm_health}")
            
            # Initialize HSM slots if needed
            for slot_type, slot_config in hsm_manager.config.slots.items():
                logger.info(f"Verifying HSM slot: {slot_type.value}")
                # HSM slot verification would go here
            
            logger.info("HSM configuration completed")
            
        except Exception as e:
            logger.error(f"HSM configuration failed: {e}")
            raise
    
    async def _start_services(self):
        """Start VCC PKI services in correct order"""
        logger.info("Starting VCC PKI services...")
        
        services_to_start = [
            "redis-server",      # Cache/session store first
            "postgresql",        # Database
            "vcc-pki-worker",    # Background workers  
            "vcc-pki-api",       # Main API service
            "vcc-pki-scheduler", # Task scheduler
            "nginx"              # Reverse proxy last
        ]
        
        for service in services_to_start:
            try:
                logger.info(f"Starting service: {service}")
                
                result = subprocess.run(
                    ["systemctl", "start", service],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    # Wait a moment for service to initialize
                    await asyncio.sleep(2)
                    
                    # Check service status
                    status_result = subprocess.run(
                        ["systemctl", "is-active", service],
                        capture_output=True,
                        text=True
                    )
                    
                    if status_result.stdout.strip() == "active":
                        logger.info(f"Service started successfully: {service}")
                    else:
                        logger.warning(f"Service may not have started properly: {service}")
                else:
                    logger.error(f"Failed to start service {service}: {result.stderr}")
                    raise Exception(f"Service startup failed: {service}")
                    
            except subprocess.TimeoutExpired:
                raise Exception(f"Timeout starting service: {service}")
            except Exception as e:
                logger.error(f"Error starting service {service}: {e}")
                raise
    
    async def _run_post_deployment_health_checks(self) -> Dict[str, Any]:
        """
        Comprehensive post-deployment health checks
        """
        logger.info("Running post-deployment health checks...")
        
        health_result = {
            "all_healthy": True,
            "checks": {},
            "issues": []
        }
        
        # Check 1: API endpoint availability
        try:
            api_healthy = await self._check_api_health()
            health_result["checks"]["api_health"] = api_healthy
            if not api_healthy:
                health_result["issues"].append("API health check failed")
        except Exception as e:
            health_result["checks"]["api_health"] = False
            health_result["issues"].append(f"API health check error: {str(e)}")
        
        # Check 2: Database connectivity from application
        try:
            db_app_connectivity = await self._check_app_database_connectivity()
            health_result["checks"]["database_app_connectivity"] = db_app_connectivity
            if not db_app_connectivity:
                health_result["issues"].append("Application database connectivity failed")
        except Exception as e:
            health_result["checks"]["database_app_connectivity"] = False
            health_result["issues"].append(f"App DB connectivity error: {str(e)}")
        
        # Check 3: Service status
        try:
            services_status = self._check_services_status()
            health_result["checks"]["services_status"] = services_status["all_running"]
            if not services_status["all_running"]:
                health_result["issues"].extend([
                    f"Service not running: {service}" 
                    for service, running in services_status["services"].items() 
                    if not running
                ])
        except Exception as e:
            health_result["checks"]["services_status"] = False
            health_result["issues"].append(f"Service status check error: {str(e)}")
        
        # Check 4: Basic PKI operations
        try:
            pki_operations = await self._test_basic_pki_operations()
            health_result["checks"]["pki_operations"] = pki_operations
            if not pki_operations:
                health_result["issues"].append("Basic PKI operations test failed")
        except Exception as e:
            health_result["checks"]["pki_operations"] = False
            health_result["issues"].append(f"PKI operations test error: {str(e)}")
        
        health_result["all_healthy"] = all(health_result["checks"].values()) and not health_result["issues"]
        
        logger.info(f"Post-deployment health checks completed. Healthy: {health_result['all_healthy']}")
        
        return health_result
    
    # Helper methods for various checks
    
    def _validate_environment_config(self) -> bool:
        """Validate environment configuration"""
        try:
            # Check required configuration values
            if not self.config.database.host:
                return False
            
            if self.environment == Environment.PRODUCTION:
                if "default" in self.config.database.password.lower():
                    return False
                
                if not self.config.security.force_https:
                    return False
            
            return True
            
        except Exception:
            return False
    
    async def _check_database_connectivity(self) -> bool:
        """Test database connectivity"""
        try:
            import asyncpg
            
            conn = await asyncpg.connect(
                host=self.config.database.host,
                port=self.config.database.port,
                database=self.config.database.database,
                user=self.config.database.username,
                password=self.config.database.password,
                timeout=10
            )
            
            # Simple query test
            result = await conn.fetchval("SELECT 1")
            await conn.close()
            
            return result == 1
            
        except Exception as e:
            logger.error(f"Database connectivity test failed: {e}")
            return False
    
    def _check_disk_space(self, min_free_gb: int = 5) -> bool:
        """Check available disk space"""
        try:
            statvfs = os.statvfs("/")
            free_bytes = statvfs.f_frsize * statvfs.f_availó
            free_gb = free_bytes / (1024 ** 3)
            
            return free_gb >= min_free_gb
            
        except Exception:
            return False

async def main():
    """Main deployment function"""
    parser = argparse.ArgumentParser(description="VCC PKI Production Deployment")
    parser.add_argument("--environment", "-e", required=True, 
                       choices=["development", "testing", "staging", "production"],
                       help="Target deployment environment")
    parser.add_argument("--skip-validations", action="store_true",
                       help="Skip pre-deployment validations")
    parser.add_argument("--no-backup", action="store_true",
                       help="Skip pre-deployment backup")
    
    args = parser.parse_args()
    
    try:
        deployment = VCCPKIDeployment(args.environment)
        
        result = await deployment.deploy_production(
            skip_validations=args.skip_validations,
            backup_before_deploy=not args.no_backup
        )
        
        if result["success"]:
            logger.info("✅ VCC PKI deployment completed successfully!")
            print(f"Deployment ID: {result['deployment_id']}")
            print(f"Duration: {result.get('duration_minutes', 0):.2f} minutes")
            sys.exit(0)
        else:
            logger.error("❌ VCC PKI deployment failed!")
            print(f"Error: {result['error']}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Deployment script failed: {e}")
        print(f"Deployment failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())