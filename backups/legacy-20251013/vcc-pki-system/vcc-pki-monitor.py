#!/usr/bin/env python3
"""
VCC PKI System - Health Monitoring Scripts
Continuous monitoring and alerting for VCC PKI infrastructure
"""

import asyncio
import json
import logging
import smtplib
import sqlite3
import time
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from pathlib import Path
from typing import Dict, List, Optional, Any
import aiohttp
import argparse
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vcc-pki-monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VCCPKIMonitor:
    """VCC PKI System Health Monitor"""
    
    def __init__(self, config_path: str = "config/monitor.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.db_path = "data/vcc_pki.db"
        self.alerts_sent = set()  # Track sent alerts to avoid spam
        
    def load_config(self) -> Dict[str, Any]:
        """Load monitoring configuration"""
        default_config = {
            "monitoring": {
                "check_interval": 300,  # 5 minutes
                "certificate_warning_days": 30,
                "certificate_critical_days": 7,
                "database_size_warning_mb": 500,
                "database_size_critical_mb": 1000,
                "disk_space_warning_gb": 5,
                "disk_space_critical_gb": 1
            },
            "alerts": {
                "enabled": True,
                "email": {
                    "smtp_server": "smtp.brandenburg.de",
                    "smtp_port": 587,
                    "username": "vcc-pki-alerts@brandenburg.de",
                    "password": "secure_password",
                    "recipients": [
                        "admin@brandenburg.de",
                        "it-security@brandenburg.de"
                    ]
                },
                "webhook": {
                    "enabled": False,
                    "url": "https://monitoring.brandenburg.de/webhook/vcc-pki",
                    "token": "webhook_token_here"
                }
            },
            "vcc_services": {
                "timeout": 30,
                "retry_count": 3,
                "check_interval": 600  # 10 minutes
            }
        }
        
        try:
            if Path(self.config_path).exists():
                with open(self.config_path) as f:
                    user_config = json.load(f)
                
                # Merge with defaults
                self.merge_config(default_config, user_config)
                return default_config
            else:
                # Create default config file
                Path(self.config_path).parent.mkdir(exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                
                logger.info(f"Created default config file: {self.config_path}")
                return default_config
                
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return default_config
    
    def merge_config(self, base: Dict, override: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self.merge_config(base[key], value)
            else:
                base[key] = value
    
    async def run_continuous_monitoring(self):
        """Run continuous monitoring loop"""
        logger.info("Starting VCC PKI continuous monitoring...")
        
        check_interval = self.config["monitoring"]["check_interval"]
        vcc_check_interval = self.config["vcc_services"]["check_interval"]
        
        last_vcc_check = 0
        
        try:
            while True:
                start_time = time.time()
                
                # Perform health checks
                try:
                    health_results = await self.perform_health_checks()
                    
                    # Process alerts
                    if self.config["alerts"]["enabled"]:
                        await self.process_alerts(health_results)
                    
                    # Check VCC services periodically
                    if start_time - last_vcc_check >= vcc_check_interval:
                        vcc_results = await self.check_vcc_services()
                        
                        if self.config["alerts"]["enabled"]:
                            await self.process_vcc_alerts(vcc_results)
                        
                        last_vcc_check = start_time
                    
                    logger.info(f"Health check completed in {time.time() - start_time:.2f}s")
                    
                except Exception as e:
                    logger.error(f"Health check failed: {e}")
                    
                    # Send critical alert about monitoring failure
                    if self.config["alerts"]["enabled"]:
                        await self.send_alert("monitoring_failure", "critical", {
                            "error": str(e),
                            "timestamp": datetime.now().isoformat()
                        })
                
                # Wait for next check
                sleep_time = max(0, check_interval - (time.time() - start_time))
                await asyncio.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Monitoring loop failed: {e}")
            raise
    
    async def perform_health_checks(self) -> Dict[str, Any]:
        """Perform comprehensive health checks"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        # Database health check
        try:
            db_health = await self.check_database_health()
            results["checks"]["database"] = db_health
        except Exception as e:
            results["checks"]["database"] = {
                "status": "error",
                "error": str(e)
            }
        
        # Certificate expiry check
        try:
            cert_health = await self.check_certificate_health()
            results["checks"]["certificates"] = cert_health
        except Exception as e:
            results["checks"]["certificates"] = {
                "status": "error", 
                "error": str(e)
            }
        
        # Filesystem health check
        try:
            fs_health = await self.check_filesystem_health()
            results["checks"]["filesystem"] = fs_health
        except Exception as e:
            results["checks"]["filesystem"] = {
                "status": "error",
                "error": str(e)
            }
        
        # System resources check
        try:
            resource_health = await self.check_system_resources()
            results["checks"]["resources"] = resource_health
        except Exception as e:
            results["checks"]["resources"] = {
                "status": "error",
                "error": str(e)
            }
        
        return results
    
    async def check_database_health(self) -> Dict[str, Any]:
        """Check database health and performance"""
        try:
            db_health = {
                "status": "healthy",
                "issues": []
            }
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check integrity
                cursor.execute("PRAGMA integrity_check(1)")
                integrity = cursor.fetchone()[0]
                
                if integrity != "ok":
                    db_health["status"] = "critical"
                    db_health["issues"].append(f"Database integrity check failed: {integrity}")
                
                # Check database size
                db_size_bytes = Path(self.db_path).stat().st_size
                db_size_mb = db_size_bytes / (1024 * 1024)
                
                warning_size = self.config["monitoring"]["database_size_warning_mb"]
                critical_size = self.config["monitoring"]["database_size_critical_mb"]
                
                if db_size_mb >= critical_size:
                    db_health["status"] = "critical"
                    db_health["issues"].append(f"Database size critical: {db_size_mb:.1f}MB")
                elif db_size_mb >= warning_size:
                    if db_health["status"] == "healthy":
                        db_health["status"] = "warning"
                    db_health["issues"].append(f"Database size warning: {db_size_mb:.1f}MB")
                
                # Check connection performance
                start_time = time.time()
                cursor.execute("SELECT COUNT(*) FROM certificates")
                cert_count = cursor.fetchone()[0]
                query_time = time.time() - start_time
                
                db_health["metrics"] = {
                    "size_mb": db_size_mb,
                    "certificate_count": cert_count,
                    "query_response_ms": query_time * 1000
                }
                
                # Slow query warning
                if query_time > 1.0:  # 1 second threshold
                    if db_health["status"] == "healthy":
                        db_health["status"] = "warning"
                    db_health["issues"].append(f"Slow database queries: {query_time:.2f}s")
            
            return db_health
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def check_certificate_health(self) -> Dict[str, Any]:
        """Check certificate expiry and health"""
        try:
            cert_health = {
                "status": "healthy",
                "issues": []
            }
            
            warning_days = self.config["monitoring"]["certificate_warning_days"]
            critical_days = self.config["monitoring"]["certificate_critical_days"]
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check critical expiring certificates
                critical_cutoff = datetime.now() + timedelta(days=critical_days)
                cursor.execute("""
                    SELECT COUNT(*) FROM certificates 
                    WHERE expires_at <= ? AND status = 'valid'
                """, (critical_cutoff,))
                
                critical_count = cursor.fetchone()[0]
                
                if critical_count > 0:
                    cert_health["status"] = "critical"
                    cert_health["issues"].append(f"{critical_count} certificates expiring within {critical_days} days")
                
                # Check warning expiring certificates
                warning_cutoff = datetime.now() + timedelta(days=warning_days)
                cursor.execute("""
                    SELECT COUNT(*) FROM certificates 
                    WHERE expires_at <= ? AND status = 'valid'
                """, (warning_cutoff,))
                
                warning_count = cursor.fetchone()[0]
                
                if warning_count > critical_count:
                    if cert_health["status"] == "healthy":
                        cert_health["status"] = "warning"
                    total_warning = warning_count - critical_count
                    cert_health["issues"].append(f"{total_warning} certificates expiring within {warning_days} days")
                
                # Get certificate status counts
                cursor.execute("""
                    SELECT status, COUNT(*) 
                    FROM certificates 
                    GROUP BY status
                """)
                
                status_counts = dict(cursor.fetchall())
                
                cert_health["metrics"] = {
                    "critical_expiring": critical_count,
                    "warning_expiring": warning_count - critical_count,
                    "status_counts": status_counts
                }
            
            return cert_health
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def check_filesystem_health(self) -> Dict[str, Any]:
        """Check filesystem health and disk space"""
        try:
            fs_health = {
                "status": "healthy",
                "issues": []
            }
            
            import shutil
            
            # Check disk space
            total, used, free = shutil.disk_usage('.')
            free_gb = free / (1024**3)
            
            warning_gb = self.config["monitoring"]["disk_space_warning_gb"]
            critical_gb = self.config["monitoring"]["disk_space_critical_gb"]
            
            if free_gb <= critical_gb:
                fs_health["status"] = "critical"
                fs_health["issues"].append(f"Critical disk space: {free_gb:.1f}GB remaining")
            elif free_gb <= warning_gb:
                fs_health["status"] = "warning"
                fs_health["issues"].append(f"Low disk space: {free_gb:.1f}GB remaining")
            
            fs_health["metrics"] = {
                "total_gb": total / (1024**3),
                "used_gb": used / (1024**3),
                "free_gb": free_gb,
                "usage_percent": (used / total) * 100
            }
            
            # Check critical directories
            critical_dirs = ["data", "certificates", "private", "backups"]
            
            for dir_name in critical_dirs:
                dir_path = Path(dir_name)
                
                if not dir_path.exists():
                    fs_health["status"] = "critical"
                    fs_health["issues"].append(f"Missing critical directory: {dir_name}")
                elif not dir_path.is_dir():
                    fs_health["status"] = "critical"
                    fs_health["issues"].append(f"Critical path is not a directory: {dir_name}")
            
            return fs_health
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def check_system_resources(self) -> Dict[str, Any]:
        """Check system resources like CPU and memory"""
        try:
            import psutil
            
            resource_health = {
                "status": "healthy", 
                "issues": []
            }
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                resource_health["status"] = "critical"
                resource_health["issues"].append(f"High CPU usage: {cpu_percent}%")
            elif cpu_percent > 70:
                if resource_health["status"] == "healthy":
                    resource_health["status"] = "warning"
                resource_health["issues"].append(f"Elevated CPU usage: {cpu_percent}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                resource_health["status"] = "critical"
                resource_health["issues"].append(f"High memory usage: {memory.percent}%")
            elif memory.percent > 80:
                if resource_health["status"] == "healthy":
                    resource_health["status"] = "warning"  
                resource_health["issues"].append(f"Elevated memory usage: {memory.percent}%")
            
            resource_health["metrics"] = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3)
            }
            
            return resource_health
            
        except ImportError:
            # psutil not available, return basic check
            return {
                "status": "unknown",
                "error": "psutil not available for resource monitoring"
            }
        except Exception as e:
            return {
                "status": "error", 
                "error": str(e)
            }
    
    async def check_vcc_services(self) -> Dict[str, Any]:
        """Check VCC services connectivity and health"""
        try:
            vcc_results = {
                "timestamp": datetime.now().isoformat(),
                "services": {},
                "summary": {
                    "total": 0,
                    "online": 0,
                    "offline": 0,
                    "error": 0
                }
            }
            
            # Get services from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT name, url FROM vcc_services
                """)
                
                services = cursor.fetchall()
            
            timeout = self.config["vcc_services"]["timeout"]
            retry_count = self.config["vcc_services"]["retry_count"]
            
            # Check each service
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                for name, url in services:
                    vcc_results["summary"]["total"] += 1
                    service_result = await self.check_single_vcc_service(session, name, url, retry_count)
                    vcc_results["services"][name] = service_result
                    
                    # Update summary
                    status = service_result["status"]
                    if status == "online":
                        vcc_results["summary"]["online"] += 1
                    elif status == "offline":
                        vcc_results["summary"]["offline"] += 1
                    else:
                        vcc_results["summary"]["error"] += 1
            
            # Update database with results
            await self.update_vcc_service_status(vcc_results)
            
            return vcc_results
            
        except Exception as e:
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    async def check_single_vcc_service(self, session: aiohttp.ClientSession, 
                                     name: str, url: str, retry_count: int) -> Dict[str, Any]:
        """Check a single VCC service with retries"""
        service_result = {
            "name": name,
            "url": url,
            "status": "offline",
            "response_time_ms": None,
            "error": None,
            "last_check": datetime.now().isoformat()
        }
        
        for attempt in range(retry_count):
            try:
                start_time = time.time()
                
                async with session.get(url) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    if response.status == 200:
                        service_result["status"] = "online"
                        service_result["response_time_ms"] = response_time
                        break
                    else:
                        service_result["error"] = f"HTTP {response.status}"
                        
            except aiohttp.ClientError as e:
                service_result["error"] = str(e)
            except Exception as e:
                service_result["error"] = f"Unexpected error: {e}"
            
            # Wait before retry
            if attempt < retry_count - 1:
                await asyncio.sleep(1)
        
        return service_result
    
    async def update_vcc_service_status(self, vcc_results: Dict[str, Any]):
        """Update VCC service status in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for name, result in vcc_results["services"].items():
                    cursor.execute("""
                        UPDATE vcc_services 
                        SET status = ?, last_check = CURRENT_TIMESTAMP
                        WHERE name = ?
                    """, (result["status"], name))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to update VCC service status: {e}")
    
    async def process_alerts(self, health_results: Dict[str, Any]):
        """Process health check results and send alerts"""
        try:
            for check_name, check_result in health_results["checks"].items():
                status = check_result.get("status")
                issues = check_result.get("issues", [])
                
                if status in ["critical", "error"] and issues:
                    alert_key = f"health_{check_name}_{status}"
                    
                    # Avoid duplicate alerts
                    if alert_key not in self.alerts_sent:
                        await self.send_alert(f"{check_name}_health", status, {
                            "check": check_name,
                            "issues": issues,
                            "metrics": check_result.get("metrics", {}),
                            "timestamp": health_results["timestamp"]
                        })
                        
                        self.alerts_sent.add(alert_key)
                
                elif status == "healthy" and f"health_{check_name}_critical" in self.alerts_sent:
                    # Send recovery alert
                    await self.send_alert(f"{check_name}_recovery", "info", {
                        "check": check_name,
                        "message": f"{check_name.title()} health check recovered",
                        "timestamp": health_results["timestamp"]
                    })
                    
                    # Remove from sent alerts
                    self.alerts_sent.discard(f"health_{check_name}_critical")
                    self.alerts_sent.discard(f"health_{check_name}_error")
                    
        except Exception as e:
            logger.error(f"Alert processing failed: {e}")
    
    async def process_vcc_alerts(self, vcc_results: Dict[str, Any]):
        """Process VCC service check results and send alerts"""
        try:
            summary = vcc_results["summary"]
            
            # Alert if majority of services are offline
            if summary["offline"] > summary["online"]:
                alert_key = "vcc_services_majority_offline"
                
                if alert_key not in self.alerts_sent:
                    await self.send_alert("vcc_services_critical", "critical", {
                        "message": "Majority of VCC services are offline",
                        "summary": summary,
                        "timestamp": vcc_results["timestamp"]
                    })
                    
                    self.alerts_sent.add(alert_key)
            
            # Individual service alerts
            for service_name, service_result in vcc_results["services"].items():
                if service_result["status"] == "offline":
                    alert_key = f"vcc_service_{service_name}_offline"
                    
                    if alert_key not in self.alerts_sent:
                        await self.send_alert("vcc_service_offline", "warning", {
                            "service": service_name,
                            "url": service_result["url"], 
                            "error": service_result.get("error"),
                            "timestamp": vcc_results["timestamp"]
                        })
                        
                        self.alerts_sent.add(alert_key)
                
                elif service_result["status"] == "online":
                    # Recovery alert
                    recovery_key = f"vcc_service_{service_name}_offline"
                    if recovery_key in self.alerts_sent:
                        await self.send_alert("vcc_service_recovery", "info", {
                            "service": service_name,
                            "message": f"VCC service {service_name} recovered",
                            "response_time_ms": service_result.get("response_time_ms"),
                            "timestamp": vcc_results["timestamp"]
                        })
                        
                        self.alerts_sent.discard(recovery_key)
                        
        except Exception as e:
            logger.error(f"VCC alert processing failed: {e}")
    
    async def send_alert(self, alert_type: str, severity: str, details: Dict[str, Any]):
        """Send alert via configured channels"""
        try:
            alert_data = {
                "type": alert_type,
                "severity": severity,
                "details": details,
                "timestamp": datetime.now().isoformat(),
                "system": "VCC PKI"
            }
            
            # Send email alert
            if self.config["alerts"]["email"]:
                await self.send_email_alert(alert_data)
            
            # Send webhook alert
            if self.config["alerts"].get("webhook", {}).get("enabled", False):
                await self.send_webhook_alert(alert_data)
            
            logger.info(f"Alert sent: {alert_type} ({severity})")
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    async def send_email_alert(self, alert_data: Dict[str, Any]):
        """Send email alert"""
        try:
            email_config = self.config["alerts"]["email"]
            
            # Create message
            msg = MimeMultipart()
            msg['From'] = email_config["username"]
            msg['To'] = ", ".join(email_config["recipients"])
            msg['Subject'] = f"VCC PKI Alert: {alert_data['type']} ({alert_data['severity'].upper()})"
            
            # Format alert body
            body = f"""
VCC PKI System Alert

Type: {alert_data['type']}
Severity: {alert_data['severity'].upper()}
Timestamp: {alert_data['timestamp']}

Details:
{json.dumps(alert_data['details'], indent=2)}

System: {alert_data['system']}

--
VCC PKI Monitoring System
Land Brandenburg
"""
            
            msg.attach(MimeText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
                server.starttls()
                server.login(email_config["username"], email_config["password"])
                server.send_message(msg)
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    async def send_webhook_alert(self, alert_data: Dict[str, Any]):
        """Send webhook alert"""
        try:
            webhook_config = self.config["alerts"]["webhook"]
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {webhook_config["token"]}'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_config["url"],
                    json=alert_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        logger.error(f"Webhook alert failed: HTTP {response.status}")
                        
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")

async def main():
    """Main CLI interface for monitoring"""
    parser = argparse.ArgumentParser(
        description="VCC PKI System Health Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', default='config/monitor.json', 
                       help='Monitor configuration file')
    parser.add_argument('--continuous', action='store_true',
                       help='Run continuous monitoring')
    parser.add_argument('--health-check', action='store_true', 
                       help='Run single health check')
    parser.add_argument('--vcc-check', action='store_true',
                       help='Check VCC services')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    try:
        monitor = VCCPKIMonitor(args.config)
        
        if args.continuous:
            logger.info("Starting continuous monitoring...")
            await monitor.run_continuous_monitoring()
            
        elif args.health_check:
            logger.info("Running health check...")
            results = await monitor.perform_health_checks()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"Results saved to: {args.output}")
            else:
                print(json.dumps(results, indent=2, default=str))
                
        elif args.vcc_check:
            logger.info("Checking VCC services...")
            results = await monitor.check_vcc_services()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"Results saved to: {args.output}")
            else:
                print(json.dumps(results, indent=2, default=str))
        
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        logger.error(f"Monitoring failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())