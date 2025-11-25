#!/usr/bin/env python3
"""
VCC PKI Server - Auto-Renewal Engine
=====================================

Server-side automatic certificate renewal engine implementing Phase 1
of the VCC-PKI development strategy.

Features:
- Background worker for automatic certificate renewal
- Configurable renewal thresholds (30/14/7 days)
- Retry mechanism with exponential backoff
- Webhook/Email notification support
- Comprehensive audit logging

This component runs ON-PREMISE and requires no external vendor dependencies.

Author: VCC PKI Team
Date: November 2025
Version: 1.0.0
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
import threading
import time
import traceback

from sqlalchemy.orm import Session

from database import (
    get_db, 
    init_database,
    Certificate, 
    Service, 
    RotationSchedule, 
    AuditLog
)

# Configure logging
logger = logging.getLogger(__name__)


class RenewalStatus(str, Enum):
    """Certificate renewal status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class NotificationLevel(str, Enum):
    """Notification urgency level"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class RenewalConfig:
    """Configuration for the auto-renewal engine"""
    # Renewal thresholds (days before expiry)
    renewal_threshold_days: int = 30
    warning_threshold_days: int = 14
    critical_threshold_days: int = 7
    
    # Check interval (seconds)
    check_interval_seconds: int = 3600  # 1 hour
    
    # Retry configuration
    max_retry_attempts: int = 3
    retry_delay_seconds: int = 300  # 5 minutes
    retry_backoff_multiplier: float = 2.0
    
    # Notification settings
    enable_notifications: bool = True
    notification_webhook_url: Optional[str] = None
    notification_email_recipients: List[str] = field(default_factory=list)
    
    # Performance settings
    batch_size: int = 10
    concurrent_renewals: int = 3


@dataclass
class RenewalResult:
    """Result of a certificate renewal operation"""
    certificate_id: str
    service_id: str
    success: bool
    old_serial: Optional[str] = None
    new_serial: Optional[str] = None
    error_message: Optional[str] = None
    renewed_at: Optional[datetime] = None


class NotificationManager:
    """Manages notifications for certificate renewal events"""
    
    def __init__(self, config: RenewalConfig):
        self.config = config
        self._notification_handlers: List[Callable] = []
    
    def register_handler(self, handler: Callable):
        """Register a notification handler"""
        self._notification_handlers.append(handler)
    
    async def send_notification(
        self,
        level: NotificationLevel,
        title: str,
        message: str,
        data: Optional[Dict[str, Any]] = None
    ):
        """Send notification through all registered channels"""
        if not self.config.enable_notifications:
            return
        
        notification = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.value,
            "title": title,
            "message": message,
            "data": data or {}
        }
        
        logger.info(f"📢 Notification [{level.value}]: {title}")
        
        # Call registered handlers
        for handler in self._notification_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(notification)
                else:
                    handler(notification)
            except Exception as e:
                logger.error(f"Notification handler failed: {e}")
        
        # Send webhook if configured
        if self.config.notification_webhook_url:
            await self._send_webhook(notification)
    
    async def _send_webhook(self, notification: Dict[str, Any]):
        """Send notification to webhook URL"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.notification_webhook_url,
                    json=notification,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Webhook returned status {response.status}")
        except ImportError:
            logger.debug("aiohttp not available for webhook notifications")
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")


class AutoRenewalEngine:
    """
    Server-side certificate auto-renewal engine.
    
    Implements:
    - Automatic certificate renewal before expiry
    - Configurable thresholds (30/14/7 days)
    - Retry mechanism with exponential backoff
    - Comprehensive audit logging
    - Notification system for administrators
    
    This component is designed for ON-PREMISE deployment with
    no external vendor dependencies.
    """
    
    def __init__(
        self,
        cert_manager,
        config: Optional[RenewalConfig] = None
    ):
        """
        Initialize the Auto-Renewal Engine.
        
        Args:
            cert_manager: ServiceCertificateManager instance
            config: Renewal configuration (uses defaults if not provided)
        """
        self.cert_manager = cert_manager
        self.config = config or RenewalConfig()
        self.notification_manager = NotificationManager(self.config)
        
        # Engine state
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Statistics
        self._stats = {
            "total_renewals": 0,
            "successful_renewals": 0,
            "failed_renewals": 0,
            "last_check": None,
            "last_renewal": None
        }
        
        logger.info("🔄 Auto-Renewal Engine initialized")
        logger.info(f"   Renewal threshold: {self.config.renewal_threshold_days} days")
        logger.info(f"   Check interval: {self.config.check_interval_seconds} seconds")
    
    # ========================================================================
    # Engine Lifecycle
    # ========================================================================
    
    def start(self):
        """Start the auto-renewal engine"""
        with self._lock:
            if self._running:
                logger.warning("Auto-Renewal Engine is already running")
                return
            
            self._running = True
            self._worker_thread = threading.Thread(
                target=self._run_worker,
                daemon=True,
                name="AutoRenewalWorker"
            )
            self._worker_thread.start()
            logger.info("🚀 Auto-Renewal Engine started")
    
    def stop(self):
        """Stop the auto-renewal engine"""
        with self._lock:
            if not self._running:
                return
            
            self._running = False
            logger.info("🛑 Auto-Renewal Engine stopping...")
        
        # Wait for worker thread to finish
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=30)
        
        logger.info("✅ Auto-Renewal Engine stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if the engine is running"""
        return self._running
    
    @property
    def statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return self._stats.copy()
    
    # ========================================================================
    # Background Worker
    # ========================================================================
    
    def _run_worker(self):
        """Background worker loop"""
        logger.info("🔄 Auto-Renewal Worker started")
        
        while self._running:
            try:
                # Create new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    loop.run_until_complete(self._check_and_renew_certificates())
                finally:
                    loop.close()
                
            except Exception as e:
                logger.error(f"Error in renewal check cycle: {e}")
                logger.debug(traceback.format_exc())
            
            # Wait for next check interval
            for _ in range(self.config.check_interval_seconds):
                if not self._running:
                    break
                time.sleep(1)
        
        logger.info("🔄 Auto-Renewal Worker stopped")
    
    async def _check_and_renew_certificates(self):
        """Check all certificates and renew those approaching expiry"""
        self._stats["last_check"] = datetime.now(timezone.utc)
        logger.info("🔍 Checking certificates for renewal...")
        
        # Get database session
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            # Find certificates needing renewal
            certificates_to_renew = self._get_certificates_needing_renewal(db)
            
            if not certificates_to_renew:
                logger.info("✅ No certificates need renewal")
                return
            
            logger.info(f"📋 Found {len(certificates_to_renew)} certificates needing renewal")
            
            # Process renewals
            results = await self._process_renewals(db, certificates_to_renew)
            
            # Log summary
            successful = sum(1 for r in results if r.success)
            failed = len(results) - successful
            
            self._stats["total_renewals"] += len(results)
            self._stats["successful_renewals"] += successful
            self._stats["failed_renewals"] += failed
            
            if successful > 0:
                self._stats["last_renewal"] = datetime.now(timezone.utc)
            
            logger.info(f"📊 Renewal summary: {successful} successful, {failed} failed")
            
            # Send summary notification
            if results:
                await self._send_renewal_summary(results)
        
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    
    def _get_certificates_needing_renewal(self, db: Session) -> List[Certificate]:
        """Get all certificates that need renewal"""
        threshold_date = datetime.now(timezone.utc) + timedelta(
            days=self.config.renewal_threshold_days
        )
        
        certificates = db.query(Certificate).filter(
            Certificate.status == "active",
            Certificate.not_after <= threshold_date
        ).order_by(Certificate.not_after.asc()).all()
        
        return certificates
    
    async def _process_renewals(
        self,
        db: Session,
        certificates: List[Certificate]
    ) -> List[RenewalResult]:
        """Process certificate renewals"""
        results = []
        
        for cert in certificates:
            days_until_expiry = (cert.not_after - datetime.now(timezone.utc)).days
            
            # Determine notification level based on urgency
            if days_until_expiry <= self.config.critical_threshold_days:
                level = NotificationLevel.CRITICAL
            elif days_until_expiry <= self.config.warning_threshold_days:
                level = NotificationLevel.WARNING
            else:
                level = NotificationLevel.INFO
            
            logger.info(f"🔄 Renewing certificate for {cert.service_id} "
                       f"(expires in {days_until_expiry} days)")
            
            # Send pre-renewal notification
            await self.notification_manager.send_notification(
                level=level,
                title=f"Certificate Renewal Starting: {cert.service_id}",
                message=f"Auto-renewal initiated for {cert.common_name} "
                       f"(expires in {days_until_expiry} days)",
                data={
                    "service_id": cert.service_id,
                    "certificate_id": cert.certificate_id,
                    "days_until_expiry": days_until_expiry
                }
            )
            
            # Attempt renewal
            result = await self._renew_certificate(db, cert)
            results.append(result)
            
            # Send post-renewal notification
            if result.success:
                await self.notification_manager.send_notification(
                    level=NotificationLevel.INFO,
                    title=f"Certificate Renewed: {cert.service_id}",
                    message=f"Successfully renewed certificate for {cert.common_name}",
                    data={
                        "service_id": result.service_id,
                        "old_serial": result.old_serial,
                        "new_serial": result.new_serial
                    }
                )
            else:
                await self.notification_manager.send_notification(
                    level=NotificationLevel.CRITICAL,
                    title=f"Certificate Renewal Failed: {cert.service_id}",
                    message=f"Failed to renew certificate: {result.error_message}",
                    data={
                        "service_id": result.service_id,
                        "certificate_id": result.certificate_id,
                        "error": result.error_message
                    }
                )
        
        return results
    
    async def _renew_certificate(
        self,
        db: Session,
        cert: Certificate
    ) -> RenewalResult:
        """Renew a single certificate with retry logic"""
        old_serial = cert.serial_number
        
        # Check/create rotation schedule
        schedule = db.query(RotationSchedule).filter(
            RotationSchedule.certificate_id == cert.certificate_id,
            RotationSchedule.status == RenewalStatus.PENDING.value
        ).first()
        
        if not schedule:
            schedule = RotationSchedule(
                certificate_id=cert.certificate_id,
                service_id=cert.service_id,
                scheduled_renewal_date=datetime.now(timezone.utc),
                status=RenewalStatus.PENDING.value,
                attempt_count=0
            )
            db.add(schedule)
            db.commit()
        
        # Retry loop
        retry_delay = self.config.retry_delay_seconds
        
        for attempt in range(1, self.config.max_retry_attempts + 1):
            try:
                schedule.last_attempt = datetime.now(timezone.utc)
                schedule.attempt_count = attempt
                schedule.status = RenewalStatus.IN_PROGRESS.value
                db.commit()
                
                # Perform renewal
                result = self._perform_renewal(cert, db)
                
                if result.success:
                    schedule.status = RenewalStatus.COMPLETED.value
                    schedule.completed_at = datetime.now(timezone.utc)
                    db.commit()
                    
                    # Log audit entry
                    self._log_audit(db, "CERTIFICATE_RENEWED", cert.service_id,
                                   cert.certificate_id, success=True,
                                   details={"old_serial": old_serial,
                                           "new_serial": result.new_serial})
                    
                    return result
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Renewal attempt {attempt} failed: {error_msg}")
                
                schedule.error_message = error_msg
                db.commit()
                
                if attempt < self.config.max_retry_attempts:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= self.config.retry_backoff_multiplier
        
        # All retries failed
        schedule.status = RenewalStatus.FAILED.value
        db.commit()
        
        self._log_audit(db, "CERTIFICATE_RENEWED", cert.service_id,
                       cert.certificate_id, success=False,
                       error_message=schedule.error_message)
        
        return RenewalResult(
            certificate_id=cert.certificate_id,
            service_id=cert.service_id,
            success=False,
            old_serial=old_serial,
            error_message=schedule.error_message
        )
    
    def _perform_renewal(self, cert: Certificate, db: Session) -> RenewalResult:
        """Perform the actual certificate renewal"""
        try:
            # Parse existing SANs
            san_dns = json.loads(cert.san_dns) if cert.san_dns else []
            san_ip = json.loads(cert.san_ip) if cert.san_ip else []
            
            # Renew using cert_manager
            new_cert_info = self.cert_manager.renew_service_certificate(
                service_id=cert.service_id,
                validity_days=365  # Default 1 year
            )
            
            return RenewalResult(
                certificate_id=cert.certificate_id,
                service_id=cert.service_id,
                success=True,
                old_serial=cert.serial_number,
                new_serial=new_cert_info.get("serial_number"),
                renewed_at=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            return RenewalResult(
                certificate_id=cert.certificate_id,
                service_id=cert.service_id,
                success=False,
                old_serial=cert.serial_number,
                error_message=str(e)
            )
    
    def _log_audit(
        self,
        db: Session,
        action: str,
        service_id: str,
        certificate_id: str,
        success: bool = True,
        details: Optional[Dict] = None,
        error_message: Optional[str] = None
    ):
        """Log an audit entry"""
        try:
            audit = AuditLog(
                action=action,
                service_id=service_id,
                certificate_id=certificate_id,
                user_id="auto-renewal-engine",
                success=success,
                details=json.dumps(details) if details else None,
                error_message=error_message
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to log audit entry: {e}")
    
    async def _send_renewal_summary(self, results: List[RenewalResult]):
        """Send a summary notification of all renewals"""
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        if failed:
            level = NotificationLevel.WARNING
            title = f"Auto-Renewal Summary: {len(successful)} successful, {len(failed)} failed"
        else:
            level = NotificationLevel.INFO
            title = f"Auto-Renewal Summary: {len(successful)} certificates renewed"
        
        await self.notification_manager.send_notification(
            level=level,
            title=title,
            message=f"Renewal cycle completed. "
                   f"{len(successful)} renewed, {len(failed)} failed.",
            data={
                "successful": [{"service_id": r.service_id, 
                               "new_serial": r.new_serial} for r in successful],
                "failed": [{"service_id": r.service_id, 
                           "error": r.error_message} for r in failed]
            }
        )
    
    # ========================================================================
    # Manual Operations
    # ========================================================================
    
    def force_check(self):
        """Force an immediate certificate check (useful for testing)"""
        logger.info("⚡ Forcing immediate certificate check...")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self._check_and_renew_certificates())
        finally:
            loop.close()
    
    def get_certificates_status(self) -> List[Dict[str, Any]]:
        """Get status of all certificates with renewal information"""
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            certificates = db.query(Certificate).filter(
                Certificate.status == "active"
            ).all()
            
            result = []
            for cert in certificates:
                days_until_expiry = (cert.not_after - datetime.now(timezone.utc)).days
                
                # Determine status
                if days_until_expiry <= self.config.critical_threshold_days:
                    renewal_status = "critical"
                elif days_until_expiry <= self.config.warning_threshold_days:
                    renewal_status = "warning"
                elif days_until_expiry <= self.config.renewal_threshold_days:
                    renewal_status = "scheduled"
                else:
                    renewal_status = "ok"
                
                result.append({
                    "service_id": cert.service_id,
                    "certificate_id": cert.certificate_id,
                    "common_name": cert.common_name,
                    "serial_number": cert.serial_number,
                    "not_after": cert.not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "renewal_status": renewal_status,
                    "needs_renewal": days_until_expiry <= self.config.renewal_threshold_days
                })
            
            return sorted(result, key=lambda x: x["days_until_expiry"])
        
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass


# ============================================================================
# Integration with PKI Server
# ============================================================================

def create_auto_renewal_engine(cert_manager, config: Optional[RenewalConfig] = None):
    """Factory function to create an auto-renewal engine instance"""
    return AutoRenewalEngine(cert_manager, config)


# ============================================================================
# Example Usage / Testing
# ============================================================================

if __name__ == "__main__":
    """Example usage of the auto-renewal engine"""
    
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("VCC PKI Auto-Renewal Engine - Test Mode")
    print("=" * 60)
    
    # Initialize database
    from database import init_database
    init_database()
    
    # For testing, we would need a cert_manager instance
    # This is just a demonstration of the API
    
    config = RenewalConfig(
        renewal_threshold_days=30,
        warning_threshold_days=14,
        critical_threshold_days=7,
        check_interval_seconds=60,  # 1 minute for testing
        max_retry_attempts=3
    )
    
    print(f"\nConfiguration:")
    print(f"  - Renewal threshold: {config.renewal_threshold_days} days")
    print(f"  - Warning threshold: {config.warning_threshold_days} days")
    print(f"  - Critical threshold: {config.critical_threshold_days} days")
    print(f"  - Check interval: {config.check_interval_seconds} seconds")
    
    print("\n✅ Auto-Renewal Engine module loaded successfully")
    print("   Use create_auto_renewal_engine(cert_manager) to create an instance")
