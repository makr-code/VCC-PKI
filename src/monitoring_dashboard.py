# ============================================================================
# VCC PROTECTED SOURCE CODE
# ============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# License: Proprietary
# Contact: legal@vcc.local
#
# Module: monitoring_dashboard
# Description: VCC PKI Certificate Monitoring Dashboard API
# File Path: monitoring_dashboard.py
#
# Version: 1.0.0
# Author: VCC Security Team
#
# ============================================================================

"""
VCC PKI Monitoring Dashboard
============================

Provides comprehensive certificate monitoring and analytics capabilities.

Features:
- Real-time certificate status overview
- Expiration alerts and warnings
- Certificate metrics and statistics
- Health indicators for all components
- Audit log viewer
- System status dashboard

Author: VCC Team
Date: 2025-11-25
Version: 1.0.0
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class CertificateHealthStatus(str, Enum):
    """Certificate health status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"
    REVOKED = "revoked"


class SystemHealthStatus(str, Enum):
    """System health status levels"""
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    DOWN = "down"
    MAINTENANCE = "maintenance"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class Alert:
    """Alert model"""
    alert_id: str
    severity: AlertSeverity
    title: str
    message: str
    source: str
    created_at: datetime
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result["severity"] = self.severity.value
        result["created_at"] = self.created_at.isoformat()
        if self.acknowledged_at:
            result["acknowledged_at"] = self.acknowledged_at.isoformat()
        return result


@dataclass
class DashboardConfig:
    """Configuration for the Monitoring Dashboard"""
    warning_threshold_days: int = 30
    critical_threshold_days: int = 14
    max_alerts: int = 100
    enable_notifications: bool = True
    refresh_interval_seconds: int = 60
    
    @classmethod
    def from_env(cls) -> "DashboardConfig":
        """Create configuration from environment variables"""
        return cls(
            warning_threshold_days=int(os.getenv("VCC_DASHBOARD_WARNING_DAYS", "30")),
            critical_threshold_days=int(os.getenv("VCC_DASHBOARD_CRITICAL_DAYS", "14")),
            max_alerts=int(os.getenv("VCC_DASHBOARD_MAX_ALERTS", "100")),
            enable_notifications=os.getenv("VCC_DASHBOARD_NOTIFICATIONS", "true").lower() == "true",
            refresh_interval_seconds=int(os.getenv("VCC_DASHBOARD_REFRESH_SECONDS", "60"))
        )


@dataclass
class CertificateMetrics:
    """Certificate metrics summary"""
    total_certificates: int = 0
    active_certificates: int = 0
    expired_certificates: int = 0
    revoked_certificates: int = 0
    expiring_soon_30d: int = 0
    expiring_soon_14d: int = 0
    expiring_soon_7d: int = 0
    avg_days_to_expiry: float = 0.0
    oldest_certificate_days: int = 0
    newest_certificate_days: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class SystemMetrics:
    """System metrics summary"""
    uptime_seconds: float = 0.0
    total_requests: int = 0
    requests_per_minute: float = 0.0
    avg_response_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    disk_usage_percent: float = 0.0
    active_connections: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class ComponentStatus:
    """Component health status"""
    name: str
    status: SystemHealthStatus
    message: str
    last_check: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "last_check": self.last_check.isoformat(),
            "details": self.details
        }


# ============================================================================
# Monitoring Dashboard
# ============================================================================

class MonitoringDashboard:
    """
    Certificate Monitoring Dashboard.
    
    Provides comprehensive monitoring and analytics for the PKI system.
    """
    
    def __init__(self, config: Optional[DashboardConfig] = None):
        """
        Initialize the Monitoring Dashboard.
        
        Args:
            config: Dashboard configuration
        """
        self.config = config or DashboardConfig.from_env()
        
        # Alerts storage (in production, use database)
        self._alerts: List[Alert] = []
        self._alert_counter = 0
        
        # Metrics tracking
        self._start_time = datetime.now(timezone.utc)
        self._request_count = 0
        self._response_times: List[float] = []
        
        # Component status tracking
        self._component_status: Dict[str, ComponentStatus] = {}
        
        logger.info("📊 Monitoring Dashboard initialized")
    
    # ========================================================================
    # Certificate Monitoring
    # ========================================================================
    
    def get_certificate_metrics(self, db_session) -> CertificateMetrics:
        """
        Get comprehensive certificate metrics.
        
        Args:
            db_session: Database session
            
        Returns:
            CertificateMetrics object
        """
        from database import Certificate
        
        now = datetime.now(timezone.utc)
        
        # Query all certificates
        certificates = db_session.query(Certificate).all()
        
        metrics = CertificateMetrics()
        metrics.total_certificates = len(certificates)
        
        days_to_expiry_list = []
        
        for cert in certificates:
            if cert.status == "active":
                metrics.active_certificates += 1
                
                # Calculate days to expiry
                # Handle timezone-naive datetime
                if cert.not_after.tzinfo is None:
                    not_after = cert.not_after.replace(tzinfo=timezone.utc)
                else:
                    not_after = cert.not_after
                    
                days_to_expiry = (not_after - now).days
                days_to_expiry_list.append(days_to_expiry)
                
                # Expiration buckets
                if days_to_expiry <= 7:
                    metrics.expiring_soon_7d += 1
                    metrics.expiring_soon_14d += 1
                    metrics.expiring_soon_30d += 1
                elif days_to_expiry <= 14:
                    metrics.expiring_soon_14d += 1
                    metrics.expiring_soon_30d += 1
                elif days_to_expiry <= 30:
                    metrics.expiring_soon_30d += 1
                    
            elif cert.status == "expired":
                metrics.expired_certificates += 1
            elif cert.status == "revoked":
                metrics.revoked_certificates += 1
        
        # Calculate averages
        if days_to_expiry_list:
            metrics.avg_days_to_expiry = sum(days_to_expiry_list) / len(days_to_expiry_list)
            metrics.oldest_certificate_days = min(days_to_expiry_list)
            metrics.newest_certificate_days = max(days_to_expiry_list)
        
        return metrics
    
    def get_certificate_health_overview(self, db_session) -> Dict[str, Any]:
        """
        Get certificate health overview with status breakdown.
        
        Args:
            db_session: Database session
            
        Returns:
            Dictionary with health overview
        """
        from database import Certificate
        
        now = datetime.now(timezone.utc)
        
        # Query active certificates
        certificates = db_session.query(Certificate).filter(
            Certificate.status == "active"
        ).all()
        
        health_breakdown = {
            CertificateHealthStatus.HEALTHY.value: [],
            CertificateHealthStatus.WARNING.value: [],
            CertificateHealthStatus.CRITICAL.value: [],
            CertificateHealthStatus.EXPIRED.value: [],
            CertificateHealthStatus.REVOKED.value: []
        }
        
        for cert in certificates:
            # Handle timezone-naive datetime
            if cert.not_after.tzinfo is None:
                not_after = cert.not_after.replace(tzinfo=timezone.utc)
            else:
                not_after = cert.not_after
                
            days_to_expiry = (not_after - now).days
            
            cert_info = {
                "certificate_id": cert.certificate_id,
                "service_id": cert.service_id,
                "common_name": cert.common_name,
                "days_to_expiry": days_to_expiry,
                "not_after": cert.not_after.isoformat()
            }
            
            if days_to_expiry <= 0:
                health_breakdown[CertificateHealthStatus.EXPIRED.value].append(cert_info)
            elif days_to_expiry <= self.config.critical_threshold_days:
                health_breakdown[CertificateHealthStatus.CRITICAL.value].append(cert_info)
            elif days_to_expiry <= self.config.warning_threshold_days:
                health_breakdown[CertificateHealthStatus.WARNING.value].append(cert_info)
            else:
                health_breakdown[CertificateHealthStatus.HEALTHY.value].append(cert_info)
        
        # Add revoked certificates
        revoked_certs = db_session.query(Certificate).filter(
            Certificate.status == "revoked"
        ).all()
        
        for cert in revoked_certs:
            health_breakdown[CertificateHealthStatus.REVOKED.value].append({
                "certificate_id": cert.certificate_id,
                "service_id": cert.service_id,
                "common_name": cert.common_name,
                "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
                "revocation_reason": cert.revocation_reason
            })
        
        # Calculate summary
        total_active = len(health_breakdown[CertificateHealthStatus.HEALTHY.value]) + \
                       len(health_breakdown[CertificateHealthStatus.WARNING.value]) + \
                       len(health_breakdown[CertificateHealthStatus.CRITICAL.value])
        
        return {
            "summary": {
                "total_active": total_active,
                "healthy": len(health_breakdown[CertificateHealthStatus.HEALTHY.value]),
                "warning": len(health_breakdown[CertificateHealthStatus.WARNING.value]),
                "critical": len(health_breakdown[CertificateHealthStatus.CRITICAL.value]),
                "expired": len(health_breakdown[CertificateHealthStatus.EXPIRED.value]),
                "revoked": len(health_breakdown[CertificateHealthStatus.REVOKED.value])
            },
            "health_breakdown": health_breakdown,
            "overall_health": self._determine_overall_health(health_breakdown)
        }
    
    def _determine_overall_health(self, health_breakdown: Dict[str, List]) -> str:
        """Determine overall certificate health status"""
        if len(health_breakdown[CertificateHealthStatus.CRITICAL.value]) > 0:
            return "critical"
        elif len(health_breakdown[CertificateHealthStatus.WARNING.value]) > 0:
            return "warning"
        elif len(health_breakdown[CertificateHealthStatus.EXPIRED.value]) > 0:
            return "degraded"
        return "healthy"
    
    def get_expiring_certificates(
        self, 
        db_session, 
        days: int = 30, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get certificates expiring within specified days.
        
        Args:
            db_session: Database session
            days: Number of days to check
            limit: Maximum number of results
            
        Returns:
            List of expiring certificates
        """
        from database import Certificate
        
        threshold = datetime.now(timezone.utc) + timedelta(days=days)
        
        certificates = db_session.query(Certificate).filter(
            Certificate.status == "active",
            Certificate.not_after <= threshold
        ).order_by(Certificate.not_after.asc()).limit(limit).all()
        
        now = datetime.now(timezone.utc)
        
        result = []
        for cert in certificates:
            # Handle timezone-naive datetime
            if cert.not_after.tzinfo is None:
                not_after = cert.not_after.replace(tzinfo=timezone.utc)
            else:
                not_after = cert.not_after
                
            days_remaining = (not_after - now).days
            
            result.append({
                "certificate_id": cert.certificate_id,
                "service_id": cert.service_id,
                "common_name": cert.common_name,
                "serial_number": cert.serial_number,
                "not_after": cert.not_after.isoformat(),
                "days_remaining": days_remaining,
                "urgency": self._get_urgency_level(days_remaining)
            })
        
        return result
    
    def _get_urgency_level(self, days_remaining: int) -> str:
        """Determine urgency level based on days remaining"""
        if days_remaining <= 0:
            return "expired"
        elif days_remaining <= 7:
            return "critical"
        elif days_remaining <= 14:
            return "high"
        elif days_remaining <= 30:
            return "medium"
        return "low"
    
    # ========================================================================
    # System Monitoring
    # ========================================================================
    
    def get_system_metrics(self) -> SystemMetrics:
        """
        Get system performance metrics.
        
        Returns:
            SystemMetrics object
        """
        import psutil
        
        now = datetime.now(timezone.utc)
        
        metrics = SystemMetrics()
        
        # Uptime
        metrics.uptime_seconds = (now - self._start_time).total_seconds()
        
        # Request statistics
        metrics.total_requests = self._request_count
        if metrics.uptime_seconds > 0:
            metrics.requests_per_minute = (self._request_count / metrics.uptime_seconds) * 60
        
        # Response time
        if self._response_times:
            metrics.avg_response_time_ms = sum(self._response_times[-100:]) / min(len(self._response_times), 100)
        
        # System resources
        try:
            process = psutil.Process()
            metrics.memory_usage_mb = process.memory_info().rss / (1024 * 1024)
            metrics.disk_usage_percent = psutil.disk_usage('/').percent
        except Exception:
            pass
        
        return metrics
    
    def get_component_status(self) -> Dict[str, ComponentStatus]:
        """
        Get status of all system components.
        
        Returns:
            Dictionary of component statuses
        """
        return self._component_status
    
    def update_component_status(
        self,
        name: str,
        status: SystemHealthStatus,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Update the status of a component.
        
        Args:
            name: Component name
            status: Current status
            message: Status message
            details: Additional details
        """
        self._component_status[name] = ComponentStatus(
            name=name,
            status=status,
            message=message,
            last_check=datetime.now(timezone.utc),
            details=details or {}
        )
    
    def get_overall_system_status(self) -> Dict[str, Any]:
        """
        Get overall system status.
        
        Returns:
            Dictionary with overall status
        """
        components = self._component_status
        
        if not components:
            overall_status = SystemHealthStatus.OPERATIONAL
        elif any(c.status == SystemHealthStatus.DOWN for c in components.values()):
            overall_status = SystemHealthStatus.DOWN
        elif any(c.status == SystemHealthStatus.DEGRADED for c in components.values()):
            overall_status = SystemHealthStatus.DEGRADED
        else:
            overall_status = SystemHealthStatus.OPERATIONAL
        
        return {
            "status": overall_status.value,
            "components": {name: status.to_dict() for name, status in components.items()},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    # ========================================================================
    # Alert Management
    # ========================================================================
    
    def create_alert(
        self,
        severity: AlertSeverity,
        title: str,
        message: str,
        source: str
    ) -> Alert:
        """
        Create a new alert.
        
        Args:
            severity: Alert severity
            title: Alert title
            message: Alert message
            source: Source component
            
        Returns:
            Created alert
        """
        self._alert_counter += 1
        
        alert = Alert(
            alert_id=f"ALT-{self._alert_counter:06d}",
            severity=severity,
            title=title,
            message=message,
            source=source,
            created_at=datetime.now(timezone.utc)
        )
        
        # Add to alerts list (keep max alerts)
        self._alerts.insert(0, alert)
        if len(self._alerts) > self.config.max_alerts:
            self._alerts = self._alerts[:self.config.max_alerts]
        
        logger.warning(f"🚨 Alert created: [{severity.value}] {title}")
        
        return alert
    
    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 50
    ) -> List[Alert]:
        """
        Get alerts with optional filtering.
        
        Args:
            severity: Filter by severity
            acknowledged: Filter by acknowledgement status
            limit: Maximum number of alerts
            
        Returns:
            List of alerts
        """
        alerts = self._alerts
        
        if severity is not None:
            alerts = [a for a in alerts if a.severity == severity]
        
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        
        return alerts[:limit]
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: Alert identifier
            acknowledged_by: User who acknowledged
            
        Returns:
            True if acknowledged successfully
        """
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_at = datetime.now(timezone.utc)
                alert.acknowledged_by = acknowledged_by
                logger.info(f"✅ Alert {alert_id} acknowledged by {acknowledged_by}")
                return True
        return False
    
    def get_alert_summary(self) -> Dict[str, int]:
        """
        Get summary of alerts by severity.
        
        Returns:
            Dictionary with alert counts
        """
        summary = {
            "info": 0,
            "warning": 0,
            "critical": 0,
            "emergency": 0,
            "unacknowledged": 0,
            "total": len(self._alerts)
        }
        
        for alert in self._alerts:
            summary[alert.severity.value] += 1
            if not alert.acknowledged:
                summary["unacknowledged"] += 1
        
        return summary
    
    # ========================================================================
    # Audit Log Viewer
    # ========================================================================
    
    def get_audit_logs(
        self,
        db_session,
        service_id: Optional[str] = None,
        action: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get audit logs with optional filtering.
        
        Args:
            db_session: Database session
            service_id: Filter by service ID
            action: Filter by action type
            start_date: Start date filter
            end_date: End date filter
            limit: Maximum number of results
            
        Returns:
            List of audit log entries
        """
        from database import AuditLog
        
        query = db_session.query(AuditLog)
        
        if service_id:
            query = query.filter(AuditLog.service_id == service_id)
        
        if action:
            query = query.filter(AuditLog.action == action)
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
        
        return [
            {
                "log_id": str(log.id),
                "action": log.action,
                "service_id": log.service_id,
                "certificate_id": log.certificate_id,
                "user_id": log.user_id,
                "ip_address": log.ip_address,
                "details": log.details,
                "success": log.success,
                "error_message": log.error_message,
                "timestamp": log.timestamp.isoformat()
            }
            for log in logs
        ]
    
    def get_audit_summary(self, db_session) -> Dict[str, Any]:
        """
        Get summary of audit log activity.
        
        Args:
            db_session: Database session
            
        Returns:
            Dictionary with audit summary
        """
        from database import AuditLog
        from sqlalchemy import func
        
        # Get counts by action
        action_counts = db_session.query(
            AuditLog.action,
            func.count(AuditLog.id)
        ).group_by(AuditLog.action).all()
        
        # Get counts by day (last 7 days)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        daily_counts = db_session.query(
            func.date(AuditLog.timestamp),
            func.count(AuditLog.id)
        ).filter(
            AuditLog.timestamp >= seven_days_ago
        ).group_by(func.date(AuditLog.timestamp)).all()
        
        # Success/failure counts
        success_count = db_session.query(AuditLog).filter(AuditLog.success == True).count()
        failure_count = db_session.query(AuditLog).filter(AuditLog.success == False).count()
        
        return {
            "by_action": {action: count for action, count in action_counts},
            "by_day": {str(date): count for date, count in daily_counts},
            "success_rate": success_count / max(success_count + failure_count, 1) * 100,
            "total_success": success_count,
            "total_failure": failure_count
        }
    
    # ========================================================================
    # Dashboard Statistics
    # ========================================================================
    
    def record_request(self, response_time_ms: float):
        """
        Record a request for statistics.
        
        Args:
            response_time_ms: Response time in milliseconds
        """
        self._request_count += 1
        self._response_times.append(response_time_ms)
        
        # Keep only last 1000 response times
        if len(self._response_times) > 1000:
            self._response_times = self._response_times[-1000:]
    
    def get_dashboard_summary(self, db_session) -> Dict[str, Any]:
        """
        Get comprehensive dashboard summary.
        
        Args:
            db_session: Database session
            
        Returns:
            Dictionary with full dashboard data
        """
        cert_metrics = self.get_certificate_metrics(db_session)
        cert_health = self.get_certificate_health_overview(db_session)
        sys_metrics = self.get_system_metrics()
        sys_status = self.get_overall_system_status()
        alert_summary = self.get_alert_summary()
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificate_metrics": cert_metrics.to_dict(),
            "certificate_health": cert_health,
            "system_metrics": sys_metrics.to_dict(),
            "system_status": sys_status,
            "alerts": alert_summary,
            "config": {
                "warning_threshold_days": self.config.warning_threshold_days,
                "critical_threshold_days": self.config.critical_threshold_days,
                "refresh_interval_seconds": self.config.refresh_interval_seconds
            }
        }


# ============================================================================
# API Router Factory
# ============================================================================

def create_monitoring_router(dashboard: MonitoringDashboard) -> APIRouter:
    """
    Create FastAPI router for monitoring endpoints.
    
    Args:
        dashboard: MonitoringDashboard instance
        
    Returns:
        FastAPI router
    """
    from database import get_db
    from sqlalchemy.orm import Session
    
    router = APIRouter(prefix="/api/v1/monitoring", tags=["Monitoring Dashboard"])
    
    @router.get("/dashboard")
    async def get_dashboard_summary(db: Session = Depends(get_db)):
        """Get comprehensive dashboard summary"""
        return dashboard.get_dashboard_summary(db)
    
    @router.get("/certificates/metrics")
    async def get_certificate_metrics(db: Session = Depends(get_db)):
        """Get certificate metrics"""
        return dashboard.get_certificate_metrics(db).to_dict()
    
    @router.get("/certificates/health")
    async def get_certificate_health(db: Session = Depends(get_db)):
        """Get certificate health overview"""
        return dashboard.get_certificate_health_overview(db)
    
    @router.get("/certificates/expiring")
    async def get_expiring_certificates(
        days: int = Query(30, ge=1, le=365),
        limit: int = Query(50, ge=1, le=200),
        db: Session = Depends(get_db)
    ):
        """Get certificates expiring within specified days"""
        return {
            "days": days,
            "certificates": dashboard.get_expiring_certificates(db, days, limit)
        }
    
    @router.get("/system/metrics")
    async def get_system_metrics():
        """Get system performance metrics"""
        return dashboard.get_system_metrics().to_dict()
    
    @router.get("/system/status")
    async def get_system_status():
        """Get overall system status"""
        return dashboard.get_overall_system_status()
    
    @router.get("/alerts")
    async def get_alerts(
        severity: Optional[str] = Query(None),
        acknowledged: Optional[bool] = Query(None),
        limit: int = Query(50, ge=1, le=200)
    ):
        """Get alerts with optional filtering"""
        sev = AlertSeverity(severity) if severity else None
        alerts = dashboard.get_alerts(sev, acknowledged, limit)
        return {
            "total": len(alerts),
            "alerts": [a.to_dict() for a in alerts]
        }
    
    @router.get("/alerts/summary")
    async def get_alert_summary():
        """Get alert summary"""
        return dashboard.get_alert_summary()
    
    @router.post("/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert(alert_id: str, acknowledged_by: str = "system"):
        """Acknowledge an alert"""
        success = dashboard.acknowledge_alert(alert_id, acknowledged_by)
        if not success:
            raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")
        return {"success": True, "alert_id": alert_id}
    
    @router.get("/audit")
    async def get_audit_logs(
        service_id: Optional[str] = Query(None),
        action: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=500),
        db: Session = Depends(get_db)
    ):
        """Get audit logs with optional filtering"""
        logs = dashboard.get_audit_logs(db, service_id, action, limit=limit)
        return {
            "total": len(logs),
            "logs": logs
        }
    
    @router.get("/audit/summary")
    async def get_audit_summary(db: Session = Depends(get_db)):
        """Get audit log summary"""
        return dashboard.get_audit_summary(db)
    
    return router


# ============================================================================
# Factory Function
# ============================================================================

def create_monitoring_dashboard(config: Optional[DashboardConfig] = None) -> MonitoringDashboard:
    """
    Create a new MonitoringDashboard instance.
    
    Args:
        config: Dashboard configuration
        
    Returns:
        MonitoringDashboard instance
    """
    return MonitoringDashboard(config)
