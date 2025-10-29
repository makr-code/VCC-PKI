# VCC PKI System - Certificate Re-certification & Lifecycle Management

## 📋 Übersicht

Das **Certificate Lifecycle Management** erweitert das VCC PKI System um automatisierte Zertifikat-Erneuerung, intelligente Re-certification Workflows und Enterprise-grade Certificate Governance für alle VCC-Services.

## 🎯 **Ziele & Anforderungen**

### **Primäre Ziele**
- **Zero-Downtime Renewals** für alle VCC-Services ohne Service-Unterbrechung
- **Proactive Lifecycle Management** mit automatischer Erneuerung vor Ablauf
- **Emergency Re-certification** bei Sicherheitsvorfällen oder Kompromittierung
- **Compliance Automation** für Audit-Trails und Governance-Reporting

### **Business Requirements**
- **99.9% Renewal Success Rate** für kritische VCC-Services
- **<30 Minuten Emergency Re-certification** bei Sicherheitsvorfällen
- **Zero Touch Operations** für Routine-Erneuerungen
- **Complete Audit Trail** für Compliance und Forensik

## 🏗️ **Architektur**

### **Certificate Lifecycle Components**
```
┌────────────────────────────────────────────────────────────┐
│                VCC Certificate Lifecycle Manager           │
├────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │  Renewal    │  │  Template    │  │   Policy        │   │
│  │  Scheduler  │◄─►│  Manager     │◄─►│   Engine        │   │
│  │             │  │              │  │                 │   │
│  └─────────────┘  └──────────────┘  └─────────────────┘   │
│         │                   │                     │        │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Certificate │  │  Notification│  │    Audit &      │   │
│  │ Deployment  │  │   Service    │  │   Reporting     │   │
│  │  Automation │  │              │  │    Service      │   │
│  └─────────────┘  └──────────────┘  └─────────────────┘   │
├────────────────────────────────────────────────────────────┤
│                    VCC Service Integration                  │
│   Clara │ Covina │ Argus │ Veritas │ VPB │ External      │
└────────────────────────────────────────────────────────────┘
```

### **Certificate States & Transitions**
```
┌─────────┐   Issue    ┌─────────┐   Activate   ┌─────────┐
│ Request │ ────────► │ Issued  │ ───────────► │ Active  │
└─────────┘           └─────────┘              └─────────┘
                                                     │
    ┌─────────┐   Renew    ┌──────────┐   Warning   │
    │ Renewed │ ◄────────── │ Expiring │ ◄───────────┘
    └─────────┘             └──────────┘
         │                        │
         │                        ▼
         │                  ┌─────────┐
         └─────────────────►│ Revoked │
                           └─────────┘
```

## 🔧 **Implementation Spezifikation**

### **1. Certificate Lifecycle Manager**

```python
# app/services/certificate_lifecycle.py
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Union
from enum import Enum
import asyncio
from dataclasses import dataclass
import logging

class CertificateStatus(Enum):
    ISSUED = "issued"
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    REVOKED = "revoked"
    RENEWED = "renewed"
    SUSPENDED = "suspended"

class RenewalTrigger(Enum):
    SCHEDULED = "scheduled"           # Normal renewal before expiry
    EMERGENCY = "emergency"           # Security incident
    POLICY_UPDATE = "policy_update"   # Changed security policies
    SERVICE_UPDATE = "service_update" # VCC service changes
    MANUAL = "manual"                 # Manual administrative action

@dataclass
class RenewalPolicy:
    """Certificate Renewal Policy Configuration"""
    certificate_type: str
    validity_period: timedelta
    renewal_threshold: timedelta      # When to start renewal process
    emergency_threshold: timedelta    # When to send critical alerts
    auto_renewal_enabled: bool
    notification_recipients: List[str]
    pre_validation_required: bool
    post_deployment_validation: bool
    max_renewal_attempts: int = 3
    retry_interval: timedelta = timedelta(hours=1)

class VCCCertificateLifecycleManager:
    """Enterprise Certificate Lifecycle Management für VCC Services"""
    
    def __init__(self, pki_service, notification_service, audit_service):
        self.pki_service = pki_service
        self.notification_service = notification_service
        self.audit_service = audit_service
        self.renewal_policies: Dict[str, RenewalPolicy] = {}
        self.active_renewals: Dict[str, RenewalProcess] = {}
        
        # Load renewal policies
        asyncio.create_task(self._load_renewal_policies())
        
        # Start background scheduler
        asyncio.create_task(self._renewal_scheduler_loop())
    
    async def schedule_certificate_renewal(self, 
                                         cert_id: str, 
                                         renewal_trigger: RenewalTrigger = RenewalTrigger.SCHEDULED,
                                         force_renewal: bool = False) -> RenewalProcess:
        """
        Schedule certificate renewal with comprehensive validation
        
        Args:
            cert_id: Certificate ID to renew
            renewal_trigger: Reason for renewal
            force_renewal: Skip eligibility checks
            
        Returns:
            RenewalProcess tracking object
        """
        try:
            logger.info(f"Scheduling renewal for certificate {cert_id}, trigger: {renewal_trigger.value}")
            
            # Get certificate info
            certificate = await self.pki_service.get_certificate(cert_id)
            if not certificate:
                raise CertificateNotFoundError(f"Certificate {cert_id} not found")
            
            # Check renewal eligibility
            if not force_renewal:
                eligibility = await self._check_renewal_eligibility(certificate, renewal_trigger)
                if not eligibility.eligible:
                    raise RenewalNotEligibleError(eligibility.reason)
            
            # Create renewal process
            renewal_process = RenewalProcess(
                cert_id=cert_id,
                original_certificate=certificate,
                renewal_trigger=renewal_trigger,
                policy=self.renewal_policies.get(certificate.cert_type),
                created_at=datetime.utcnow()
            )
            
            # Track active renewal
            self.active_renewals[cert_id] = renewal_process
            
            # Start renewal workflow
            asyncio.create_task(self._execute_renewal_workflow(renewal_process))
            
            # Audit logging
            await self.audit_service.log_event(
                event_type="certificate_renewal_scheduled",
                certificate_id=cert_id,
                trigger=renewal_trigger.value,
                metadata={
                    "original_expiry": certificate.expires_at.isoformat(),
                    "renewal_reason": renewal_trigger.value
                }
            )
            
            return renewal_process
            
        except Exception as e:
            logger.error(f"Failed to schedule renewal for {cert_id}: {e}")
            raise
    
    async def execute_emergency_recertification(self, 
                                              cert_ids: List[str],
                                              incident_id: str,
                                              reason: str) -> EmergencyRecertificationResult:
        """
        Emergency re-certification bei Sicherheitsvorfällen
        
        Designed für schnelle Reaktion bei kompromittierten Zertifikaten
        """
        try:
            logger.critical(f"Emergency recertification initiated for incident {incident_id}")
            
            recert_result = EmergencyRecertificationResult(
                incident_id=incident_id,
                affected_certificates=cert_ids,
                started_at=datetime.utcnow()
            )
            
            # Parallel processing für Geschwindigkeit
            tasks = []
            for cert_id in cert_ids:
                task = asyncio.create_task(
                    self._emergency_recertify_single(cert_id, incident_id, reason)
                )
                tasks.append(task)
            
            # Wait for all emergency renewals
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            successful_renewals = []
            failed_renewals = []
            
            for cert_id, result in zip(cert_ids, results):
                if isinstance(result, Exception):
                    failed_renewals.append({
                        "cert_id": cert_id,
                        "error": str(result)
                    })
                else:
                    successful_renewals.append(result)
            
            recert_result.successful_count = len(successful_renewals)
            recert_result.failed_count = len(failed_renewals)
            recert_result.completed_at = datetime.utcnow()
            
            # Critical notification
            await self.notification_service.send_critical_alert(
                subject=f"Emergency Re-certification Completed - Incident {incident_id}",
                message=f"Processed {len(cert_ids)} certificates: {len(successful_renewals)} successful, {len(failed_renewals)} failed",
                recipients=await self._get_security_team_contacts()
            )
            
            # Audit logging
            await self.audit_service.log_event(
                event_type="emergency_recertification_completed",
                incident_id=incident_id,
                metadata={
                    "total_certificates": len(cert_ids),
                    "successful_count": len(successful_renewals),
                    "failed_count": len(failed_renewals),
                    "duration_minutes": (recert_result.completed_at - recert_result.started_at).total_seconds() / 60
                }
            )
            
            return recert_result
            
        except Exception as e:
            logger.error(f"Emergency recertification failed for incident {incident_id}: {e}")
            raise
    
    async def bulk_certificate_renewal(self, 
                                     service_pattern: str = "*.vcc.internal",
                                     cert_type_filter: Optional[str] = None,
                                     dry_run: bool = False) -> BulkRenewalResult:
        """
        Bulk renewal für VCC-Services mit Pattern-Matching
        
        Useful für Policy Updates oder geplante Maintenance-Fenster
        """
        try:
            logger.info(f"Bulk renewal initiated for pattern: {service_pattern}")
            
            # Find matching certificates
            matching_certs = await self._find_certificates_by_pattern(
                service_pattern, cert_type_filter
            )
            
            if dry_run:
                return BulkRenewalResult(
                    dry_run=True,
                    matching_certificates=len(matching_certs),
                    certificate_list=[cert.cert_id for cert in matching_certs]
                )
            
            # Group by priority (critical VCC services first)
            prioritized_certs = await self._prioritize_certificates(matching_certs)
            
            bulk_result = BulkRenewalResult(
                started_at=datetime.utcnow(),
                total_certificates=len(matching_certs)
            )
            
            # Process in batches to avoid overwhelming the system
            batch_size = 10
            
            for batch_start in range(0, len(prioritized_certs), batch_size):
                batch = prioritized_certs[batch_start:batch_start + batch_size]
                
                # Process batch
                batch_tasks = [
                    self.schedule_certificate_renewal(cert.cert_id, RenewalTrigger.SCHEDULED)
                    for cert in batch
                ]
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Track results
                for cert, result in zip(batch, batch_results):
                    if isinstance(result, Exception):
                        bulk_result.failed_renewals.append({
                            "cert_id": cert.cert_id,
                            "error": str(result)
                        })
                    else:
                        bulk_result.successful_renewals.append(result.cert_id)
                
                # Brief pause between batches
                await asyncio.sleep(2)
            
            bulk_result.completed_at = datetime.utcnow()
            
            # Summary notification
            await self.notification_service.send_info_alert(
                subject=f"Bulk Certificate Renewal Completed",
                message=f"Pattern: {service_pattern}\nSuccess: {len(bulk_result.successful_renewals)}\nFailed: {len(bulk_result.failed_renewals)}",
                recipients=await self._get_admin_contacts()
            )
            
            return bulk_result
            
        except Exception as e:
            logger.error(f"Bulk renewal failed for pattern {service_pattern}: {e}")
            raise
    
    async def _execute_renewal_workflow(self, renewal_process: RenewalProcess):
        """
        Complete renewal workflow execution with validation and deployment
        """
        try:
            renewal_process.status = RenewalStatus.IN_PROGRESS
            
            # Step 1: Pre-renewal validation
            if renewal_process.policy and renewal_process.policy.pre_validation_required:
                validation_result = await self._validate_renewal_prerequisites(renewal_process)
                if not validation_result.valid:
                    raise RenewalValidationError(validation_result.errors)
            
            # Step 2: Generate new certificate
            new_certificate = await self._generate_renewed_certificate(renewal_process)
            renewal_process.new_certificate = new_certificate
            
            # Step 3: Test certificate (if possible)
            if renewal_process.policy and renewal_process.policy.post_deployment_validation:
                test_result = await self._test_new_certificate(new_certificate)
                if not test_result.valid:
                    raise CertificateTestError(test_result.errors)
            
            # Step 4: Deploy certificate to VCC services
            deployment_result = await self._deploy_certificate_to_services(
                renewal_process.original_certificate,
                new_certificate
            )
            
            if not deployment_result.success:
                raise CertificateDeploymentError(deployment_result.errors)
            
            # Step 5: Verify deployment success
            verification_result = await self._verify_certificate_deployment(
                new_certificate,
                deployment_result.deployed_services
            )
            
            if verification_result.all_services_verified:
                # Step 6: Revoke old certificate
                await self.pki_service.revoke_certificate(
                    renewal_process.original_certificate.cert_id,
                    reason="superseded"
                )
                
                renewal_process.status = RenewalStatus.COMPLETED
                renewal_process.completed_at = datetime.utcnow()
                
                # Success notification
                await self.notification_service.send_success_notification(
                    subject=f"Certificate Renewal Successful: {renewal_process.cert_id}",
                    message=f"Certificate successfully renewed and deployed to {len(deployment_result.deployed_services)} services",
                    recipients=renewal_process.policy.notification_recipients if renewal_process.policy else []
                )
                
            else:
                raise CertificateVerificationError("Deployment verification failed")
            
            # Cleanup
            if renewal_process.cert_id in self.active_renewals:
                del self.active_renewals[renewal_process.cert_id]
            
        except Exception as e:
            logger.error(f"Renewal workflow failed for {renewal_process.cert_id}: {e}")
            
            # Mark as failed
            renewal_process.status = RenewalStatus.FAILED
            renewal_process.error = str(e)
            renewal_process.completed_at = datetime.utcnow()
            
            # Error notification
            await self.notification_service.send_error_notification(
                subject=f"Certificate Renewal Failed: {renewal_process.cert_id}",
                message=f"Renewal failed: {str(e)}",
                recipients=await self._get_admin_contacts()
            )
            
            # Schedule retry if within policy limits
            if (renewal_process.retry_count < 
                (renewal_process.policy.max_renewal_attempts if renewal_process.policy else 3)):
                
                renewal_process.retry_count += 1
                retry_delay = renewal_process.policy.retry_interval if renewal_process.policy else timedelta(hours=1)
                
                logger.info(f"Scheduling retry #{renewal_process.retry_count} for {renewal_process.cert_id} in {retry_delay}")
                
                await asyncio.sleep(retry_delay.total_seconds())
                await self._execute_renewal_workflow(renewal_process)

    # VCC Service Integration Methods
    
    async def get_vcc_service_certificates(self, service_name: str) -> List[Certificate]:
        """Get all certificates for a specific VCC service"""
        return await self.pki_service.find_certificates(
            service_name=service_name,
            status=CertificateStatus.ACTIVE
        )
    
    async def renew_all_vcc_service_certificates(self, service_name: str) -> ServiceRenewalResult:
        """Renew all certificates for a VCC service (Clara, Covina, etc.)"""
        
        service_certs = await self.get_vcc_service_certificates(service_name)
        
        renewal_tasks = [
            self.schedule_certificate_renewal(cert.cert_id, RenewalTrigger.SERVICE_UPDATE)
            for cert in service_certs
        ]
        
        results = await asyncio.gather(*renewal_tasks, return_exceptions=True)
        
        successful = [r for r in results if not isinstance(r, Exception)]
        failed = [r for r in results if isinstance(r, Exception)]
        
        return ServiceRenewalResult(
            service_name=service_name,
            total_certificates=len(service_certs),
            successful_renewals=len(successful),
            failed_renewals=len(failed),
            renewal_processes=successful
        )
    
    async def update_certificate_template(self, cert_type: str, new_template: CertificateTemplate):
        """
        Update certificate template and trigger renewals for existing certificates
        """
        # Update template
        await self.pki_service.update_certificate_template(cert_type, new_template)
        
        # Find certificates using old template
        affected_certs = await self.pki_service.find_certificates_by_type(cert_type)
        
        # Schedule renewals with policy update trigger
        renewal_tasks = [
            self.schedule_certificate_renewal(cert.cert_id, RenewalTrigger.POLICY_UPDATE)
            for cert in affected_certs
        ]
        
        await asyncio.gather(*renewal_tasks)
        
        logger.info(f"Updated template for {cert_type}, scheduled renewal for {len(affected_certs)} certificates")

    # Background Scheduler
    
    async def _renewal_scheduler_loop(self):
        """Background task for automated renewal scheduling"""
        while True:
            try:
                # Check for certificates approaching expiry
                expiring_certs = await self._find_expiring_certificates()
                
                for cert in expiring_certs:
                    if cert.cert_id not in self.active_renewals:
                        # Check if renewal policy allows auto-renewal
                        policy = self.renewal_policies.get(cert.cert_type)
                        
                        if policy and policy.auto_renewal_enabled:
                            await self.schedule_certificate_renewal(
                                cert.cert_id, 
                                RenewalTrigger.SCHEDULED
                            )
                
                # Sleep for 1 hour before next check
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Renewal scheduler error: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes on error
```

### **2. Certificate Templates & Policies**

```python
# app/models/certificate_templates.py
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import timedelta

@dataclass
class CertificateTemplate:
    """Certificate Template für standardisierte Zertifikatserstellung"""
    
    template_id: str
    name: str
    description: str
    
    # Certificate Properties
    validity_period: timedelta
    key_size: int
    key_type: str = "RSA"  # RSA, ECDSA
    hash_algorithm: str = "SHA256"
    
    # X.509 Extensions
    key_usage: List[str]          # digitalSignature, keyEncipherment, etc.
    extended_key_usage: List[str] # serverAuth, clientAuth, codeSigning, etc.
    subject_alt_names: List[str]  # DNS names, IP addresses, etc.
    
    # VCC-Specific Properties
    vcc_service_type: Optional[str] = None  # clara, covina, argus, etc.
    certificate_purpose: str = "service_auth"  # service_auth, code_signing, admin
    
    # Lifecycle Properties
    auto_renewal_enabled: bool = True
    renewal_threshold_days: int = 30
    emergency_threshold_days: int = 7
    max_renewals: int = 5
    
    # Compliance Properties
    compliance_profiles: List[str] = None  # GDPR, AI_ACT, BSI_TR
    audit_level: str = "standard"  # minimal, standard, enhanced
    
    # Notification Properties
    notification_recipients: List[str] = None
    escalation_recipients: List[str] = None

# Vordefinierte VCC Service Templates
VCC_CERTIFICATE_TEMPLATES = {
    "clara_service_auth": CertificateTemplate(
        template_id="clara_service_auth",
        name="Clara KI Service Authentication",
        description="mTLS Certificates für Clara KI-Processing Services",
        validity_period=timedelta(days=730),  # 2 Jahre
        key_size=2048,
        key_usage=["digitalSignature", "keyEncipherment"],
        extended_key_usage=["serverAuth", "clientAuth"],
        subject_alt_names=["DNS:clara.vcc.internal", "DNS:*.clara.vcc.internal"],
        vcc_service_type="clara",
        auto_renewal_enabled=True,
        renewal_threshold_days=60,  # Frühe Erneuerung wegen Kritikalität
        compliance_profiles=["AI_ACT", "GDPR"],
        audit_level="enhanced"
    ),
    
    "clara_model_signing": CertificateTemplate(
        template_id="clara_model_signing",
        name="Clara KI Model Code Signing",
        description="Code Signing Certificates für Clara LoRa-Adapter",
        validity_period=timedelta(days=1825),  # 5 Jahre
        key_size=4096,
        key_usage=["digitalSignature"],
        extended_key_usage=["codeSigning"],
        vcc_service_type="clara",
        certificate_purpose="code_signing",
        auto_renewal_enabled=False,  # Manuelle Kontrolle für Code Signing
        renewal_threshold_days=90,
        compliance_profiles=["AI_ACT", "GDPR"],
        audit_level="enhanced"
    ),
    
    "covina_orchestrator": CertificateTemplate(
        template_id="covina_orchestrator",
        name="Covina Management Orchestrator",
        description="Service Certificates für Covina Core Management",
        validity_period=timedelta(days=365),  # 1 Jahr
        key_size=2048,
        key_usage=["digitalSignature", "keyEncipherment"],
        extended_key_usage=["serverAuth", "clientAuth"],
        subject_alt_names=["DNS:covina.vcc.internal", "DNS:*.covina.vcc.internal"],
        vcc_service_type="covina",
        auto_renewal_enabled=True,
        renewal_threshold_days=30,
        compliance_profiles=["GDPR"],
        audit_level="standard"
    ),
    
    "argus_api": CertificateTemplate(
        template_id="argus_api",
        name="Argus API Gateway",
        description="API Gateway Certificates für Argus Services",
        validity_period=timedelta(days=730),  # 2 Jahre
        key_size=2048,
        key_usage=["digitalSignature", "keyEncipherment"],
        extended_key_usage=["serverAuth"],
        subject_alt_names=["DNS:argus.vcc.internal", "DNS:api.argus.vcc.internal"],
        vcc_service_type="argus",
        auto_renewal_enabled=True,
        renewal_threshold_days=45,
        compliance_profiles=["GDPR"],
        audit_level="standard"
    ),
    
    "veritas_pipeline": CertificateTemplate(
        template_id="veritas_pipeline",
        name="Veritas Pipeline Authentication",
        description="Pipeline Authentication für Veritas Workflows",
        validity_period=timedelta(days=365),  # 1 Jahr
        key_size=2048,
        key_usage=["digitalSignature", "keyEncipherment"],
        extended_key_usage=["clientAuth"],
        vcc_service_type="veritas",
        auto_renewal_enabled=True,
        renewal_threshold_days=30,
        compliance_profiles=["GDPR"],
        audit_level="standard"
    )
}
```

### **3. Advanced Lifecycle API**

```python
# app/api/v1/certificate_lifecycle.py
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from app.services.certificate_lifecycle import VCCCertificateLifecycleManager
from app.core.security import get_current_user, require_permission

router = APIRouter(prefix="/certificates/lifecycle", tags=["certificate-lifecycle"])

@router.post("/renew/{cert_id}",
             dependencies=[Depends(require_permission("certificate:renew"))])
async def renew_certificate(
    cert_id: str,
    renewal_request: CertificateRenewalRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Schedule certificate renewal
    """
    try:
        renewal_process = await lifecycle_manager.schedule_certificate_renewal(
            cert_id=cert_id,
            renewal_trigger=RenewalTrigger(renewal_request.trigger),
            force_renewal=renewal_request.force
        )
        
        return {
            "renewal_id": renewal_process.renewal_id,
            "cert_id": cert_id,
            "status": renewal_process.status.value,
            "estimated_completion": renewal_process.estimated_completion.isoformat(),
            "trigger": renewal_request.trigger
        }
        
    except Exception as e:
        logger.error(f"Certificate renewal failed: {e}")
        raise HTTPException(500, f"Renewal failed: {str(e)}")

@router.post("/emergency-recertification",
             dependencies=[Depends(require_permission("certificate:emergency"))])
async def emergency_recertification(
    emergency_request: EmergencyRecertificationRequest,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Emergency re-certification bei Sicherheitsvorfällen
    """
    try:
        result = await lifecycle_manager.execute_emergency_recertification(
            cert_ids=emergency_request.certificate_ids,
            incident_id=emergency_request.incident_id,
            reason=emergency_request.reason
        )
        
        return {
            "incident_id": result.incident_id,
            "total_certificates": len(emergency_request.certificate_ids),
            "successful_count": result.successful_count,
            "failed_count": result.failed_count,
            "duration_minutes": (result.completed_at - result.started_at).total_seconds() / 60,
            "status": "completed"
        }
        
    except Exception as e:
        logger.error(f"Emergency recertification failed: {e}")
        raise HTTPException(500, f"Emergency recertification failed: {str(e)}")

@router.post("/bulk-renewal",
             dependencies=[Depends(require_permission("certificate:bulk"))])
async def bulk_certificate_renewal(
    bulk_request: BulkRenewalRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Bulk certificate renewal für VCC services
    """
    try:
        if bulk_request.dry_run:
            # Dry run - show what would be renewed
            result = await lifecycle_manager.bulk_certificate_renewal(
                service_pattern=bulk_request.service_pattern,
                cert_type_filter=bulk_request.cert_type_filter,
                dry_run=True
            )
            
            return {
                "dry_run": True,
                "matching_certificates": result.matching_certificates,
                "certificate_list": result.certificate_list
            }
        else:
            # Execute bulk renewal in background
            background_tasks.add_task(
                lifecycle_manager.bulk_certificate_renewal,
                bulk_request.service_pattern,
                bulk_request.cert_type_filter,
                False
            )
            
            return {
                "message": "Bulk renewal started in background",
                "service_pattern": bulk_request.service_pattern,
                "status": "processing"
            }
        
    except Exception as e:
        logger.error(f"Bulk renewal failed: {e}")
        raise HTTPException(500, f"Bulk renewal failed: {str(e)}")

@router.get("/vcc-service/{service_name}/certificates")
async def get_vcc_service_certificates(
    service_name: str,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Get all certificates for a VCC service
    """
    try:
        certificates = await lifecycle_manager.get_vcc_service_certificates(service_name)
        
        return {
            "service_name": service_name,
            "certificate_count": len(certificates),
            "certificates": [
                {
                    "cert_id": cert.cert_id,
                    "subject": cert.subject,
                    "expires_at": cert.expires_at.isoformat(),
                    "status": cert.status.value,
                    "days_until_expiry": (cert.expires_at - datetime.utcnow()).days
                } for cert in certificates
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get certificates for service {service_name}: {e}")
        raise HTTPException(500, f"Failed to get service certificates: {str(e)}")

@router.post("/vcc-service/{service_name}/renew-all",
             dependencies=[Depends(require_permission("certificate:service:renew"))])
async def renew_all_vcc_service_certificates(
    service_name: str,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Renew all certificates for a VCC service
    """
    try:
        # Execute service renewal in background
        background_tasks.add_task(
            lifecycle_manager.renew_all_vcc_service_certificates,
            service_name
        )
        
        return {
            "message": f"Certificate renewal started for service {service_name}",
            "service_name": service_name,
            "status": "processing"
        }
        
    except Exception as e:
        logger.error(f"Service certificate renewal failed for {service_name}: {e}")
        raise HTTPException(500, f"Service renewal failed: {str(e)}")

@router.get("/expiring")
async def get_expiring_certificates(
    days_ahead: int = 30,
    service_filter: Optional[str] = None,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Get certificates expiring within specified days
    """
    try:
        expiring_certs = await lifecycle_manager._find_expiring_certificates(
            days_ahead=days_ahead,
            service_filter=service_filter
        )
        
        # Group by urgency
        critical = [cert for cert in expiring_certs if (cert.expires_at - datetime.utcnow()).days <= 7]
        warning = [cert for cert in expiring_certs if (cert.expires_at - datetime.utcnow()).days <= 30]
        
        return {
            "total_expiring": len(expiring_certs),
            "critical_count": len(critical),
            "warning_count": len(warning) - len(critical),
            "certificates": {
                "critical": [
                    {
                        "cert_id": cert.cert_id,
                        "subject": cert.subject,
                        "service_name": cert.service_name,
                        "expires_at": cert.expires_at.isoformat(),
                        "days_remaining": (cert.expires_at - datetime.utcnow()).days
                    } for cert in critical
                ],
                "warning": [
                    {
                        "cert_id": cert.cert_id,
                        "subject": cert.subject,
                        "service_name": cert.service_name,
                        "expires_at": cert.expires_at.isoformat(),
                        "days_remaining": (cert.expires_at - datetime.utcnow()).days
                    } for cert in warning if cert not in critical
                ]
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get expiring certificates: {e}")
        raise HTTPException(500, f"Failed to get expiring certificates: {str(e)}")

@router.get("/templates")
async def get_certificate_templates(
    user: User = Depends(get_current_user)
):
    """
    Get available certificate templates
    """
    return {
        "templates": [
            {
                "template_id": template.template_id,
                "name": template.name,
                "description": template.description,
                "validity_period_days": template.validity_period.days,
                "vcc_service_type": template.vcc_service_type,
                "auto_renewal_enabled": template.auto_renewal_enabled,
                "renewal_threshold_days": template.renewal_threshold_days
            } for template in VCC_CERTIFICATE_TEMPLATES.values()
        ]
    }

@router.post("/templates/{template_id}",
             dependencies=[Depends(require_permission("certificate:template:update"))])
async def update_certificate_template(
    template_id: str,
    template_update: CertificateTemplateUpdate,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    lifecycle_manager: VCCCertificateLifecycleManager = Depends(get_lifecycle_manager)
):
    """
    Update certificate template and trigger renewals
    """
    try:
        # Update template in background
        background_tasks.add_task(
            lifecycle_manager.update_certificate_template,
            template_id,
            template_update.to_template()
        )
        
        return {
            "message": f"Template {template_id} update initiated",
            "template_id": template_id,
            "status": "processing"
        }
        
    except Exception as e:
        logger.error(f"Template update failed for {template_id}: {e}")
        raise HTTPException(500, f"Template update failed: {str(e)}")
```

## 📊 **Monitoring & Reporting**

### **Lifecycle Metrics Dashboard**
```python
# Certificate Lifecycle Metrics
certificate_renewals_total = Counter('certificate_renewals_total', 
                                    'Total certificate renewals', 
                                    ['service_name', 'renewal_trigger', 'status'])

certificate_renewal_duration = Histogram('certificate_renewal_duration_seconds', 
                                       'Certificate renewal duration')

certificates_expiring = Gauge('certificates_expiring_count', 
                            'Certificates expiring in N days', 
                            ['days_threshold', 'service_name'])

emergency_recertifications_total = Counter('emergency_recertifications_total', 
                                         'Emergency recertifications', 
                                         ['incident_type'])

certificate_deployment_success_rate = Gauge('certificate_deployment_success_rate', 
                                          'Certificate deployment success rate')

# VCC-spezifische Metrics
clara_model_certificates_active = Gauge('clara_model_certificates_active', 
                                       'Active Clara model signing certificates')

vcc_service_certificate_health = Gauge('vcc_service_certificate_health', 
                                      'VCC service certificate health score', 
                                      ['service_name'])
```

### **Compliance Reporting**
```python
async def generate_certificate_lifecycle_report(period: str = "monthly") -> ComplianceReport:
    """
    Generate comprehensive certificate lifecycle compliance report
    """
    
    report_data = {
        "report_period": period,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_certificates": await get_total_certificate_count(),
            "active_certificates": await get_active_certificate_count(),
            "renewals_completed": await get_renewals_count(period),
            "emergency_recertifications": await get_emergency_recert_count(period),
            "compliance_violations": await get_compliance_violations(period)
        },
        "vcc_service_breakdown": {
            service: await get_service_certificate_stats(service)
            for service in ["clara", "covina", "argus", "veritas", "vpb"]
        },
        "renewal_performance": {
            "success_rate": await calculate_renewal_success_rate(period),
            "average_duration_minutes": await calculate_average_renewal_duration(period),
            "automated_renewals_percentage": await calculate_automation_rate(period)
        },
        "risk_assessment": {
            "expiring_soon": await get_expiring_certificates_count(30),
            "high_risk_certificates": await identify_high_risk_certificates(),
            "compliance_gaps": await identify_compliance_gaps()
        }
    }
    
    return ComplianceReport(**report_data)
```

## 🚀 **Implementation Benefits**

### **Operational Excellence**
- **99.9% Automated Renewal Success Rate** - Minimale manuelle Eingriffe
- **<30 Minuten Emergency Response** - Schnelle Reaktion bei Sicherheitsvorfällen  
- **Zero Downtime Deployments** - Nahtlose Certificate Updates ohne Service-Unterbrechung
- **Comprehensive Audit Trails** - Vollständige Nachverfolgbarkeit aller Lifecycle-Events

### **VCC Service Integration**
- **Clara KI-Model Lifecycle** - Automatische Verwaltung von Code-Signing-Zertifikaten
- **Covina Orchestrator Continuity** - Unterbrechungsfreie Service-Authentication
- **Cross-Service Dependencies** - Koordinierte Renewal-Workflows
- **Service-Specific Policies** - Angepasste Lifecycle-Regeln pro VCC-Service

### **Enterprise Compliance**
- **Automated Policy Enforcement** - Konsistente Anwendung von Security-Policies
- **Regulatory Reporting** - Automatisierte Compliance-Reports für Audits
- **Risk Management** - Proaktive Identifikation und Behandlung von Certificate-Risiken
- **Governance Integration** - Integration in bestehende IT-Governance-Prozesse

Das Certificate Re-certification & Lifecycle Management System stellt sicher, dass alle VCC-Service-Zertifikate automatisch und sicher verwaltet werden, ohne manuelle Eingriffe und mit vollständiger Compliance-Dokumentation! 🔄🚀