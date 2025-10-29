# VCC PKI: Service Integration Examples
## Praktische Implementierungsbeispiele für das VCC-Ecosystem

---

## 🔧 **VCC Service-spezifische PKI-Integration**

### **1. Argus Backend Integration**

#### **FastAPI mTLS Middleware**
```python
# app/middleware/vcc_pki_middleware.py
from fastapi import Request, HTTPException
from app.services.vcc_pki_client import VCCPKIClient

class VCCmTLSMiddleware:
    def __init__(self):
        self.pki_client = VCCPKIClient(service_id="argus", organization="brandenburg")
    
    async def __call__(self, request: Request, call_next):
        # Für sichere API-Endpunkte mTLS erzwingen
        if request.url.path.startswith(("/api/v1/secure/", "/api/v1/management/")):
            client_cert = request.headers.get("X-SSL-Client-Cert")
            
            if not client_cert:
                raise HTTPException(401, "Client certificate required for VCC services")
            
            # VCC-Service-Zertifikat verifizieren
            verification = await self.pki_client.verify_vcc_service_cert(client_cert)
            
            if not verification.valid:
                await self.pki_client.log_security_event(
                    event_type="invalid_client_cert",
                    source_ip=request.client.host,
                    details={"path": request.url.path, "reason": verification.error}
                )
                raise HTTPException(403, "Invalid VCC service certificate")
            
            # Service-Identität in Request-Context speichern
            request.state.vcc_service = verification.service_identity
            request.state.vcc_org = verification.organization
        
        response = await call_next(request)
        return response

# Integration in main.py
app.add_middleware(VCCmTLSMiddleware)
```

#### **Health Service PKI Integration**
```python
# app/services/health.py - Erweitert um PKI-Status
class HealthService:
    def __init__(self, llm_service: ChecklistLLMService, pki_client: VCCPKIClient):
        self._llm_service = llm_service
        self._pki_client = pki_client

    def collect(self) -> HealthStatus:
        components = {"api": ComponentStatus(status="ok")}
        
        # VCC PKI Health Check
        try:
            pki_status = await self._pki_client.health_check()
            components["vcc_pki"] = ComponentStatus(
                status="ok" if pki_status.certificate_valid else "error",
                detail=f"Cert expires: {pki_status.cert_expiry}, CRL status: {pki_status.crl_current}"
            )
        except Exception as exc:
            components["vcc_pki"] = ComponentStatus(status="error", detail=str(exc))
        
        # Bestehende Ollama-Checks...
        
        return HealthStatus(components=components, timestamp=datetime.now(timezone.utc))
```

---

### **2. Covina Management Core Integration**

#### **Worker Authentication**
```python
# management_core/security/worker_auth.py
class VCCWorkerAuthenticator:
    def __init__(self, pki_client: VCCPKIClient):
        self.pki_client = pki_client
    
    async def authenticate_worker(self, worker_module_path: Path, worker_config: dict) -> WorkerAuthResult:
        """Authentifiziert Covina Worker vor der Ausführung"""
        
        # 1. Code-Signatur prüfen
        signature_verification = await self.pki_client.verify_vcc_artifact(
            artifact_path=worker_module_path,
            expected_type="python_package",
            service_context="covina"
        )
        
        if not signature_verification.valid:
            return WorkerAuthResult(
                authenticated=False,
                reason="Invalid or missing code signature",
                worker_id=None
            )
        
        # 2. Worker-spezifische Berechtigungen prüfen
        worker_permissions = worker_config.get("required_permissions", [])
        service_cert = signature_verification.service_certificate
        
        permission_check = await self.pki_client.validate_service_permissions(
            certificate=service_cert,
            requested_permissions=worker_permissions,
            target_service="covina"
        )
        
        if not permission_check.authorized:
            return WorkerAuthResult(
                authenticated=False,
                reason=f"Insufficient permissions: {permission_check.missing_permissions}",
                worker_id=signature_verification.artifact_id
            )
        
        # 3. Audit-Log erstellen
        await self.pki_client.log_worker_execution(
            worker_id=signature_verification.artifact_id,
            service_id="covina",
            permissions_granted=worker_permissions,
            execution_context=worker_config.get("context", {})
        )
        
        return WorkerAuthResult(
            authenticated=True,
            reason="Successfully authenticated",
            worker_id=signature_verification.artifact_id,
            granted_permissions=worker_permissions
        )

# Integration in ManagementCore
class ManagementCore:
    def __init__(self, ..., vcc_pki_client: VCCPKIClient):
        # ...bestehende Initialisierung
        self.worker_auth = VCCWorkerAuthenticator(vcc_pki_client)
    
    async def execute_worker_safely(self, worker_path: Path, config: dict):
        # VCC PKI Worker-Authentifizierung
        auth_result = await self.worker_auth.authenticate_worker(worker_path, config)
        
        if not auth_result.authenticated:
            raise WorkerSecurityException(f"Worker authentication failed: {auth_result.reason}")
        
        # Worker mit verifizierten Berechtigungen ausführen
        return await self._execute_authenticated_worker(worker_path, config, auth_result)
```

#### **UDS3 Backend Security Integration**
```python
# uds3/security/vcc_data_integrity.py
class UDS3VCCSecurityLayer:
    """Sicherheitsschicht für UDS3 Backend mit VCC PKI Integration"""
    
    async def sign_data_operation(self, operation: str, data_hash: str, service_context: str) -> DataSignature:
        """Signiert UDS3-Datenoperationen für Audit-Trail"""
        
        signature = await self.pki_client.sign_data_operation(
            operation_type=operation,  # 'insert', 'update', 'delete', 'query'
            data_fingerprint=data_hash,
            service_id="covina",
            subsystem="uds3",
            context_metadata={"service": service_context}
        )
        
        return DataSignature(
            signature_id=signature.signature_id,
            timestamp=signature.timestamp,
            service_certificate_id=signature.cert_id
        )
    
    async def verify_data_integrity_chain(self, data_record_id: str) -> IntegrityChainResult:
        """Prüft die komplette Integritätskette eines UDS3-Datenrecords"""
        
        # Alle Operationen für diesen Record abrufen
        operations = await self.get_record_operation_history(data_record_id)
        
        integrity_results = []
        for operation in operations:
            verification = await self.pki_client.verify_data_signature(operation.signature_id)
            integrity_results.append({
                "operation": operation.type,
                "timestamp": operation.timestamp,
                "verified": verification.valid,
                "service": verification.service_identity
            })
        
        return IntegrityChainResult(
            record_id=data_record_id,
            chain_intact=all(r["verified"] for r in integrity_results),
            operation_history=integrity_results
        )
```

---

### **3. Clara KI Engine Security Integration**

#### **Model and Adapter Signing**
```python
# clara/security/model_integrity.py
class ClaraModelSecurityManager:
    """Sicherheitsmanager für Clara KI-Modelle und LoRa-Adapter"""
    
    async def sign_lora_adapter(self, adapter_path: Path, model_metadata: dict) -> AdapterSignature:
        """Signiert LoRa-Adapter vor der Bereitstellung"""
        
        # Adapter-Manifest erstellen
        manifest = await self._create_adapter_manifest(adapter_path, model_metadata)
        
        # Mit Clara-spezifischem Zertifikat signieren
        signature = await self.pki_client.sign_vcc_artifact(
            artifact_path=adapter_path,
            artifact_type="lora_adapter",
            service_id="clara",
            metadata={
                "model_version": model_metadata.get("version"),
                "base_model": model_metadata.get("base_model"),
                "training_data_hash": model_metadata.get("data_hash"),
                "performance_metrics": model_metadata.get("metrics", {})
            }
        )
        
        return AdapterSignature(
            adapter_id=signature.artifact_id,
            signature_data=signature.signature_data,
            certificate_id=signature.cert_id,
            manifest_hash=manifest.hash
        )
    
    async def load_verified_adapter(self, adapter_id: str, security_context: dict) -> LoadedAdapter:
        """Lädt und verifiziert LoRa-Adapter mit Just-in-Time-Verifikation"""
        
        # 1. Adapter-Metadaten abrufen
        adapter_info = await self.get_adapter_info(adapter_id)
        
        # 2. Signatur und Zertifikat verifizieren
        verification = await self.pki_client.verify_vcc_artifact(
            artifact_path=adapter_info.path,
            expected_type="lora_adapter",
            service_context="clara"
        )
        
        if not verification.valid:
            await self._log_security_violation(
                event="invalid_adapter_signature",
                adapter_id=adapter_id,
                context=security_context
            )
            raise ModelSecurityException(f"Invalid signature for adapter {adapter_id}")
        
        # 3. Zertifikatsstatus prüfen (CRL/OCSP)
        cert_status = await self.pki_client.check_certificate_status(verification.cert_id)
        if cert_status.revoked:
            raise ModelSecurityException(f"Certificate {verification.cert_id} has been revoked")
        
        # 4. Adapter sicher laden
        adapter = await self._safe_adapter_load(adapter_info.path, verification.manifest)
        
        # 5. Usage-Audit erstellen
        await self.pki_client.log_model_usage(
            model_id=adapter_id,
            service_id="clara",
            usage_type="adapter_loaded",
            context=security_context
        )
        
        return LoadedAdapter(
            adapter=adapter,
            verification_status=verification,
            security_metadata={"verified_at": datetime.utcnow(), "cert_id": verification.cert_id}
        )
```

#### **Training Pipeline Security**
```python
# clara/training/secure_pipeline.py
class SecureTrainingPipeline:
    """Sichere KI-Model-Trainingspipeline mit PKI-Integration"""
    
    async def start_secure_training(self, training_config: TrainingConfig) -> TrainingSession:
        """Startet sicheres Model-Training mit kryptographischer Nachverfolgung"""
        
        # 1. Trainingsdaten-Integrität verifizieren
        data_verification = await self.verify_training_data_integrity(training_config.data_sources)
        
        if not data_verification.valid:
            raise TrainingSecurityException("Training data integrity check failed")
        
        # 2. Training-Session signieren
        session_signature = await self.pki_client.sign_training_session(
            config_hash=training_config.hash,
            data_sources_hash=data_verification.combined_hash,
            service_id="clara",
            trainer_identity=training_config.trainer
        )
        
        # 3. Sicheres Training in isolierter Umgebung
        training_session = TrainingSession(
            session_id=session_signature.session_id,
            config=training_config,
            signature=session_signature,
            isolation_level="high"
        )
        
        return training_session
    
    async def finalize_trained_model(self, session: TrainingSession, model_output: Path) -> SignedModel:
        """Finalisiert und signiert das trainierte Modell"""
        
        # 1. Model-Qualitätsprüfungen
        quality_metrics = await self._run_model_quality_checks(model_output)
        
        # 2. Modell signieren mit Trainingsnachweisen
        model_signature = await self.pki_client.sign_trained_model(
            model_path=model_output,
            training_session_id=session.session_id,
            quality_metrics=quality_metrics,
            service_id="clara"
        )
        
        # 3. Deployment-ready Package erstellen
        signed_package = await self._create_deployment_package(
            model_path=model_output,
            signature=model_signature,
            metadata={
                "training_session": session.session_id,
                "quality_score": quality_metrics.overall_score,
                "data_lineage": session.config.data_sources
            }
        )
        
        return SignedModel(
            model_id=model_signature.model_id,
            package_path=signed_package.path,
            signature=model_signature,
            deployment_ready=True
        )
```

---

### **4. Veritas Pipeline Orchestrator Integration**

#### **Pipeline Job Authentication**
```python
# veritas/security/pipeline_auth.py
class VeritasPipelineSecurityManager:
    """Sicherheitsmanager für Veritas Pipeline-Orchestration"""
    
    async def authenticate_pipeline_job(self, job_config: dict, pipeline_context: str) -> JobAuthResult:
        """Authentifiziert Pipeline-Jobs vor der Ausführung"""
        
        # 1. Job-Konfiguration signieren für Nachverfolgbarkeit
        job_signature = await self.pki_client.sign_pipeline_job(
            job_config=job_config,
            pipeline_id=pipeline_context,
            service_id="veritas"
        )
        
        # 2. Abhängige Services authentifizieren
        required_services = job_config.get("dependencies", [])
        service_auth_results = {}
        
        for service_name in required_services:
            service_cert_status = await self.pki_client.check_vcc_service_status(service_name)
            service_auth_results[service_name] = {
                "authenticated": service_cert_status.valid,
                "certificate_expires": service_cert_status.expires_at,
                "last_seen": service_cert_status.last_health_check
            }
        
        # 3. Pipeline-Berechtigung prüfen
        pipeline_permissions = await self.pki_client.validate_pipeline_permissions(
            pipeline_id=pipeline_context,
            requested_services=required_services,
            job_type=job_config.get("type", "unknown")
        )
        
        return JobAuthResult(
            job_id=job_signature.job_id,
            authenticated=pipeline_permissions.authorized and all(s["authenticated"] for s in service_auth_results.values()),
            service_dependencies=service_auth_results,
            signature=job_signature
        )

# Integration in VeritasPipelineOrchestrator
class VeritasPipelineOrchestrator:
    def __init__(self, ..., pki_client: VCCPKIClient):
        # ...bestehende Initialisierung
        self.security_manager = VeritasPipelineSecurityManager(pki_client)
    
    async def _execute_secure_pipeline_job(self, job_config: dict, pipeline_id: str):
        """Führt Pipeline-Job mit VCC PKI-Sicherheit aus"""
        
        # 1. Job authentifizieren
        auth_result = await self.security_manager.authenticate_pipeline_job(job_config, pipeline_id)
        
        if not auth_result.authenticated:
            logger.error(f"Pipeline job authentication failed: {auth_result}")
            return PipelineResult(success=False, error="Authentication failed")
        
        # 2. Job mit Sicherheitskontext ausführen
        try:
            result = await self._execute_authenticated_job(job_config, auth_result)
            
            # 3. Erfolgreiches Ergebnis signieren
            await self.security_manager.pki_client.sign_job_result(
                job_id=auth_result.job_id,
                result_hash=result.hash,
                success=result.success
            )
            
            return result
            
        except Exception as e:
            # Fehler-Audit erstellen
            await self.security_manager.pki_client.log_job_failure(
                job_id=auth_result.job_id,
                error=str(e),
                pipeline_id=pipeline_id
            )
            raise
```

---

### **5. VPB Visual Processing Integration**

#### **Asset and UI Bundle Signing**
```python
# vpb/security/asset_integrity.py
class VPBAssetSecurityManager:
    """Sicherheitsmanager für VPB Visual Assets und UI-Bundles"""
    
    async def sign_ui_bundle(self, bundle_path: Path, bundle_metadata: dict) -> UIBundleSignature:
        """Signiert UI-Bundles für sichere Bereitstellung"""
        
        # 1. Bundle-Manifest erstellen
        manifest = await self._create_ui_bundle_manifest(bundle_path, bundle_metadata)
        
        # 2. Bundle signieren
        signature = await self.pki_client.sign_vcc_artifact(
            artifact_path=bundle_path,
            artifact_type="ui_bundle",
            service_id="vpb",
            metadata={
                "bundle_version": bundle_metadata.get("version"),
                "target_environment": bundle_metadata.get("environment", "production"),
                "ui_framework": bundle_metadata.get("framework", "unknown"),
                "asset_count": manifest.asset_count
            }
        )
        
        return UIBundleSignature(
            bundle_id=signature.artifact_id,
            signature_data=signature.signature_data,
            manifest=manifest
        )
    
    async def verify_asset_integrity(self, asset_path: Path) -> AssetVerificationResult:
        """Verifiziert Integrität von Visual Assets"""
        
        # 1. Asset-Signatur prüfen
        verification = await self.pki_client.verify_vcc_artifact(
            artifact_path=asset_path,
            expected_type="visual_asset",
            service_context="vpb"
        )
        
        if not verification.valid:
            return AssetVerificationResult(
                verified=False,
                asset_path=asset_path,
                error="Invalid or missing asset signature"
            )
        
        # 2. Asset-Typ validieren (Sicherheitsprüfung gegen schädliche Uploads)
        asset_type_check = await self._validate_asset_type(asset_path, verification.metadata)
        
        return AssetVerificationResult(
            verified=verification.valid and asset_type_check.safe,
            asset_path=asset_path,
            signature_info=verification,
            asset_metadata=asset_type_check.metadata
        )

# Integration in VPB Services
@app.middleware("http") 
async def vpb_asset_security_middleware(request: Request, call_next):
    """Middleware für VPB Asset-Sicherheit"""
    
    # Asset-Upload-Endpunkte absichern
    if request.url.path.startswith("/api/assets/upload"):
        # Client-Zertifikat für Asset-Uploads prüfen
        client_cert = request.headers.get("X-Client-Certificate")
        
        if not client_cert:
            raise HTTPException(401, "Client certificate required for asset uploads")
        
        vpb_pki = VCCPKIClient(service_id="vpb")
        cert_verification = await vpb_pki.verify_client_certificate(client_cert, "asset_upload")
        
        if not cert_verification.valid:
            raise HTTPException(403, "Invalid client certificate for VPB asset upload")
    
    response = await call_next(request)
    return response
```

---

## 🔄 **Cross-Service Integration Examples**

### **Service-zu-Service mTLS Setup**
```python
# shared/vcc_mtls_client.py
class VCCServiceClient:
    """Client für sichere VCC Service-zu-Service-Kommunikation"""
    
    def __init__(self, source_service: str, target_service: str, organization: str = "brandenburg"):
        self.source_service = source_service
        self.target_service = target_service
        self.pki_client = VCCPKIClient(service_id=source_service, organization=organization)
        self.session = self._create_mtls_session()
    
    def _create_mtls_session(self) -> httpx.AsyncClient:
        """Erstellt HTTP-Session mit mTLS-Konfiguration"""
        
        # Service-Zertifikat und Private Key laden
        service_cert, private_key = self.pki_client.get_service_credentials(self.source_service)
        
        # Target-Service CA-Bundle für Verifikation
        ca_bundle = self.pki_client.get_ca_bundle_for_service(self.target_service)
        
        return httpx.AsyncClient(
            cert=(service_cert, private_key),  # Client-Zertifikat
            verify=ca_bundle,  # Server-Zertifikat-Verifikation
            timeout=30.0
        )
    
    async def secure_request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Führt sichere Anfrage an anderen VCC-Service aus"""
        
        # Service-Discovery für Target-Service
        target_url = await self.pki_client.discover_service_endpoint(self.target_service)
        
        if not target_url:
            raise VCCServiceException(f"Service {self.target_service} not discoverable")
        
        full_url = f"{target_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Request mit mTLS ausführen
        response = await self.session.request(method, full_url, **kwargs)
        
        # Response-Signatur verifizieren (falls vorhanden)
        response_signature = response.headers.get("X-VCC-Response-Signature")
        if response_signature:
            signature_valid = await self.pki_client.verify_response_signature(
                response.content, response_signature, self.target_service
            )
            if not signature_valid:
                raise VCCServiceException("Invalid response signature from target service")
        
        return response

# Verwendungsbeispiel: Argus ruft Covina Management Core auf
async def argus_calls_covina_example():
    covina_client = VCCServiceClient(source_service="argus", target_service="covina")
    
    # Sichere Anfrage an Covina Registry
    response = await covina_client.secure_request(
        "GET", 
        "/api/registry/entries",
        params={"filter": "lifecycle_state:active"}
    )
    
    if response.status_code == 200:
        registry_data = response.json()
        return registry_data
    else:
        raise VCCServiceException(f"Covina request failed: {response.status_code}")
```

---

## 📊 **Monitoring Integration**

### **VCC PKI Health Dashboard Integration**
```python
# monitoring/vcc_pki_health.py
class VCCPKIHealthCollector:
    """Sammelt PKI-Gesundheitsdaten für VCC Services"""
    
    async def collect_vcc_pki_metrics(self) -> VCCPKIHealthReport:
        """Sammelt umfassende PKI-Gesundheitsdaten"""
        
        service_health = {}
        
        # Für jeden VCC-Service Zertifikatsstatus prüfen
        for service in ["argus", "covina", "clara", "veritas", "vpb"]:
            try:
                cert_status = await self.pki_client.get_service_certificate_status(service)
                service_health[service] = {
                    "certificate_valid": cert_status.valid,
                    "expires_in_days": (cert_status.expires_at - datetime.utcnow()).days,
                    "last_used": cert_status.last_used,
                    "mtls_connections_active": cert_status.active_connections,
                    "signature_operations_24h": cert_status.daily_signature_count
                }
            except Exception as e:
                service_health[service] = {"error": str(e), "status": "unknown"}
        
        # Globale PKI-Metriken
        global_metrics = await self.pki_client.get_global_metrics()
        
        return VCCPKIHealthReport(
            services=service_health,
            global_metrics=global_metrics,
            timestamp=datetime.utcnow(),
            overall_status=self._calculate_overall_status(service_health)
        )

# Integration in bestehende Health Services
class EnhancedArgusHealthService(HealthService):
    def __init__(self, llm_service, vcc_pki_health: VCCPKIHealthCollector):
        super().__init__(llm_service)
        self.vcc_pki_health = vcc_pki_health
    
    async def collect(self) -> HealthStatus:
        base_status = super().collect()
        
        # VCC PKI Health hinzufügen
        pki_health = await self.vcc_pki_health.collect_vcc_pki_metrics()
        
        base_status.components["vcc_pki_ecosystem"] = ComponentStatus(
            status="ok" if pki_health.overall_status == "healthy" else "degraded",
            detail=f"Services: {len(pki_health.services)} tracked, Issues: {pki_health.issue_count}"
        )
        
        return base_status
```

Diese praktischen Beispiele zeigen die konkrete Integration der VCC PKI in alle identifizierten Services und bieten eine solide Grundlage für die Implementierung.