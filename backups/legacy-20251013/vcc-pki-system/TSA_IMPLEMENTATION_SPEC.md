# VCC PKI System - TSA (Timestamp Authority) Implementation

## 📋 Übersicht

Die **TSA (Timestamp Authority) Integration** erweitert das VCC PKI System um RFC 3161 konforme Zeitstempel-Services für die sichere und rechtssichere Dokumentation von VCC-Service-Operationen.

## 🎯 **Ziele & Anforderungen**

### **Primäre Ziele**
- **Rechtssichere Zeitstempel** für alle kritischen VCC-Operationen
- **RFC 3161 Compliance** für internationale Interoperabilität
- **VCC-Service Integration** für nahtlose Nutzung in bestehenden Workflows
- **Audit-Trail Enhancement** mit verifizierbaren Zeitstempeln

### **Compliance Anforderungen**
- **eIDAS Regulation** (EU) No 910/2014 - Qualifizierte Zeitstempel
- **RFC 3161** - Time-Stamp Protocol (TSP)
- **BSI TR-03109** - Anforderungen an Zeitstempeldienste
- **EU AI Act** - Zeitstempel für KI-System-Outputs (Clara)

## 🏗️ **Architektur**

### **TSA Service Components**
```
┌─────────────────────────────────────────────────┐
│                VCC PKI System                   │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────┐ │
│  │    TSA      │  │   TSA-CA     │  │   HSM   │ │
│  │  Service    │◄─►│ Certificate  │◄─►│ Storage │ │
│  │             │  │  Management  │  │         │ │
│  └─────────────┘  └──────────────┘  └─────────┘ │
│         │                                       │
│  ┌─────────────┐  ┌──────────────┐              │
│  │ Timestamp   │  │   Audit &    │              │
│  │ Verification│  │   Logging    │              │
│  │   Service   │  │   Service    │              │
│  └─────────────┘  └──────────────┘              │
├─────────────────────────────────────────────────┤
│              VCC Service Integration             │
│   Clara │ Covina │ Argus │ Veritas │ VPB       │
└─────────────────────────────────────────────────┘
```

### **TSA Certificate Hierarchy**
```
VCC Root CA
    │
    ├── VCC Issuing CA (Services)
    │
    └── VCC TSA CA (Timestamping)
            │
            ├── TSA-Service-001.vcc.internal
            ├── TSA-Service-002.vcc.internal (Backup)
            └── TSA-Archive.vcc.internal (Archivierung)
```

## 🔧 **Implementation Spezifikation**

### **1. TSA Core Service**

```python
# app/services/tsa_service.py
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import asn1crypto.tsp
from datetime import datetime, timezone
import hashlib
from typing import Optional, Tuple

class VCCTSAService:
    """RFC 3161 konforme Timestamp Authority für VCC PKI System"""
    
    def __init__(self, tsa_cert_path: str, tsa_key_path: str, 
                 policy_oid: str = "1.3.6.1.4.1.55555.1"):
        self.tsa_certificate = self._load_certificate(tsa_cert_path)
        self.tsa_private_key = self._load_private_key(tsa_key_path)
        self.policy_oid = policy_oid
        self.serial_number_counter = 1
        
    async def create_timestamp_token(self, 
                                   timestamp_request: bytes) -> Tuple[bytes, str]:
        """
        RFC 3161 Timestamp Token Creation
        
        Args:
            timestamp_request: DER-encoded TSRequest
            
        Returns:
            Tuple[timestamp_response_bytes, timestamp_token_id]
        """
        try:
            # Parse TSRequest
            ts_request = asn1crypto.tsp.TSARequest.load(timestamp_request)
            
            # Validate request
            validation_result = await self._validate_timestamp_request(ts_request)
            if not validation_result.valid:
                return await self._create_error_response(validation_result.error_code)
            
            # Generate timestamp
            timestamp = datetime.now(timezone.utc)
            serial_number = await self._get_next_serial_number()
            
            # Create TSToken
            ts_token = await self._create_timestamp_token(
                ts_request=ts_request,
                timestamp=timestamp,
                serial_number=serial_number
            )
            
            # Create TSResponse
            ts_response = asn1crypto.tsp.TSAResponse({
                'status': {
                    'status': 'granted',
                    'status_string': 'Timestamp created successfully'
                },
                'time_stamp_token': ts_token
            })
            
            # Log timestamp creation
            token_id = f"TSA-{serial_number:08d}"
            await self._audit_timestamp_creation(
                token_id=token_id,
                request_hash=ts_request['message_imprint']['hashed_message'].native.hex(),
                timestamp=timestamp
            )
            
            return ts_response.dump(), token_id
            
        except Exception as e:
            logger.error(f"Timestamp creation failed: {e}")
            return await self._create_error_response("systemFailure")
    
    async def verify_timestamp_token(self, 
                                   timestamp_token: bytes,
                                   original_data: bytes) -> TimestampVerificationResult:
        """
        Verify RFC 3161 Timestamp Token
        
        Args:
            timestamp_token: DER-encoded timestamp token
            original_data: Original data that was timestamped
            
        Returns:
            TimestampVerificationResult with verification status
        """
        try:
            # Parse timestamp token
            ts_token = asn1crypto.cms.ContentInfo.load(timestamp_token)
            
            # Verify signature
            signature_valid = await self._verify_token_signature(ts_token)
            
            # Verify certificate chain
            cert_chain_valid = await self._verify_certificate_chain(ts_token)
            
            # Verify message imprint
            message_imprint_valid = await self._verify_message_imprint(
                ts_token, original_data
            )
            
            # Extract timestamp info
            timestamp_info = await self._extract_timestamp_info(ts_token)
            
            return TimestampVerificationResult(
                valid=signature_valid and cert_chain_valid and message_imprint_valid,
                timestamp=timestamp_info.gen_time,
                serial_number=timestamp_info.serial_number,
                policy_oid=timestamp_info.policy,
                tsa_certificate=timestamp_info.tsa_cert,
                hash_algorithm=timestamp_info.hash_algorithm,
                message_imprint=timestamp_info.message_imprint
            )
            
        except Exception as e:
            logger.error(f"Timestamp verification failed: {e}")
            return TimestampVerificationResult(
                valid=False,
                error=str(e)
            )

    # VCC-spezifische Timestamp-Methoden
    
    async def timestamp_vcc_operation(self, 
                                    service_name: str,
                                    operation_type: str,
                                    data_hash: str,
                                    metadata: dict = None) -> VCCTimestampResult:
        """
        VCC-Service spezifische Zeitstempel-Erstellung
        
        Args:
            service_name: VCC Service (clara, covina, argus, etc.)
            operation_type: Art der Operation (model_training, workflow_execution, etc.)
            data_hash: SHA-256 Hash der zu zeitstempelnden Daten
            metadata: Zusätzliche VCC-spezifische Metadaten
        """
        
        # Create extended TSRequest with VCC metadata
        vcc_metadata = {
            "vcc_service": service_name,
            "operation_type": operation_type,
            "metadata": metadata or {},
            "vcc_version": "1.0",
            "compliance_context": {
                "gdpr_basis": "legitimate_interest",
                "ai_act_applicable": service_name == "clara"
            }
        }
        
        # Standard RFC 3161 Request
        message_imprint = await self._create_message_imprint(
            bytes.fromhex(data_hash), "sha256"
        )
        
        ts_request = asn1crypto.tsp.TSARequest({
            'version': 1,
            'message_imprint': message_imprint,
            'req_policy': self.policy_oid,
            'nonce': os.urandom(8),
            'cert_req': True,
            'extensions': await self._create_vcc_extensions(vcc_metadata)
        })
        
        # Create timestamp
        ts_response_bytes, token_id = await self.create_timestamp_token(
            ts_request.dump()
        )
        
        return VCCTimestampResult(
            token_id=token_id,
            timestamp_token=ts_response_bytes,
            vcc_metadata=vcc_metadata,
            service_name=service_name,
            operation_type=operation_type
        )

    async def bulk_timestamp_clara_models(self, 
                                        model_artifacts: List[ClaraModelArtifact]) -> List[VCCTimestampResult]:
        """
        Bulk Timestamping für Clara KI-Modelle und LoRa-Adapter
        
        Optimiert für große Mengen von KI-Modell-Artifacts
        """
        results = []
        
        for artifact in model_artifacts:
            try:
                # Model-spezifische Metadaten
                metadata = {
                    "model_type": artifact.model_type,
                    "adapter_version": artifact.adapter_version,
                    "training_dataset_hash": artifact.dataset_hash,
                    "model_performance": artifact.performance_metrics,
                    "ai_act_risk_level": artifact.risk_assessment
                }
                
                timestamp_result = await self.timestamp_vcc_operation(
                    service_name="clara",
                    operation_type="model_finalization",
                    data_hash=artifact.model_hash,
                    metadata=metadata
                )
                
                results.append(timestamp_result)
                
            except Exception as e:
                logger.error(f"Clara model timestamping failed for {artifact.model_id}: {e}")
                results.append(VCCTimestampResult(
                    error=str(e),
                    model_id=artifact.model_id
                ))
        
        return results
```

### **2. TSA API Endpoints**

```python
# app/api/v1/tsa.py
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from app.services.tsa_service import VCCTSAService
from app.core.security import get_current_user, require_permission

router = APIRouter(prefix="/tsa", tags=["timestamp"])

@router.post("/timestamp", 
             summary="RFC 3161 Timestamp Request",
             response_class=Response)
async def create_timestamp(
    request: Request,
    tsa_service: VCCTSAService = Depends(get_tsa_service)
):
    """
    Standard RFC 3161 Timestamp Request/Response Endpoint
    
    Content-Type: application/timestamp-query
    Response: application/timestamp-reply
    """
    try:
        # Read raw TSRequest
        timestamp_request = await request.body()
        
        # Validate content type
        if request.headers.get("content-type") != "application/timestamp-query":
            raise HTTPException(400, "Invalid content type")
        
        # Create timestamp
        timestamp_response, token_id = await tsa_service.create_timestamp_token(
            timestamp_request
        )
        
        return Response(
            content=timestamp_response,
            media_type="application/timestamp-reply",
            headers={
                "X-Timestamp-Token-ID": token_id,
                "X-TSA-Service": "VCC-TSA-v1.0"
            }
        )
        
    except Exception as e:
        logger.error(f"TSA timestamp creation failed: {e}")
        raise HTTPException(500, "Timestamp service error")

@router.post("/vcc/timestamp",
             dependencies=[Depends(require_permission("tsa:create"))])
async def create_vcc_timestamp(
    request: VCCTimestampRequest,
    user: User = Depends(get_current_user),
    tsa_service: VCCTSAService = Depends(get_tsa_service)
):
    """
    VCC-spezifische Timestamp-Erstellung mit erweiterten Metadaten
    """
    try:
        result = await tsa_service.timestamp_vcc_operation(
            service_name=request.service_name,
            operation_type=request.operation_type,
            data_hash=request.data_hash,
            metadata=request.metadata
        )
        
        return {
            "token_id": result.token_id,
            "timestamp_token_b64": base64.b64encode(result.timestamp_token).decode(),
            "service_name": result.service_name,
            "operation_type": result.operation_type,
            "created_at": result.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"VCC timestamp creation failed: {e}")
        raise HTTPException(500, "VCC timestamp service error")

@router.post("/verify")
async def verify_timestamp(
    verification_request: TimestampVerificationRequest,
    tsa_service: VCCTSAService = Depends(get_tsa_service)
):
    """
    Timestamp Token Verification
    """
    try:
        timestamp_token = base64.b64decode(verification_request.timestamp_token_b64)
        original_data = base64.b64decode(verification_request.original_data_b64)
        
        result = await tsa_service.verify_timestamp_token(
            timestamp_token=timestamp_token,
            original_data=original_data
        )
        
        return {
            "valid": result.valid,
            "timestamp": result.timestamp.isoformat() if result.timestamp else None,
            "serial_number": result.serial_number,
            "policy_oid": result.policy_oid,
            "hash_algorithm": result.hash_algorithm,
            "error": result.error
        }
        
    except Exception as e:
        logger.error(f"Timestamp verification failed: {e}")
        raise HTTPException(500, "Timestamp verification error")

@router.post("/clara/bulk-timestamp",
             dependencies=[Depends(require_permission("tsa:clara:bulk"))])
async def bulk_timestamp_clara_models(
    models: List[ClaraModelTimestampRequest],
    user: User = Depends(get_current_user),
    tsa_service: VCCTSAService = Depends(get_tsa_service)
):
    """
    Bulk Timestamping für Clara KI-Modelle
    """
    try:
        model_artifacts = [
            ClaraModelArtifact.from_request(model) for model in models
        ]
        
        results = await tsa_service.bulk_timestamp_clara_models(model_artifacts)
        
        return {
            "processed_count": len(results),
            "successful_count": len([r for r in results if not r.error]),
            "results": [
                {
                    "model_id": r.model_id,
                    "token_id": r.token_id,
                    "success": not bool(r.error),
                    "error": r.error
                } for r in results
            ]
        }
        
    except Exception as e:
        logger.error(f"Clara bulk timestamping failed: {e}")
        raise HTTPException(500, "Clara bulk timestamping error")

@router.get("/certificate")
async def get_tsa_certificate(
    tsa_service: VCCTSAService = Depends(get_tsa_service)
):
    """
    TSA Certificate Download für Client-seitige Verifikation
    """
    try:
        tsa_cert = await tsa_service.get_tsa_certificate()
        
        return Response(
            content=tsa_cert.public_bytes(serialization.Encoding.PEM),
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": "attachment; filename=vcc-tsa.pem"
            }
        )
        
    except Exception as e:
        logger.error(f"TSA certificate retrieval failed: {e}")
        raise HTTPException(500, "TSA certificate error")
```

### **3. Database Schema Extensions**

```sql
-- TSA-spezifische Tabellen
CREATE TABLE tsa_certificates (
    cert_id TEXT PRIMARY KEY,
    tsa_service_name TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_reference TEXT, -- HSM Key Reference
    policy_oid TEXT NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    serial_number_counter INTEGER DEFAULT 1,
    status TEXT CHECK (status IN ('active', 'revoked', 'expired')) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE timestamp_tokens (
    token_id TEXT PRIMARY KEY,
    serial_number INTEGER NOT NULL,
    tsa_cert_id TEXT REFERENCES tsa_certificates(cert_id),
    message_imprint_hash TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL,
    timestamp_utc TIMESTAMP NOT NULL,
    policy_oid TEXT NOT NULL,
    
    -- VCC-spezifische Felder
    vcc_service_name TEXT, -- 'clara', 'covina', etc.
    operation_type TEXT,   -- 'model_training', 'workflow_execution', etc.
    vcc_metadata TEXT,     -- JSON mit VCC-spezifischen Daten
    
    -- Compliance & Audit
    requester_user_id TEXT,
    requester_service TEXT,
    compliance_context TEXT, -- JSON mit GDPR/AI-Act Kontext
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(tsa_cert_id, serial_number)
);

CREATE INDEX idx_timestamp_tokens_service ON timestamp_tokens(vcc_service_name);
CREATE INDEX idx_timestamp_tokens_timestamp ON timestamp_tokens(timestamp_utc);
CREATE INDEX idx_timestamp_tokens_hash ON timestamp_tokens(message_imprint_hash);

-- Timestamp Verification Log
CREATE TABLE timestamp_verifications (
    verification_id TEXT PRIMARY KEY,
    token_id TEXT REFERENCES timestamp_tokens(token_id),
    verification_result BOOLEAN NOT NULL,
    verification_timestamp TIMESTAMP NOT NULL,
    verifier_service TEXT,
    error_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔗 **VCC Service Integration**

### **Clara KI-Model Integration**

```python
# Beispiel: Clara LoRa-Adapter Timestamping
async def finalize_clara_model(model_path: str, adapter_config: dict):
    """Clara Model Finalization mit TSA Integration"""
    
    # 1. Model Training abgeschlossen
    model_hash = calculate_model_hash(model_path)
    
    # 2. TSA Timestamp erstellen
    tsa_client = VCCTSAClient()
    timestamp_result = await tsa_client.timestamp_vcc_operation(
        service_name="clara",
        operation_type="model_finalization",
        data_hash=model_hash,
        metadata={
            "adapter_type": adapter_config["type"],
            "training_dataset": adapter_config["dataset_id"],
            "model_version": adapter_config["version"],
            "ai_act_risk_level": "high_risk"
        }
    )
    
    # 3. Model + Timestamp archivieren
    await archive_model_with_timestamp(
        model_path=model_path,
        timestamp_token=timestamp_result.timestamp_token,
        metadata=timestamp_result.vcc_metadata
    )
    
    return {
        "model_id": generate_model_id(),
        "model_hash": model_hash,
        "timestamp_token_id": timestamp_result.token_id,
        "finalized_at": timestamp_result.timestamp
    }
```

### **Covina Workflow Integration**

```python
# Beispiel: Covina Workflow Timestamping
async def complete_covina_workflow(workflow_id: str, results: dict):
    """Covina Workflow Completion mit Timestamping"""
    
    # 1. Workflow Results hashen
    results_hash = hashlib.sha256(
        json.dumps(results, sort_keys=True).encode()
    ).hexdigest()
    
    # 2. Timestamp erstellen
    tsa_client = VCCTSAClient()
    timestamp_result = await tsa_client.timestamp_vcc_operation(
        service_name="covina",
        operation_type="workflow_completion",
        data_hash=results_hash,
        metadata={
            "workflow_id": workflow_id,
            "worker_count": len(results.get("workers", [])),
            "execution_time_ms": results.get("execution_time"),
            "success_rate": results.get("success_rate")
        }
    )
    
    # 3. Workflow Results mit Timestamp persistieren
    await store_workflow_results(
        workflow_id=workflow_id,
        results=results,
        timestamp_token=timestamp_result.timestamp_token,
        completed_at=timestamp_result.timestamp
    )
```

## 📊 **Monitoring & Metrics**

### **TSA Health Metrics**
```python
# Prometheus Metrics für TSA Service
tsa_requests_total = Counter('tsa_requests_total', 'Total TSA requests', ['service_name', 'operation_type'])
tsa_request_duration = Histogram('tsa_request_duration_seconds', 'TSA request duration')
tsa_certificate_expiry_days = Gauge('tsa_certificate_expiry_days', 'Days until TSA certificate expires')
tsa_serial_number_usage = Gauge('tsa_serial_number_current', 'Current TSA serial number')

# VCC-spezifische Metrics  
clara_model_timestamps_total = Counter('clara_model_timestamps_total', 'Clara model timestamps created')
covina_workflow_timestamps_total = Counter('covina_workflow_timestamps_total', 'Covina workflow timestamps')
timestamp_verification_success_rate = Gauge('timestamp_verification_success_rate', 'TSA verification success rate')
```

### **Alert Thresholds**
```yaml
tsa_alerts:
  certificate_expiry_warning: "30 days"
  certificate_expiry_critical: "7 days"
  request_failure_rate_warning: "5%"
  request_failure_rate_critical: "10%"
  serial_number_exhaustion_warning: "90%"
  verification_failure_rate_critical: "1%"
```

## 🔒 **Security Considerations**

### **TSA Private Key Protection**
- **HSM Storage**: TSA Private Keys ausschließlich in Hardware Security Modules
- **Key Ceremony**: Multi-Person Authorization für TSA Key Operations
- **Key Rotation**: Jährliche TSA Certificate Renewal mit neuen Keys
- **Backup Strategy**: Encrypted Offsite Storage der TSA Key Backups

### **Timestamp Security**
- **Clock Synchronization**: NTP-synchronisierte Zeit mit Stratum-1 Referenz
- **Timestamp Precision**: Mikrosekunden-Genauigkeit für forensische Zwecke
- **Archive Security**: Langfristige Archivierung der Timestamp Tokens
- **Audit Trail**: Vollständige Protokollierung aller TSA-Operationen

## 📈 **Implementation Roadmap**

### **Phase 1: TSA Core (Woche 1-2)**
- [ ] RFC 3161 TSA Service Implementation
- [ ] Database Schema Extensions
- [ ] Basic API Endpoints
- [ ] HSM Integration für TSA Keys

### **Phase 2: VCC Integration (Woche 3-4)**
- [ ] VCC-spezifische Timestamp Methoden
- [ ] Clara KI-Model Integration
- [ ] Covina Workflow Integration
- [ ] Bulk Operations für Performance

### **Phase 3: Monitoring & Operations (Woche 5)**
- [ ] Health Monitoring & Alerting
- [ ] Performance Optimization
- [ ] Security Hardening
- [ ] Documentation & Training

### **Phase 4: Production Deployment (Woche 6)**
- [ ] Production Environment Setup
- [ ] Load Testing & Performance Validation
- [ ] Disaster Recovery Testing
- [ ] Go-Live & Monitoring

## ✅ **Acceptance Criteria**

### **Functional Requirements**
- ✅ RFC 3161 konforme Timestamp Token Erstellung
- ✅ VCC-Service Integration (Clara, Covina, Argus, Veritas, VPB)
- ✅ Bulk Operations für große Datenmengen
- ✅ Timestamp Verification mit Original-Daten
- ✅ HSM-geschützte TSA Private Keys

### **Non-Functional Requirements**
- ✅ <200ms Response Zeit für Standard Timestamps
- ✅ <5s für Bulk Operations (100 Timestamps)
- ✅ >99.9% TSA Service Verfügbarkeit
- ✅ Skalierung auf >10.000 Timestamps/Tag
- ✅ Vollständige Audit-Trail Compliance

### **Security Requirements**
- ✅ HSM-basierte TSA Certificate Storage
- ✅ Encrypted-at-Rest für alle Timestamp Data
- ✅ Role-based Access Control für TSA Operations
- ✅ Forensic-grade Logging und Monitoring
- ✅ BSI IT-Grundschutz konforme Implementation

Das TSA System erweitert das VCC PKI System um rechtssichere Zeitstempel-Funktionalität und ermöglicht die vollständige Nachverfolgbarkeit und Compliance aller kritischen VCC-Service-Operationen! 🚀