#!/usr/bin/env python3
"""
VCC PKI Server - Certificate Templates Module (Phase 2)
========================================================

Policy-based certificate templates for standardized certificate issuance.

Features:
- YAML/JSON-based template definitions
- Variable substitution
- Template inheritance
- Policy enforcement
- Pre-defined VCC templates
- Custom extension support

Author: VCC Team
Date: November 2025
"""

import os
import sys
import json
import logging
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from copy import deepcopy
import yaml

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class KeyUsageFlags(str, Enum):
    """X.509 Key Usage flags"""
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_ENCIPHERMENT = "key_encipherment"
    CONTENT_COMMITMENT = "content_commitment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


class ExtendedKeyUsage(str, Enum):
    """X.509 Extended Key Usage OIDs"""
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth"
    CODE_SIGNING = "code_signing"
    EMAIL_PROTECTION = "email_protection"
    TIME_STAMPING = "time_stamping"
    OCSP_SIGNING = "ocsp_signing"


class TemplateType(str, Enum):
    """Certificate template types"""
    SERVICE = "service"
    CODE_SIGNING = "code_signing"
    TLS_SERVER = "tls_server"
    TLS_CLIENT = "tls_client"
    ADMIN = "admin"
    CA = "ca"
    TSA = "tsa"
    OCSP = "ocsp"
    CUSTOM = "custom"


@dataclass
class TemplateConfig:
    """Template configuration"""
    templates_path: str = "../templates"
    auto_load: bool = True
    strict_validation: bool = True
    
    @classmethod
    def from_env(cls) -> "TemplateConfig":
        """Create config from environment variables"""
        return cls(
            templates_path=os.getenv("VCC_TEMPLATES_PATH", "../templates"),
            auto_load=os.getenv("VCC_TEMPLATES_AUTO_LOAD", "true").lower() == "true",
            strict_validation=os.getenv("VCC_TEMPLATES_STRICT_VALIDATION", "true").lower() == "true"
        )


@dataclass
class SubjectConfig:
    """Certificate subject configuration"""
    country: Optional[str] = "DE"
    state: Optional[str] = "Brandenburg"
    locality: Optional[str] = None
    organization: Optional[str] = "VCC - Veritas Control Center"
    organizational_unit: Optional[str] = None
    common_name: Optional[str] = None  # Can use variables like ${service_name}
    email: Optional[str] = None


@dataclass
class KeyUsageConfig:
    """Key usage configuration"""
    digital_signature: bool = False
    key_encipherment: bool = False
    content_commitment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False
    critical: bool = True


@dataclass
class ExtendedKeyUsageConfig:
    """Extended key usage configuration"""
    usages: List[ExtendedKeyUsage] = field(default_factory=list)
    critical: bool = False


@dataclass
class ValidityConfig:
    """Certificate validity configuration"""
    days: int = 365
    max_days: int = 730
    min_days: int = 1
    renewable: bool = True
    renewal_threshold_days: int = 30


@dataclass
class SANConfig:
    """Subject Alternative Names configuration"""
    dns_names: List[str] = field(default_factory=list)  # Can use variables
    ip_addresses: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    uris: List[str] = field(default_factory=list)


@dataclass
class PolicyConfig:
    """Certificate policy configuration"""
    policy_oid: Optional[str] = None
    cps_uri: Optional[str] = None
    user_notice: Optional[str] = None


@dataclass
class CertificateTemplate:
    """Certificate template definition"""
    template_id: str
    template_name: str
    template_type: TemplateType
    description: str = ""
    version: str = "1.0"
    
    # Inheritance
    parent_template: Optional[str] = None
    
    # Subject
    subject: SubjectConfig = field(default_factory=SubjectConfig)
    
    # Key settings
    key_algorithm: str = "rsa"
    key_size: int = 4096
    
    # Extensions
    key_usage: KeyUsageConfig = field(default_factory=KeyUsageConfig)
    extended_key_usage: ExtendedKeyUsageConfig = field(default_factory=ExtendedKeyUsageConfig)
    basic_constraints_ca: bool = False
    basic_constraints_path_length: Optional[int] = None
    
    # Validity
    validity: ValidityConfig = field(default_factory=ValidityConfig)
    
    # SANs
    san: SANConfig = field(default_factory=SANConfig)
    
    # Policy
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    
    # Custom extensions
    custom_extensions: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "system"
    tags: List[str] = field(default_factory=list)


# ============================================================================
# Template Manager
# ============================================================================

class CertificateTemplateManager:
    """
    Manages certificate templates for policy-based certificate issuance.
    
    Features:
    - Load templates from YAML/JSON files
    - Template inheritance
    - Variable substitution
    - Validation and enforcement
    """
    
    def __init__(self, config: TemplateConfig):
        self.config = config
        self._templates: Dict[str, CertificateTemplate] = {}
        self._templates_path = Path(config.templates_path)
        self._templates_path.mkdir(parents=True, exist_ok=True)
        
        # Load pre-defined templates
        self._load_predefined_templates()
        
        # Load custom templates from disk
        if config.auto_load:
            self._load_templates_from_disk()
        
        logger.info(f"✅ Certificate Template Manager initialized with {len(self._templates)} templates")
    
    def _load_predefined_templates(self) -> None:
        """Load pre-defined VCC templates"""
        
        # VCC Service Certificate Template
        self._templates["vcc-service"] = CertificateTemplate(
            template_id="vcc-service",
            template_name="VCC Service Certificate",
            template_type=TemplateType.SERVICE,
            description="Standard certificate for VCC microservices (mTLS)",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Services",
                common_name="${service_name}.vcc.local"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                key_encipherment=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[ExtendedKeyUsage.SERVER_AUTH, ExtendedKeyUsage.CLIENT_AUTH],
                critical=False
            ),
            validity=ValidityConfig(
                days=365,
                max_days=730,
                renewable=True,
                renewal_threshold_days=30
            ),
            san=SANConfig(
                dns_names=["${service_name}.vcc.local", "${service_name}"],
                ip_addresses=["127.0.0.1"]
            ),
            tags=["vcc", "service", "mtls"]
        )
        
        # Code Signing Template
        self._templates["vcc-code-signing"] = CertificateTemplate(
            template_id="vcc-code-signing",
            template_name="VCC Code Signing Certificate",
            template_type=TemplateType.CODE_SIGNING,
            description="Certificate for signing VCC code artifacts",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Code Signing",
                common_name="${signer_name} Code Signing"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                content_commitment=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[ExtendedKeyUsage.CODE_SIGNING],
                critical=True
            ),
            validity=ValidityConfig(
                days=365,
                max_days=1095,
                renewable=True,
                renewal_threshold_days=60
            ),
            tags=["vcc", "code-signing"]
        )
        
        # Clara Model Signing Template
        self._templates["vcc-clara-model"] = CertificateTemplate(
            template_id="vcc-clara-model",
            template_name="Clara Model Signing Certificate",
            template_type=TemplateType.CODE_SIGNING,
            description="Certificate for signing Clara AI models and LoRa adapters",
            parent_template="vcc-code-signing",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Clara AI",
                common_name="${model_name} Model Signing"
            ),
            validity=ValidityConfig(
                days=730,
                max_days=1095,
                renewable=True,
                renewal_threshold_days=90
            ),
            tags=["vcc", "clara", "ai", "model-signing"]
        )
        
        # TLS Server Template
        self._templates["vcc-tls-server"] = CertificateTemplate(
            template_id="vcc-tls-server",
            template_name="VCC TLS Server Certificate",
            template_type=TemplateType.TLS_SERVER,
            description="Certificate for TLS server authentication",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Infrastructure",
                common_name="${server_name}"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                key_encipherment=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[ExtendedKeyUsage.SERVER_AUTH],
                critical=False
            ),
            validity=ValidityConfig(
                days=365,
                max_days=730,
                renewable=True,
                renewal_threshold_days=30
            ),
            san=SANConfig(
                dns_names=["${server_name}"]
            ),
            tags=["vcc", "tls", "server"]
        )
        
        # TLS Client Template
        self._templates["vcc-tls-client"] = CertificateTemplate(
            template_id="vcc-tls-client",
            template_name="VCC TLS Client Certificate",
            template_type=TemplateType.TLS_CLIENT,
            description="Certificate for TLS client authentication",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Users",
                common_name="${client_name}"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                key_encipherment=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[ExtendedKeyUsage.CLIENT_AUTH],
                critical=False
            ),
            validity=ValidityConfig(
                days=365,
                max_days=730,
                renewable=True,
                renewal_threshold_days=30
            ),
            tags=["vcc", "tls", "client"]
        )
        
        # Admin Certificate Template
        self._templates["vcc-admin"] = CertificateTemplate(
            template_id="vcc-admin",
            template_name="VCC Admin Certificate",
            template_type=TemplateType.ADMIN,
            description="Certificate for VCC administrators",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Administrators",
                common_name="${admin_name}"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[
                    ExtendedKeyUsage.CLIENT_AUTH,
                    ExtendedKeyUsage.CODE_SIGNING,
                    ExtendedKeyUsage.EMAIL_PROTECTION
                ],
                critical=False
            ),
            validity=ValidityConfig(
                days=365,
                max_days=365,
                renewable=True,
                renewal_threshold_days=30
            ),
            tags=["vcc", "admin"]
        )
        
        # TSA Certificate Template
        self._templates["vcc-tsa"] = CertificateTemplate(
            template_id="vcc-tsa",
            template_name="VCC TSA Certificate",
            template_type=TemplateType.TSA,
            description="Certificate for Timestamp Authority",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="Timestamp Authority",
                common_name="VCC Timestamp Authority"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                content_commitment=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[ExtendedKeyUsage.TIME_STAMPING],
                critical=True
            ),
            validity=ValidityConfig(
                days=3650,
                max_days=3650,
                renewable=True,
                renewal_threshold_days=365
            ),
            tags=["vcc", "tsa", "timestamp"]
        )
        
        # OCSP Responder Certificate Template
        self._templates["vcc-ocsp"] = CertificateTemplate(
            template_id="vcc-ocsp",
            template_name="VCC OCSP Responder Certificate",
            template_type=TemplateType.OCSP,
            description="Certificate for OCSP Responder",
            subject=SubjectConfig(
                organization="VCC - Veritas Control Center",
                organizational_unit="OCSP",
                common_name="VCC OCSP Responder"
            ),
            key_algorithm="rsa",
            key_size=4096,
            key_usage=KeyUsageConfig(
                digital_signature=True,
                critical=True
            ),
            extended_key_usage=ExtendedKeyUsageConfig(
                usages=[ExtendedKeyUsage.OCSP_SIGNING],
                critical=True
            ),
            validity=ValidityConfig(
                days=365,
                max_days=730,
                renewable=True,
                renewal_threshold_days=30
            ),
            tags=["vcc", "ocsp"]
        )
        
        logger.info(f"✅ Loaded {len(self._templates)} pre-defined templates")
    
    def _load_templates_from_disk(self) -> None:
        """Load templates from disk (YAML/JSON files)"""
        if not self._templates_path.exists():
            return
        
        for file_path in self._templates_path.glob("*.yaml"):
            try:
                self._load_template_file(file_path)
            except Exception as e:
                logger.error(f"❌ Failed to load template {file_path}: {e}")
        
        for file_path in self._templates_path.glob("*.json"):
            try:
                self._load_template_file(file_path)
            except Exception as e:
                logger.error(f"❌ Failed to load template {file_path}: {e}")
    
    def _load_template_file(self, file_path: Path) -> None:
        """Load a template from a file"""
        with open(file_path, 'r') as f:
            if file_path.suffix == '.yaml':
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        
        template = self._dict_to_template(data)
        self._templates[template.template_id] = template
        logger.info(f"✅ Loaded template: {template.template_id}")
    
    def _dict_to_template(self, data: Dict[str, Any]) -> CertificateTemplate:
        """Convert dictionary to CertificateTemplate"""
        # Parse subject
        subject_data = data.get("subject", {})
        subject = SubjectConfig(
            country=subject_data.get("country", "DE"),
            state=subject_data.get("state", "Brandenburg"),
            locality=subject_data.get("locality"),
            organization=subject_data.get("organization", "VCC - Veritas Control Center"),
            organizational_unit=subject_data.get("organizational_unit"),
            common_name=subject_data.get("common_name"),
            email=subject_data.get("email")
        )
        
        # Parse key usage
        key_usage_data = data.get("key_usage", {})
        key_usage = KeyUsageConfig(
            digital_signature=key_usage_data.get("digital_signature", False),
            key_encipherment=key_usage_data.get("key_encipherment", False),
            content_commitment=key_usage_data.get("content_commitment", False),
            data_encipherment=key_usage_data.get("data_encipherment", False),
            key_agreement=key_usage_data.get("key_agreement", False),
            key_cert_sign=key_usage_data.get("key_cert_sign", False),
            crl_sign=key_usage_data.get("crl_sign", False),
            encipher_only=key_usage_data.get("encipher_only", False),
            decipher_only=key_usage_data.get("decipher_only", False),
            critical=key_usage_data.get("critical", True)
        )
        
        # Parse extended key usage
        eku_data = data.get("extended_key_usage", {})
        eku_usages = [ExtendedKeyUsage(u) for u in eku_data.get("usages", [])]
        extended_key_usage = ExtendedKeyUsageConfig(
            usages=eku_usages,
            critical=eku_data.get("critical", False)
        )
        
        # Parse validity
        validity_data = data.get("validity", {})
        validity = ValidityConfig(
            days=validity_data.get("days", 365),
            max_days=validity_data.get("max_days", 730),
            min_days=validity_data.get("min_days", 1),
            renewable=validity_data.get("renewable", True),
            renewal_threshold_days=validity_data.get("renewal_threshold_days", 30)
        )
        
        # Parse SAN
        san_data = data.get("san", {})
        san = SANConfig(
            dns_names=san_data.get("dns_names", []),
            ip_addresses=san_data.get("ip_addresses", []),
            emails=san_data.get("emails", []),
            uris=san_data.get("uris", [])
        )
        
        # Parse policy
        policy_data = data.get("policy", {})
        policy = PolicyConfig(
            policy_oid=policy_data.get("policy_oid"),
            cps_uri=policy_data.get("cps_uri"),
            user_notice=policy_data.get("user_notice")
        )
        
        return CertificateTemplate(
            template_id=data["template_id"],
            template_name=data.get("template_name", data["template_id"]),
            template_type=TemplateType(data.get("template_type", "custom")),
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            parent_template=data.get("parent_template"),
            subject=subject,
            key_algorithm=data.get("key_algorithm", "rsa"),
            key_size=data.get("key_size", 4096),
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            basic_constraints_ca=data.get("basic_constraints_ca", False),
            basic_constraints_path_length=data.get("basic_constraints_path_length"),
            validity=validity,
            san=san,
            policy=policy,
            custom_extensions=data.get("custom_extensions", {}),
            tags=data.get("tags", [])
        )
    
    def _template_to_dict(self, template: CertificateTemplate) -> Dict[str, Any]:
        """Convert CertificateTemplate to dictionary"""
        return {
            "template_id": template.template_id,
            "template_name": template.template_name,
            "template_type": template.template_type.value,
            "description": template.description,
            "version": template.version,
            "parent_template": template.parent_template,
            "subject": {
                "country": template.subject.country,
                "state": template.subject.state,
                "locality": template.subject.locality,
                "organization": template.subject.organization,
                "organizational_unit": template.subject.organizational_unit,
                "common_name": template.subject.common_name,
                "email": template.subject.email
            },
            "key_algorithm": template.key_algorithm,
            "key_size": template.key_size,
            "key_usage": {
                "digital_signature": template.key_usage.digital_signature,
                "key_encipherment": template.key_usage.key_encipherment,
                "content_commitment": template.key_usage.content_commitment,
                "data_encipherment": template.key_usage.data_encipherment,
                "key_agreement": template.key_usage.key_agreement,
                "key_cert_sign": template.key_usage.key_cert_sign,
                "crl_sign": template.key_usage.crl_sign,
                "encipher_only": template.key_usage.encipher_only,
                "decipher_only": template.key_usage.decipher_only,
                "critical": template.key_usage.critical
            },
            "extended_key_usage": {
                "usages": [u.value for u in template.extended_key_usage.usages],
                "critical": template.extended_key_usage.critical
            },
            "basic_constraints_ca": template.basic_constraints_ca,
            "basic_constraints_path_length": template.basic_constraints_path_length,
            "validity": {
                "days": template.validity.days,
                "max_days": template.validity.max_days,
                "min_days": template.validity.min_days,
                "renewable": template.validity.renewable,
                "renewal_threshold_days": template.validity.renewal_threshold_days
            },
            "san": {
                "dns_names": template.san.dns_names,
                "ip_addresses": template.san.ip_addresses,
                "emails": template.san.emails,
                "uris": template.san.uris
            },
            "policy": {
                "policy_oid": template.policy.policy_oid,
                "cps_uri": template.policy.cps_uri,
                "user_notice": template.policy.user_notice
            },
            "custom_extensions": template.custom_extensions,
            "tags": template.tags,
            "created_at": template.created_at.isoformat(),
            "updated_at": template.updated_at.isoformat(),
            "created_by": template.created_by
        }
    
    def get_template(self, template_id: str) -> Optional[CertificateTemplate]:
        """Get a template by ID"""
        return self._templates.get(template_id)
    
    def get_resolved_template(
        self,
        template_id: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Optional[CertificateTemplate]:
        """
        Get a template with inheritance resolved and variables substituted.
        
        Args:
            template_id: Template ID
            variables: Variables for substitution (e.g., ${service_name})
        
        Returns:
            Resolved template or None
        """
        template = self.get_template(template_id)
        if not template:
            return None
        
        # Resolve inheritance
        resolved = self._resolve_inheritance(template)
        
        # Substitute variables
        if variables:
            resolved = self._substitute_variables(resolved, variables)
        
        return resolved
    
    def _resolve_inheritance(self, template: CertificateTemplate) -> CertificateTemplate:
        """Resolve template inheritance"""
        if not template.parent_template:
            return template
        
        parent = self.get_template(template.parent_template)
        if not parent:
            logger.warning(f"⚠️ Parent template not found: {template.parent_template}")
            return template
        
        # Recursively resolve parent
        parent = self._resolve_inheritance(parent)
        
        # Merge parent into child (child takes precedence)
        resolved = deepcopy(parent)
        
        # Override with child values
        resolved.template_id = template.template_id
        resolved.template_name = template.template_name
        resolved.template_type = template.template_type
        resolved.description = template.description or parent.description
        resolved.version = template.version
        resolved.parent_template = template.parent_template
        
        # Subject (merge)
        if template.subject.common_name:
            resolved.subject.common_name = template.subject.common_name
        if template.subject.organizational_unit:
            resolved.subject.organizational_unit = template.subject.organizational_unit
        
        # Validity (override if specified)
        if template.validity.days != 365:  # Not default
            resolved.validity = template.validity
        
        # Tags (merge)
        resolved.tags = list(set(parent.tags + template.tags))
        
        return resolved
    
    def _substitute_variables(
        self,
        template: CertificateTemplate,
        variables: Dict[str, str]
    ) -> CertificateTemplate:
        """Substitute variables in template strings"""
        resolved = deepcopy(template)
        
        def substitute(text: str) -> str:
            if not text:
                return text
            for key, value in variables.items():
                text = text.replace(f"${{{key}}}", value)
            return text
        
        # Substitute in subject
        resolved.subject.common_name = substitute(resolved.subject.common_name)
        resolved.subject.organizational_unit = substitute(resolved.subject.organizational_unit)
        
        # Substitute in SAN
        resolved.san.dns_names = [substitute(d) for d in resolved.san.dns_names]
        resolved.san.uris = [substitute(u) for u in resolved.san.uris]
        
        return resolved
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available templates"""
        return [
            {
                "template_id": t.template_id,
                "template_name": t.template_name,
                "template_type": t.template_type.value,
                "description": t.description,
                "tags": t.tags
            }
            for t in self._templates.values()
        ]
    
    def create_template(self, template: CertificateTemplate) -> bool:
        """Create a new template"""
        if template.template_id in self._templates:
            return False
        
        template.created_at = datetime.utcnow()
        template.updated_at = datetime.utcnow()
        
        self._templates[template.template_id] = template
        
        # Save to disk
        self._save_template_to_disk(template)
        
        logger.info(f"✅ Created template: {template.template_id}")
        return True
    
    def update_template(self, template: CertificateTemplate) -> bool:
        """Update an existing template"""
        if template.template_id not in self._templates:
            return False
        
        template.updated_at = datetime.utcnow()
        self._templates[template.template_id] = template
        
        # Save to disk
        self._save_template_to_disk(template)
        
        logger.info(f"✅ Updated template: {template.template_id}")
        return True
    
    def delete_template(self, template_id: str) -> bool:
        """Delete a template"""
        if template_id not in self._templates:
            return False
        
        # Don't allow deleting predefined templates
        predefined = ["vcc-service", "vcc-code-signing", "vcc-clara-model",
                      "vcc-tls-server", "vcc-tls-client", "vcc-admin",
                      "vcc-tsa", "vcc-ocsp"]
        if template_id in predefined:
            logger.warning(f"⚠️ Cannot delete predefined template: {template_id}")
            return False
        
        del self._templates[template_id]
        
        # Remove from disk
        yaml_file = self._templates_path / f"{template_id}.yaml"
        json_file = self._templates_path / f"{template_id}.json"
        
        if yaml_file.exists():
            yaml_file.unlink()
        if json_file.exists():
            json_file.unlink()
        
        logger.info(f"✅ Deleted template: {template_id}")
        return True
    
    def _save_template_to_disk(self, template: CertificateTemplate) -> None:
        """Save template to disk as YAML"""
        file_path = self._templates_path / f"{template.template_id}.yaml"
        data = self._template_to_dict(template)
        
        with open(file_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    def validate_request(
        self,
        template_id: str,
        variables: Dict[str, str],
        requested_validity_days: Optional[int] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate a certificate request against a template.
        
        Args:
            template_id: Template ID
            variables: Variables for the request
            requested_validity_days: Requested validity period
        
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        
        template = self.get_template(template_id)
        if not template:
            return False, [f"Template not found: {template_id}"]
        
        # Check required variables
        resolved = self.get_resolved_template(template_id, variables)
        
        # Check common_name is set
        if not resolved.subject.common_name or "${" in resolved.subject.common_name:
            errors.append("Common name not set or contains unsubstituted variables")
        
        # Check validity
        if requested_validity_days:
            if requested_validity_days < template.validity.min_days:
                errors.append(f"Validity {requested_validity_days} days is below minimum {template.validity.min_days}")
            if requested_validity_days > template.validity.max_days:
                errors.append(f"Validity {requested_validity_days} days exceeds maximum {template.validity.max_days}")
        
        return len(errors) == 0, errors


# ============================================================================
# FastAPI Router for Templates
# ============================================================================

def create_templates_router(manager: CertificateTemplateManager):
    """Create FastAPI router for template endpoints"""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    
    router = APIRouter(prefix="/api/v1/templates", tags=["Certificate Templates"])
    
    class TemplateCreateRequest(BaseModel):
        template_id: str
        template_name: str
        template_type: str = "custom"
        description: str = ""
        parent_template: Optional[str] = None
        subject: Dict[str, Any] = {}
        key_algorithm: str = "rsa"
        key_size: int = 4096
        key_usage: Dict[str, Any] = {}
        extended_key_usage: Dict[str, Any] = {}
        validity: Dict[str, Any] = {}
        san: Dict[str, Any] = {}
        policy: Dict[str, Any] = {}
        tags: List[str] = []
    
    class TemplateResolveRequest(BaseModel):
        template_id: str
        variables: Dict[str, str] = {}
    
    class ValidateRequest(BaseModel):
        template_id: str
        variables: Dict[str, str] = {}
        validity_days: Optional[int] = None
    
    @router.get("")
    async def list_templates():
        """List all available certificate templates"""
        return {
            "total": len(manager._templates),
            "templates": manager.list_templates()
        }
    
    @router.get("/{template_id}")
    async def get_template(template_id: str):
        """Get a specific template"""
        template = manager.get_template(template_id)
        if not template:
            raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
        
        return manager._template_to_dict(template)
    
    @router.post("/resolve")
    async def resolve_template(request: TemplateResolveRequest):
        """Resolve a template with variable substitution"""
        resolved = manager.get_resolved_template(request.template_id, request.variables)
        if not resolved:
            raise HTTPException(status_code=404, detail=f"Template not found: {request.template_id}")
        
        return manager._template_to_dict(resolved)
    
    @router.post("/validate")
    async def validate_request(request: ValidateRequest):
        """Validate a certificate request against a template"""
        is_valid, errors = manager.validate_request(
            request.template_id,
            request.variables,
            request.validity_days
        )
        
        return {
            "valid": is_valid,
            "errors": errors
        }
    
    @router.post("")
    async def create_template(request: TemplateCreateRequest):
        """Create a new certificate template"""
        try:
            template_data = request.model_dump()
            template = manager._dict_to_template(template_data)
            
            if not manager.create_template(template):
                raise HTTPException(status_code=409, detail=f"Template already exists: {request.template_id}")
            
            return {
                "success": True,
                "message": f"Template created: {request.template_id}"
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.delete("/{template_id}")
    async def delete_template(template_id: str):
        """Delete a certificate template"""
        if not manager.delete_template(template_id):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete template: {template_id} (not found or predefined)"
            )
        
        return {
            "success": True,
            "message": f"Template deleted: {template_id}"
        }
    
    return router


# ============================================================================
# Factory Function
# ============================================================================

def create_template_manager(config: Optional[TemplateConfig] = None) -> CertificateTemplateManager:
    """
    Create and initialize Certificate Template Manager.
    
    Args:
        config: Template configuration (uses env vars if not provided)
    
    Returns:
        Initialized CertificateTemplateManager
    """
    if config is None:
        config = TemplateConfig.from_env()
    
    return CertificateTemplateManager(config)
