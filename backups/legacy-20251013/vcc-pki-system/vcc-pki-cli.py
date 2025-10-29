# VCC PKI System - CLI Management Tool
# Production-ready command-line interface for PKI administration

import click
import requests
import json
import sys
from typing import Optional, Dict, Any
from pathlib import Path
from datetime import datetime
import os

# Configuration
DEFAULT_API_BASE = "http://localhost:12091"
CONFIG_FILE = Path.home() / ".vcc-pki-config.json"

class VCCPKIClient:
    """VCC PKI System client for CLI operations"""
    
    def __init__(self, api_base: str, token: Optional[str] = None):
        self.api_base = api_base.rstrip('/')
        self.session = requests.Session()
        if token:
            self.session.headers['Authorization'] = f'Bearer {token}'
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[Any, Any]:
        """Make HTTP request with error handling"""
        url = f"{self.api_base}{endpoint}"
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            if response.headers.get('content-type', '').startswith('application/json'):
                return response.json()
            else:
                return {"success": False, "error": f"Non-JSON response: {response.text[:100]}"}
                
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}
    
    def get(self, endpoint: str, **kwargs) -> Dict[Any, Any]:
        return self._request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> Dict[Any, Any]:
        return self._request('POST', endpoint, **kwargs)

def load_config() -> Dict[str, Any]:
    """Load CLI configuration"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config: Dict[str, Any]):
    """Save CLI configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_client() -> VCCPKIClient:
    """Get configured PKI client"""
    config = load_config()
    api_base = config.get('api_base', DEFAULT_API_BASE)
    token = config.get('token')
    return VCCPKIClient(api_base, token)

def format_response(response: Dict[Any, Any]) -> str:
    """Format API response for display"""
    if response.get('success'):
        return f"✅ {response.get('message', 'Success')}"
    else:
        return f"❌ {response.get('message', response.get('error', 'Unknown error'))}"

def format_table(data: list, headers: list) -> str:
    """Format data as table"""
    if not data:
        return "No data available"
    
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in data:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))
    
    # Format table
    lines = []
    
    # Header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    lines.append(header_line)
    lines.append("-" * len(header_line))
    
    # Rows
    for row in data:
        row_line = " | ".join(str(val).ljust(w) for val, w in zip(row, widths))
        lines.append(row_line)
    
    return "\n".join(lines)

# CLI Commands
@click.group()
@click.option('--api-base', default=None, help='API base URL')
@click.option('--token', default=None, help='Authentication token')
@click.pass_context
def cli(ctx, api_base, token):
    """VCC PKI System CLI - Manage your PKI infrastructure"""
    
    # Store options in context
    ctx.ensure_object(dict)
    
    config = load_config()
    
    if api_base:
        config['api_base'] = api_base
    if token:
        config['token'] = token
    
    save_config(config)

@cli.command()
def status():
    """Get system status"""
    client = get_client()
    
    click.echo("🔍 Checking VCC PKI System status...")
    
    # Health check
    response = client.get("/health")
    if response.get('success'):
        click.echo("✅ System is healthy")
    else:
        click.echo(f"❌ Health check failed: {response.get('error')}")
        return
    
    # Detailed status
    response = client.get("/status")
    if response.get('success'):
        data = response['data']
        click.echo("\n📊 System Information:")
        click.echo(f"   Mock Mode: {data.get('mock_mode', 'Unknown')}")
        click.echo(f"   Uptime: {data.get('uptime_hours', 0):.1f} hours")
        click.echo(f"   Database Status: {data.get('database_status', 'Unknown')}")
        click.echo(f"   Crypto Status: {data.get('crypto_status', 'Unknown')}")
        
        if 'vcc_services' in data:
            services = data['vcc_services']
            click.echo(f"\n🏛️  VCC Services: {len(services)} registered")
            for service in services:
                status_icon = "✅" if service.get('health_status') == 'healthy' else "⚠️"
                click.echo(f"   {status_icon} {service['service_name']} ({service['service_id']})")
    else:
        click.echo(f"❌ {format_response(response)}")

@cli.group()
def org():
    """Organization management"""
    pass

@org.command('list')
def org_list():
    """List organizations"""
    client = get_client()
    
    click.echo("📋 Listing organizations...")
    
    response = client.get("/api/v1/organizations")
    if response.get('success'):
        organizations = response['data']
        
        if organizations:
            table_data = []
            for org in organizations:
                table_data.append([
                    org['org_id'],
                    org['org_name'],
                    org['org_type'],
                    org['admin_contact'],
                    org['isolation_level']
                ])
            
            headers = ['ID', 'Name', 'Type', 'Admin', 'Isolation']
            click.echo(format_table(table_data, headers))
        else:
            click.echo("No organizations found")
    else:
        click.echo(f"❌ {format_response(response)}")

@org.command('create')
@click.option('--org-id', required=True, help='Organization ID')
@click.option('--name', required=True, help='Organization name')
@click.option('--type', default='government', help='Organization type')
@click.option('--admin', required=True, help='Admin contact email')
@click.option('--isolation', default='standard', help='Isolation level')
def org_create(org_id, name, type, admin, isolation):
    """Create new organization"""
    client = get_client()
    
    org_data = {
        'org_id': org_id,
        'org_name': name,
        'org_type': type,
        'admin_contact': admin,
        'isolation_level': isolation
    }
    
    click.echo(f"🏢 Creating organization '{name}'...")
    
    response = client.post("/api/v1/organizations", json=org_data)
    click.echo(format_response(response))

@cli.group()
def service():
    """VCC service management"""
    pass

@service.command('list')
@click.option('--org', default='brandenburg-gov', help='Organization ID')
def service_list(org):
    """List VCC services"""
    client = get_client()
    
    click.echo(f"🏛️  Listing VCC services for {org}...")
    
    response = client.get(f"/api/v1/services?organization_id={org}")
    if response.get('success'):
        services = response['data']
        
        if services:
            table_data = []
            for svc in services:
                health = svc.get('health_status', 'unknown')
                health_icon = {"healthy": "✅", "degraded": "⚠️", "unhealthy": "❌"}.get(health, "❓")
                
                table_data.append([
                    svc['service_id'],
                    svc['service_name'],
                    svc['service_type'],
                    f"{health_icon} {health}",
                    svc.get('endpoint_url', 'N/A')
                ])
            
            headers = ['ID', 'Name', 'Type', 'Health', 'Endpoint']
            click.echo(format_table(table_data, headers))
        else:
            click.echo("No services found")
    else:
        click.echo(f"❌ {format_response(response)}")

@service.command('register')
@click.option('--service-id', required=True, help='Service ID')
@click.option('--name', required=True, help='Service name')
@click.option('--type', required=True, help='Service type')
@click.option('--endpoint', required=True, help='Service endpoint URL')
@click.option('--health-endpoint', help='Health check endpoint')
@click.option('--org', default='brandenburg-gov', help='Organization ID')
@click.option('--auto-renewal/--no-auto-renewal', default=True, help='Enable auto certificate renewal')
def service_register(service_id, name, type, endpoint, health_endpoint, org, auto_renewal):
    """Register new VCC service"""
    client = get_client()
    
    service_data = {
        'service_id': service_id,
        'service_name': name,
        'service_type': type,
        'endpoint_url': endpoint,
        'health_endpoint': health_endpoint or f"{endpoint}/health",
        'organization_id': org,
        'auto_cert_renewal': auto_renewal
    }
    
    click.echo(f"📝 Registering service '{name}'...")
    
    response = client.post("/api/v1/services", json=service_data)
    click.echo(format_response(response))

@cli.group()
def ca():
    """Certificate Authority management"""
    pass

@ca.command('list')
@click.option('--org', help='Organization ID filter')
def ca_list(org):
    """List Certificate Authorities"""
    client = get_client()
    
    click.echo("🏛️  Listing Certificate Authorities...")
    
    params = {}
    if org:
        params['organization_id'] = org
    
    response = client.get("/api/v1/ca/list", params=params)
    if response.get('success'):
        cas = response['data']
        
        if cas:
            table_data = []
            for ca in cas:
                status = "Active" if ca.get('active') else "Inactive"
                table_data.append([
                    ca['ca_id'],
                    ca['ca_name'],
                    ca['ca_type'],
                    ca['organization_id'],
                    status
                ])
            
            headers = ['ID', 'Name', 'Type', 'Organization', 'Status']
            click.echo(format_table(table_data, headers))
        else:
            click.echo("No Certificate Authorities found")
    else:
        click.echo(f"❌ {format_response(response)}")

@ca.command('create-issuing')
@click.option('--name', required=True, help='CA name')
@click.option('--org', default='brandenburg-gov', help='Organization ID')
@click.option('--validity-days', default=1825, help='Validity period in days')
def ca_create_issuing(name, org, validity_days):
    """Create new issuing CA"""
    client = get_client()
    
    ca_data = {
        'ca_name': name,
        'organization_id': org,
        'ca_type': 'issuing',
        'validity_days': validity_days,
        'key_size': 4096,
        'subject_data': {
            'common_name': name,
            'organization': 'Brandenburg Government',
            'country': 'DE'
        }
    }
    
    click.echo(f"🏗️  Creating issuing CA '{name}'...")
    
    response = client.post("/api/v1/ca/create-issuing-ca", json=ca_data)
    click.echo(format_response(response))

@cli.group()
def cert():
    """Certificate management"""
    pass

@cert.command('list')
@click.option('--org', help='Organization ID filter')
@click.option('--service', help='Service ID filter')
@click.option('--purpose', help='Certificate purpose filter')
def cert_list(org, service, purpose):
    """List certificates"""
    client = get_client()
    
    click.echo("📄 Listing certificates...")
    
    params = {}
    if org:
        params['organization_id'] = org
    if service:
        params['service_id'] = service
    if purpose:
        params['purpose'] = purpose
    
    response = client.get("/api/v1/certs/list", params=params)
    if response.get('success'):
        certificates = response['data']
        
        if certificates:
            table_data = []
            for cert in certificates:
                expires_at = cert.get('expires_at', '')
                if expires_at:
                    try:
                        exp_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                        days_left = (exp_date - datetime.now()).days
                        expiry = f"{days_left}d" if days_left > 0 else "EXPIRED"
                    except:
                        expiry = "Unknown"
                else:
                    expiry = "Unknown"
                
                status = "Revoked" if cert.get('revoked_at') else "Active"
                
                table_data.append([
                    cert['cert_id'][:12] + "...",
                    cert['subject_dn'][:30] + "..." if len(cert.get('subject_dn', '')) > 30 else cert.get('subject_dn', ''),
                    cert['purpose'],
                    expiry,
                    status
                ])
            
            headers = ['Certificate ID', 'Subject', 'Purpose', 'Expires', 'Status']
            click.echo(format_table(table_data, headers))
        else:
            click.echo("No certificates found")
    else:
        click.echo(f"❌ {format_response(response)}")

@cert.command('request')
@click.option('--type', 'cert_type', type=click.Choice(['vcc_service', 'code_signing']), required=True, help='Certificate type')
@click.option('--service-id', help='Service ID (for service certificates)')
@click.option('--signer-name', help='Signer name (for code signing certificates)')
@click.option('--org', default='brandenburg-gov', help='Organization ID')
def cert_request(cert_type, service_id, signer_name, org):
    """Request new certificate"""
    client = get_client()
    
    cert_data = {
        'certificate_type': cert_type,
        'organization_id': org,
        'subject_data': {}
    }
    
    if cert_type == 'vcc_service' and service_id:
        cert_data['service_id'] = service_id
    elif cert_type == 'code_signing' and signer_name:
        cert_data['subject_data']['common_name'] = signer_name
    else:
        click.echo("❌ Missing required parameters for certificate type")
        return
    
    click.echo(f"📋 Requesting {cert_type} certificate...")
    
    response = client.post("/api/v1/certs/request", json=cert_data)
    click.echo(format_response(response))
    
    if response.get('success') and response.get('data'):
        cert_id = response['data'].get('cert_id')
        if cert_id:
            click.echo(f"   Certificate ID: {cert_id}")

@cert.command('status')
@click.argument('cert_id')
def cert_status(cert_id):
    """Get certificate status"""
    client = get_client()
    
    click.echo(f"🔍 Checking certificate status: {cert_id}")
    
    response = client.get(f"/api/v1/certs/status/{cert_id}")
    if response.get('success'):
        cert_info = response['data']
        
        click.echo(f"\n📄 Certificate Information:")
        click.echo(f"   ID: {cert_info['cert_id']}")
        click.echo(f"   Purpose: {cert_info['purpose']}")
        click.echo(f"   Status: {cert_info['status']}")
        click.echo(f"   Created: {cert_info['created_at']}")
        click.echo(f"   Expires: {cert_info['expires_at']}")
        
        if cert_info.get('expires_in_days'):
            click.echo(f"   Days until expiry: {cert_info['expires_in_days']}")
        
        if cert_info.get('revoked_at'):
            click.echo(f"   Revoked: {cert_info['revoked_at']}")
            click.echo(f"   Reason: {cert_info.get('revocation_reason', 'Not specified')}")
        
        if cert_info.get('usage_count'):
            click.echo(f"   Usage count: {cert_info['usage_count']}")
        if cert_info.get('last_used'):
            click.echo(f"   Last used: {cert_info['last_used']}")
    else:
        click.echo(f"❌ {format_response(response)}")

@cert.command('revoke')
@click.argument('cert_id')
@click.option('--reason', default='unspecified', help='Revocation reason')
def cert_revoke(cert_id, reason):
    """Revoke certificate"""
    client = get_client()
    
    if not click.confirm(f"Are you sure you want to revoke certificate {cert_id}?"):
        click.echo("❌ Revocation cancelled")
        return
    
    revocation_data = {
        'revocation_reason': reason
    }
    
    click.echo(f"🚫 Revoking certificate: {cert_id}")
    
    response = client.post(f"/api/v1/certs/revoke/{cert_id}", json=revocation_data)
    click.echo(format_response(response))

@cli.group()
def sign():
    """Code signing operations"""
    pass

@sign.command('python-package')
@click.option('--cert-id', required=True, help='Code signing certificate ID')
@click.option('--package-path', required=True, help='Path to Python package')
@click.option('--package-name', help='Package name (if different from path)')
def sign_python_package(cert_id, package_path, package_name):
    """Sign Python package"""
    client = get_client()
    
    # Read package content (simplified for CLI)
    package_path = Path(package_path)
    if not package_path.exists():
        click.echo(f"❌ Package path not found: {package_path}")
        return
    
    # For demonstration, we'll just send the path
    signing_data = {
        'artifact_type': 'python_package',
        'package_name': package_name or package_path.name,
        'package_path': str(package_path),
        'version': '1.0.0',  # TODO: Extract from package
        'metadata': {'signed_via': 'vcc-pki-cli'}
    }
    
    click.echo(f"✍️  Signing package: {package_path}")
    
    response = client.post(f"/api/v1/sign/python-package?cert_id={cert_id}", json=signing_data)
    click.echo(format_response(response))
    
    if response.get('success') and response.get('data'):
        signature_id = response['data'].get('signature_id')
        if signature_id:
            click.echo(f"   Signature ID: {signature_id}")

@cli.group()
def audit():
    """Audit and compliance"""
    pass

@audit.command('events')
@click.option('--org', help='Organization ID filter')
@click.option('--service', help='Service ID filter')
@click.option('--category', help='Event category filter')
@click.option('--limit', default=20, help='Number of events to show')
def audit_events(org, service, category, limit):
    """Show audit events"""
    client = get_client()
    
    click.echo("📋 Retrieving audit events...")
    
    params = {'limit': limit}
    if org:
        params['organization_id'] = org
    if service:
        params['service_id'] = service
    if category:
        params['event_category'] = category
    
    response = client.get("/api/v1/audit/events", params=params)
    if response.get('success'):
        events = response['data']
        
        if events:
            table_data = []
            for event in events:
                table_data.append([
                    event['timestamp'][:19],  # Remove milliseconds
                    event['event_type'],
                    event.get('actor_identity', 'System'),
                    event.get('target_resource', 'N/A')[:20] + "..." if len(event.get('target_resource', '')) > 20 else event.get('target_resource', 'N/A'),
                    event.get('organization_id', 'N/A')
                ])
            
            headers = ['Timestamp', 'Event', 'Actor', 'Target', 'Org']
            click.echo(format_table(table_data, headers))
        else:
            click.echo("No audit events found")
    else:
        click.echo(f"❌ {format_response(response)}")

@cli.command()
@click.option('--config-file', help='Path to config file')
def init(config_file):
    """Initialize CLI configuration"""
    
    click.echo("🔧 Initializing VCC PKI CLI...")
    
    # Get API base
    api_base = click.prompt(
        "API Base URL", 
        default=DEFAULT_API_BASE,
        show_default=True
    )
    
    # Test connection
    client = VCCPKIClient(api_base)
    response = client.get("/health")
    
    if response.get('success'):
        click.echo("✅ Connection successful")
        
        config = {
            'api_base': api_base,
            'initialized_at': datetime.now().isoformat()
        }
        
        # Optional token
        if click.confirm("Do you want to configure an authentication token?"):
            token = click.prompt("Token", hide_input=True)
            config['token'] = token
        
        save_config(config)
        click.echo(f"✅ Configuration saved to {CONFIG_FILE}")
        
    else:
        click.echo(f"❌ Connection failed: {response.get('error')}")
        sys.exit(1)

if __name__ == '__main__':
    cli()