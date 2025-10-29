#!/usr/bin/env python3
"""
VCC PKI Admin CLI - Unified Certificate Management Tool

A comprehensive command-line interface for managing the VCC PKI infrastructure.

Features:
- CA operations (init, info, intermediate)
- Certificate lifecycle (issue, renew, revoke, list)
- Service management (register, list, info)
- CRL operations (generate, info)
- Health checks and statistics

Usage:
    pki-admin ca init-root
    pki-admin cert issue <service-id>
    pki-admin cert list
    pki-admin service register <service-id>
    pki-admin health check
"""

import argparse
import sys
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import urllib.request
import urllib.error
import ssl

# Color output support (Windows/Linux compatible)
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    # Fallback: no colors
    class Fore:
        GREEN = RED = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = ""
    HAS_COLOR = False

# Table formatting support
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


class PKIAdminCLI:
    """Main CLI class for PKI administration."""
    
    def __init__(self, server_url: str = "https://localhost:8443", verify_ssl: bool = False):
        """
        Initialize PKI Admin CLI.
        
        Args:
            server_url: PKI server URL
            verify_ssl: Whether to verify SSL certificates
        """
        self.server_url = server_url.rstrip('/')
        self.verify_ssl = verify_ssl
        
        # Setup SSL context
        if not verify_ssl:
            self.ssl_context = ssl._create_unverified_context()
        else:
            self.ssl_context = ssl.create_default_context()
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make HTTP request to PKI server.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request payload (for POST/PUT)
            
        Returns:
            Response JSON data
            
        Raises:
            SystemExit: On request failure
        """
        url = f"{self.server_url}{endpoint}"
        
        try:
            if data:
                json_data = json.dumps(data).encode('utf-8')
                headers = {'Content-Type': 'application/json'}
                req = urllib.request.Request(url, data=json_data, headers=headers, method=method)
            else:
                req = urllib.request.Request(url, method=method)
            
            with urllib.request.urlopen(req, context=self.ssl_context) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data)
        
        except urllib.error.HTTPError as e:
            error_data = e.read().decode('utf-8')
            try:
                error_json = json.loads(error_data)
                error_msg = error_json.get('detail', str(e))
            except:
                error_msg = str(e)
            
            self.print_error(f"HTTP Error {e.code}: {error_msg}")
            sys.exit(1)
        
        except urllib.error.URLError as e:
            self.print_error(f"Connection Error: {e.reason}")
            self.print_error(f"Is the PKI server running at {self.server_url}?")
            sys.exit(1)
        
        except Exception as e:
            self.print_error(f"Unexpected Error: {str(e)}")
            sys.exit(1)
    
    # ==================== Color Output Helpers ====================
    
    def print_success(self, message: str):
        """Print success message in green."""
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    
    def print_error(self, message: str):
        """Print error message in red."""
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}", file=sys.stderr)
    
    def print_warning(self, message: str):
        """Print warning message in yellow."""
        print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")
    
    def print_info(self, message: str):
        """Print info message in cyan."""
        print(f"{Fore.CYAN}ℹ {message}{Style.RESET_ALL}")
    
    def print_header(self, message: str):
        """Print header in bright white."""
        print(f"\n{Style.BRIGHT}{message}{Style.RESET_ALL}")
        print("=" * len(message))
    
    def print_table(self, data: List[Dict], headers: Optional[List[str]] = None):
        """
        Print data as formatted table.
        
        Args:
            data: List of dictionaries
            headers: Optional custom headers
        """
        if not data:
            self.print_warning("No data to display")
            return
        
        if HAS_TABULATE:
            if headers:
                print(tabulate(data, headers="keys", tablefmt="grid"))
            else:
                print(tabulate(data, headers="keys", tablefmt="grid"))
        else:
            # Fallback: simple formatting
            if not headers:
                headers = list(data[0].keys())
            
            # Calculate column widths
            widths = {h: len(h) for h in headers}
            for row in data:
                for h in headers:
                    widths[h] = max(widths[h], len(str(row.get(h, ''))))
            
            # Print header
            header_row = " | ".join(h.ljust(widths[h]) for h in headers)
            print(header_row)
            print("-" * len(header_row))
            
            # Print rows
            for row in data:
                print(" | ".join(str(row.get(h, '')).ljust(widths[h]) for h in headers))
    
    # ==================== CA Commands ====================
    
    def ca_init_root(self, common_name: str, country: str, org: str, 
                     password: Optional[str] = None, key_size: int = 4096,
                     validity_days: int = 3650):
        """Initialize Root CA."""
        self.print_header("Initialize Root CA")
        
        data = {
            "common_name": common_name,
            "country": country,
            "organization": org,
            "password": password or os.getenv("VCC_CA_PASSWORD"),
            "key_size": key_size,
            "validity_days": validity_days
        }
        
        self.print_info(f"Creating Root CA with CN={common_name}, Key Size={key_size} bits")
        response = self._make_request("POST", "/api/ca/root", data)
        
        self.print_success("Root CA initialized successfully")
        print(f"  Certificate: {response.get('root_cert_path')}")
        print(f"  Serial Number: {response.get('serial_number')}")
        print(f"  Valid Until: {response.get('valid_until')}")
    
    def ca_create_intermediate(self, common_name: str, country: str, org: str,
                               password: Optional[str] = None, key_size: int = 2048,
                               validity_days: int = 1825):
        """Create Intermediate CA."""
        self.print_header("Create Intermediate CA")
        
        data = {
            "common_name": common_name,
            "country": country,
            "organization": org,
            "password": password or os.getenv("VCC_CA_PASSWORD"),
            "key_size": key_size,
            "validity_days": validity_days
        }
        
        self.print_info(f"Creating Intermediate CA with CN={common_name}, Key Size={key_size} bits")
        response = self._make_request("POST", "/api/ca/intermediate", data)
        
        self.print_success("Intermediate CA created successfully")
        print(f"  Certificate: {response.get('intermediate_cert_path')}")
        print(f"  Serial Number: {response.get('serial_number')}")
        print(f"  Valid Until: {response.get('valid_until')}")
    
    def ca_info(self):
        """Display CA information."""
        self.print_header("CA Information")
        
        response = self._make_request("GET", "/api/ca/info")
        
        # Root CA
        if response.get('root_ca'):
            root = response['root_ca']
            print(f"\n{Fore.CYAN}Root CA:{Style.RESET_ALL}")
            print(f"  Subject: {root.get('subject')}")
            print(f"  Serial: {root.get('serial_number')}")
            print(f"  Valid From: {root.get('not_before')}")
            print(f"  Valid Until: {root.get('not_after')}")
            print(f"  Key Size: {root.get('key_size')} bits")
        
        # Intermediate CA
        if response.get('intermediate_ca'):
            inter = response['intermediate_ca']
            print(f"\n{Fore.CYAN}Intermediate CA:{Style.RESET_ALL}")
            print(f"  Subject: {inter.get('subject')}")
            print(f"  Serial: {inter.get('serial_number')}")
            print(f"  Valid From: {inter.get('not_before')}")
            print(f"  Valid Until: {inter.get('not_after')}")
            print(f"  Key Size: {inter.get('key_size')} bits")
            print(f"  Issuer: {inter.get('issuer')}")
    
    # ==================== Certificate Commands ====================
    
    def cert_issue(self, service_id: str, common_name: str, 
                   san_dns: Optional[List[str]] = None,
                   san_ip: Optional[List[str]] = None,
                   validity_days: int = 365):
        """Issue new certificate."""
        self.print_header(f"Issue Certificate: {service_id}")
        
        data = {
            "service_id": service_id,
            "common_name": common_name,
            "validity_days": validity_days
        }
        
        if san_dns:
            data["san_dns"] = san_dns
        if san_ip:
            data["san_ip"] = san_ip
        
        self.print_info(f"Issuing certificate for {common_name}")
        response = self._make_request("POST", "/api/certificates/issue", data)
        
        self.print_success(f"Certificate issued successfully")
        print(f"  Certificate ID: {response.get('certificate_id')}")
        print(f"  Serial Number: {response.get('serial_number')}")
        print(f"  Common Name: {response.get('common_name')}")
        print(f"  Valid Until: {response.get('valid_until')}")
        print(f"  Certificate Path: {response.get('certificate_path')}")
        print(f"  Private Key Path: {response.get('private_key_path')}")
    
    def cert_renew(self, service_id: str, validity_days: int = 365):
        """Renew existing certificate."""
        self.print_header(f"Renew Certificate: {service_id}")
        
        data = {
            "service_id": service_id,
            "validity_days": validity_days
        }
        
        self.print_info(f"Renewing certificate for {service_id}")
        response = self._make_request("POST", "/api/certificates/renew", data)
        
        self.print_success(f"Certificate renewed successfully")
        print(f"  Certificate ID: {response.get('certificate_id')}")
        print(f"  Serial Number: {response.get('serial_number')}")
        print(f"  Valid Until: {response.get('valid_until')}")
    
    def cert_revoke(self, service_id: str, reason: str = "unspecified"):
        """Revoke certificate."""
        self.print_header(f"Revoke Certificate: {service_id}")
        
        data = {
            "service_id": service_id,
            "reason": reason
        }
        
        self.print_warning(f"Revoking certificate for {service_id} (reason: {reason})")
        
        # Confirmation prompt
        confirm = input(f"{Fore.YELLOW}Are you sure? (yes/no): {Style.RESET_ALL}")
        if confirm.lower() not in ['yes', 'y']:
            self.print_info("Revocation cancelled")
            return
        
        response = self._make_request("POST", "/api/certificates/revoke", data)
        
        self.print_success(f"Certificate revoked successfully")
        print(f"  Certificate ID: {response.get('certificate_id')}")
        print(f"  Revoked At: {response.get('revoked_at')}")
        print(f"  Reason: {response.get('reason')}")
    
    def cert_info(self, service_id: str):
        """Display certificate information."""
        self.print_header(f"Certificate Info: {service_id}")
        
        response = self._make_request("GET", f"/api/certificates/{service_id}")
        
        print(f"\n{Fore.CYAN}Certificate Details:{Style.RESET_ALL}")
        print(f"  Certificate ID: {response.get('certificate_id')}")
        print(f"  Service ID: {response.get('service_id')}")
        print(f"  Common Name: {response.get('common_name')}")
        print(f"  Serial Number: {response.get('serial_number')}")
        print(f"  Status: {response.get('status')}")
        print(f"  Issued At: {response.get('issued_at')}")
        print(f"  Expires At: {response.get('expires_at')}")
        print(f"  Days Until Expiry: {response.get('days_until_expiry')}")
        
        if response.get('san_dns'):
            print(f"  SAN DNS: {', '.join(response['san_dns'])}")
        if response.get('san_ip'):
            print(f"  SAN IP: {', '.join(response['san_ip'])}")
        
        if response.get('revoked_at'):
            print(f"\n{Fore.RED}  Revoked At: {response['revoked_at']}{Style.RESET_ALL}")
            print(f"{Fore.RED}  Revocation Reason: {response.get('revocation_reason')}{Style.RESET_ALL}")
    
    def cert_list(self, status: Optional[str] = None, service_id: Optional[str] = None):
        """List certificates."""
        self.print_header("Certificates")
        
        params = []
        if status:
            params.append(f"status={status}")
        if service_id:
            params.append(f"service_id={service_id}")
        
        query_string = "?" + "&".join(params) if params else ""
        response = self._make_request("GET", f"/api/certificates{query_string}")
        
        certificates = response.get('certificates', [])
        
        if not certificates:
            self.print_warning("No certificates found")
            return
        
        # Prepare table data
        table_data = []
        for cert in certificates:
            table_data.append({
                "Service ID": cert['service_id'],
                "Common Name": cert['common_name'],
                "Status": cert['status'],
                "Serial": cert['serial_number'][:16] + "...",
                "Expires": cert['expires_at'][:10],
                "Days Left": cert['days_until_expiry']
            })
        
        self.print_table(table_data)
        print(f"\nTotal: {len(certificates)} certificate(s)")
    
    # ==================== Service Commands ====================
    
    def service_register(self, service_id: str, service_name: str,
                         endpoints: List[str],
                         health_check_url: Optional[str] = None,
                         metadata: Optional[Dict] = None):
        """Register service."""
        self.print_header(f"Register Service: {service_id}")
        
        data = {
            "service_id": service_id,
            "service_name": service_name,
            "endpoints": endpoints
        }
        
        if health_check_url:
            data["health_check_url"] = health_check_url
        if metadata:
            data["metadata"] = metadata
        
        self.print_info(f"Registering service: {service_name}")
        response = self._make_request("POST", "/api/services/register", data)
        
        self.print_success(f"Service registered successfully")
        print(f"  Service ID: {response.get('service_id')}")
        print(f"  Service Name: {response.get('service_name')}")
        print(f"  Registered At: {response.get('registered_at')}")
        print(f"  Endpoints: {', '.join(response.get('endpoints', []))}")
    
    def service_list(self):
        """List registered services."""
        self.print_header("Registered Services")
        
        response = self._make_request("GET", "/api/services")
        services = response.get('services', [])
        
        if not services:
            self.print_warning("No services registered")
            return
        
        # Prepare table data
        table_data = []
        for svc in services:
            table_data.append({
                "Service ID": svc['service_id'],
                "Name": svc['service_name'],
                "Status": svc['status'],
                "Endpoints": len(svc.get('endpoints', [])),
                "Registered": svc['registered_at'][:10]
            })
        
        self.print_table(table_data)
        print(f"\nTotal: {len(services)} service(s)")
    
    def service_info(self, service_id: str):
        """Display service information."""
        self.print_header(f"Service Info: {service_id}")
        
        response = self._make_request("GET", f"/api/services/{service_id}")
        
        print(f"\n{Fore.CYAN}Service Details:{Style.RESET_ALL}")
        print(f"  Service ID: {response.get('service_id')}")
        print(f"  Service Name: {response.get('service_name')}")
        print(f"  Status: {response.get('status')}")
        print(f"  Registered At: {response.get('registered_at')}")
        
        if response.get('endpoints'):
            print(f"\n  Endpoints:")
            for ep in response['endpoints']:
                print(f"    - {ep}")
        
        if response.get('health_check_url'):
            print(f"\n  Health Check: {response['health_check_url']}")
        
        if response.get('metadata'):
            print(f"\n  Metadata:")
            for key, value in response['metadata'].items():
                print(f"    {key}: {value}")
        
        # Certificate info
        if response.get('certificate'):
            cert = response['certificate']
            print(f"\n{Fore.CYAN}  Certificate:{Style.RESET_ALL}")
            print(f"    Status: {cert.get('status')}")
            print(f"    Expires: {cert.get('expires_at')}")
            print(f"    Days Left: {cert.get('days_until_expiry')}")
    
    # ==================== CRL Commands ====================
    
    def crl_generate(self):
        """Generate Certificate Revocation List."""
        self.print_header("Generate CRL")
        
        self.print_info("Generating CRL...")
        response = self._make_request("POST", "/api/crl/generate", {})
        
        self.print_success("CRL generated successfully")
        print(f"  CRL Path: {response.get('crl_path')}")
        print(f"  Generated At: {response.get('generated_at')}")
        print(f"  Revoked Certificates: {response.get('revoked_count')}")
    
    def crl_info(self):
        """Display CRL information."""
        self.print_header("CRL Information")
        
        response = self._make_request("GET", "/api/crl/info")
        
        print(f"\n{Fore.CYAN}CRL Details:{Style.RESET_ALL}")
        print(f"  Last Update: {response.get('last_update')}")
        print(f"  Next Update: {response.get('next_update')}")
        print(f"  Revoked Certificates: {response.get('revoked_count')}")
        print(f"  CRL Number: {response.get('crl_number')}")
    
    # ==================== Health & Statistics ====================
    
    def health_check(self):
        """Perform system health check."""
        self.print_header("System Health Check")
        
        response = self._make_request("GET", "/api/health")
        
        status = response.get('status')
        if status == 'healthy':
            self.print_success(f"System Status: {status.upper()}")
        else:
            self.print_error(f"System Status: {status.upper()}")
        
        print(f"\n{Fore.CYAN}Components:{Style.RESET_ALL}")
        
        components = response.get('components', {})
        for name, comp_status in components.items():
            icon = "✓" if comp_status == "healthy" else "✗"
            color = Fore.GREEN if comp_status == "healthy" else Fore.RED
            print(f"  {color}{icon} {name}: {comp_status}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Statistics:{Style.RESET_ALL}")
        stats = response.get('statistics', {})
        print(f"  Total Certificates: {stats.get('total_certificates', 0)}")
        print(f"  Active Certificates: {stats.get('active_certificates', 0)}")
        print(f"  Revoked Certificates: {stats.get('revoked_certificates', 0)}")
        print(f"  Registered Services: {stats.get('registered_services', 0)}")
        
        print(f"\n{Fore.CYAN}Server Info:{Style.RESET_ALL}")
        print(f"  Version: {response.get('version', 'N/A')}")
        print(f"  Uptime: {response.get('uptime', 'N/A')}")
    
    def db_stats(self):
        """Display database statistics."""
        self.print_header("Database Statistics")
        
        response = self._make_request("GET", "/api/health")
        stats = response.get('statistics', {})
        
        table_data = [
            {"Metric": "Total Certificates", "Count": stats.get('total_certificates', 0)},
            {"Metric": "Active Certificates", "Count": stats.get('active_certificates', 0)},
            {"Metric": "Expired Certificates", "Count": stats.get('expired_certificates', 0)},
            {"Metric": "Revoked Certificates", "Count": stats.get('revoked_certificates', 0)},
            {"Metric": "Registered Services", "Count": stats.get('registered_services', 0)},
            {"Metric": "Active Services", "Count": stats.get('active_services', 0)},
        ]
        
        self.print_table(table_data)


# ==================== CLI Parser Setup ====================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with all commands."""
    
    parser = argparse.ArgumentParser(
        prog='pki-admin',
        description='VCC PKI Administration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize Root CA
  pki-admin ca init-root --cn "VCC Root CA" --country DE --org "VCC GmbH"
  
  # Issue certificate
  pki-admin cert issue veritas-backend --cn "veritas-backend.vcc.local" --san-dns veritas-backend localhost
  
  # List certificates
  pki-admin cert list --status active
  
  # Register service
  pki-admin service register veritas-backend --name "VERITAS Backend" --endpoints https://veritas.vcc.local:8001
  
  # Health check
  pki-admin health check
"""
    )
    
    parser.add_argument('--server', default='https://localhost:8443',
                        help='PKI server URL (default: https://localhost:8443)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL verification (for self-signed certs)')
    parser.add_argument('--password', help='CA password (or use VCC_CA_PASSWORD env var)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # ==================== CA Commands ====================
    
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command')
    
    # ca init-root
    init_root = ca_subparsers.add_parser('init-root', help='Initialize Root CA')
    init_root.add_argument('--cn', '--common-name', required=True, help='Common Name')
    init_root.add_argument('--country', required=True, help='Country code (e.g., DE)')
    init_root.add_argument('--org', '--organization', required=True, help='Organization name')
    init_root.add_argument('--key-size', type=int, default=4096, help='Key size (default: 4096)')
    init_root.add_argument('--validity-days', type=int, default=3650, help='Validity in days (default: 3650)')
    
    # ca create-intermediate
    create_inter = ca_subparsers.add_parser('create-intermediate', help='Create Intermediate CA')
    create_inter.add_argument('--cn', '--common-name', required=True, help='Common Name')
    create_inter.add_argument('--country', required=True, help='Country code (e.g., DE)')
    create_inter.add_argument('--org', '--organization', required=True, help='Organization name')
    create_inter.add_argument('--key-size', type=int, default=2048, help='Key size (default: 2048)')
    create_inter.add_argument('--validity-days', type=int, default=1825, help='Validity in days (default: 1825)')
    
    # ca info
    ca_subparsers.add_parser('info', help='Display CA information')
    
    # ==================== Certificate Commands ====================
    
    cert_parser = subparsers.add_parser('cert', help='Certificate operations')
    cert_subparsers = cert_parser.add_subparsers(dest='cert_command')
    
    # cert issue
    issue = cert_subparsers.add_parser('issue', help='Issue new certificate')
    issue.add_argument('service_id', help='Service ID')
    issue.add_argument('--cn', '--common-name', required=True, help='Common Name')
    issue.add_argument('--san-dns', nargs='+', help='SAN DNS names')
    issue.add_argument('--san-ip', nargs='+', help='SAN IP addresses')
    issue.add_argument('--validity-days', type=int, default=365, help='Validity in days (default: 365)')
    
    # cert renew
    renew = cert_subparsers.add_parser('renew', help='Renew certificate')
    renew.add_argument('service_id', help='Service ID')
    renew.add_argument('--validity-days', type=int, default=365, help='Validity in days (default: 365)')
    
    # cert revoke
    revoke = cert_subparsers.add_parser('revoke', help='Revoke certificate')
    revoke.add_argument('service_id', help='Service ID')
    revoke.add_argument('--reason', default='unspecified',
                        choices=['unspecified', 'key_compromise', 'ca_compromise', 'affiliation_changed',
                                 'superseded', 'cessation_of_operation', 'certificate_hold'],
                        help='Revocation reason (default: unspecified)')
    
    # cert info
    info = cert_subparsers.add_parser('info', help='Display certificate info')
    info.add_argument('service_id', help='Service ID')
    
    # cert list
    cert_list = cert_subparsers.add_parser('list', help='List certificates')
    cert_list.add_argument('--status', choices=['active', 'expired', 'revoked'], help='Filter by status')
    cert_list.add_argument('--service-id', help='Filter by service ID')
    
    # ==================== Service Commands ====================
    
    service_parser = subparsers.add_parser('service', help='Service operations')
    service_subparsers = service_parser.add_subparsers(dest='service_command')
    
    # service register
    register = service_subparsers.add_parser('register', help='Register service')
    register.add_argument('service_id', help='Service ID')
    register.add_argument('--name', required=True, help='Service name')
    register.add_argument('--endpoints', nargs='+', required=True, help='Service endpoints')
    register.add_argument('--health-url', help='Health check URL')
    register.add_argument('--metadata', type=json.loads, help='Metadata (JSON string)')
    
    # service list
    service_subparsers.add_parser('list', help='List services')
    
    # service info
    svc_info = service_subparsers.add_parser('info', help='Display service info')
    svc_info.add_argument('service_id', help='Service ID')
    
    # ==================== CRL Commands ====================
    
    crl_parser = subparsers.add_parser('crl', help='CRL operations')
    crl_subparsers = crl_parser.add_subparsers(dest='crl_command')
    
    crl_subparsers.add_parser('generate', help='Generate CRL')
    crl_subparsers.add_parser('info', help='Display CRL info')
    
    # ==================== Health Commands ====================
    
    health_parser = subparsers.add_parser('health', help='Health check')
    health_subparsers = health_parser.add_subparsers(dest='health_command')
    
    health_subparsers.add_parser('check', help='Perform health check')
    
    # ==================== DB Commands ====================
    
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command')
    
    db_subparsers.add_parser('stats', help='Display database statistics')
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize CLI
    cli = PKIAdminCLI(
        server_url=args.server,
        verify_ssl=not args.no_verify_ssl
    )
    
    # Set password if provided
    if args.password:
        os.environ['VCC_CA_PASSWORD'] = args.password
    
    try:
        # Route to appropriate command handler
        
        # CA Commands
        if args.command == 'ca':
            if args.ca_command == 'init-root':
                cli.ca_init_root(
                    common_name=args.cn,
                    country=args.country,
                    org=args.org,
                    password=args.password,
                    key_size=args.key_size,
                    validity_days=args.validity_days
                )
            elif args.ca_command == 'create-intermediate':
                cli.ca_create_intermediate(
                    common_name=args.cn,
                    country=args.country,
                    org=args.org,
                    password=args.password,
                    key_size=args.key_size,
                    validity_days=args.validity_days
                )
            elif args.ca_command == 'info':
                cli.ca_info()
            else:
                parser.error(f"Unknown CA command: {args.ca_command}")
        
        # Certificate Commands
        elif args.command == 'cert':
            if args.cert_command == 'issue':
                cli.cert_issue(
                    service_id=args.service_id,
                    common_name=args.cn,
                    san_dns=args.san_dns,
                    san_ip=args.san_ip,
                    validity_days=args.validity_days
                )
            elif args.cert_command == 'renew':
                cli.cert_renew(
                    service_id=args.service_id,
                    validity_days=args.validity_days
                )
            elif args.cert_command == 'revoke':
                cli.cert_revoke(
                    service_id=args.service_id,
                    reason=args.reason
                )
            elif args.cert_command == 'info':
                cli.cert_info(service_id=args.service_id)
            elif args.cert_command == 'list':
                cli.cert_list(
                    status=args.status,
                    service_id=getattr(args, 'service_id', None)
                )
            else:
                parser.error(f"Unknown cert command: {args.cert_command}")
        
        # Service Commands
        elif args.command == 'service':
            if args.service_command == 'register':
                cli.service_register(
                    service_id=args.service_id,
                    service_name=args.name,
                    endpoints=args.endpoints,
                    health_check_url=getattr(args, 'health_url', None),
                    metadata=getattr(args, 'metadata', None)
                )
            elif args.service_command == 'list':
                cli.service_list()
            elif args.service_command == 'info':
                cli.service_info(service_id=args.service_id)
            else:
                parser.error(f"Unknown service command: {args.service_command}")
        
        # CRL Commands
        elif args.command == 'crl':
            if args.crl_command == 'generate':
                cli.crl_generate()
            elif args.crl_command == 'info':
                cli.crl_info()
            else:
                parser.error(f"Unknown CRL command: {args.crl_command}")
        
        # Health Commands
        elif args.command == 'health':
            if args.health_command == 'check':
                cli.health_check()
            else:
                parser.error(f"Unknown health command: {args.health_command}")
        
        # DB Commands
        elif args.command == 'db':
            if args.db_command == 'stats':
                cli.db_stats()
            else:
                parser.error(f"Unknown db command: {args.db_command}")
        
        else:
            parser.error(f"Unknown command: {args.command}")
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        cli.print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
