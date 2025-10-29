# VCC PKI Admin CLI Tool

A comprehensive command-line interface for managing the VCC PKI infrastructure.

## Features

- ✅ **CA Operations**: Initialize Root CA, create Intermediate CA, display CA info
- ✅ **Certificate Lifecycle**: Issue, renew, revoke, list certificates
- ✅ **Service Management**: Register services, list services, display service info
- ✅ **CRL Operations**: Generate and display Certificate Revocation Lists
- ✅ **Health Checks**: System health monitoring and database statistics
- ✅ **Color Output**: Beautiful colored terminal output (Windows/Linux compatible)
- ✅ **Table Formatting**: Clean table display for lists and statistics
- ✅ **SSL Support**: Secure HTTPS communication with PKI server

## Installation

### Basic Installation

```bash
# No additional dependencies required
# Works with Python standard library only
python pki_admin_cli.py --help
```

### With Color & Table Support (Recommended)

```bash
pip install -r cli_requirements.txt
```

This installs:
- `colorama`: Cross-platform colored output
- `tabulate`: Beautiful table formatting

## Usage

### Quick Start

```bash
# Display help
python pki_admin_cli.py --help

# Initialize Root CA
python pki_admin_cli.py ca init-root --cn "VCC Root CA" --country DE --org "VCC GmbH"

# Issue certificate
python pki_admin_cli.py cert issue veritas-backend --cn "veritas-backend.vcc.local" --san-dns veritas-backend localhost

# List certificates
python pki_admin_cli.py cert list

# Health check
python pki_admin_cli.py health check
```

### Command Structure

```
pki-admin <category> <command> [options]

Categories:
  ca          CA operations
  cert        Certificate operations
  service     Service management
  crl         CRL operations
  health      Health monitoring
  db          Database operations
```

## Commands Reference

### CA Operations

#### Initialize Root CA

```bash
python pki_admin_cli.py ca init-root \
  --cn "VCC Root CA" \
  --country DE \
  --org "VCC GmbH" \
  --key-size 4096 \
  --validity-days 3650
```

**Options:**
- `--cn`, `--common-name` (required): Common Name for the Root CA
- `--country` (required): Country code (e.g., DE, US)
- `--org`, `--organization` (required): Organization name
- `--key-size` (optional): RSA key size (default: 4096)
- `--validity-days` (optional): Validity period in days (default: 3650 = 10 years)

#### Create Intermediate CA

```bash
python pki_admin_cli.py ca create-intermediate \
  --cn "VCC Intermediate CA" \
  --country DE \
  --org "VCC GmbH" \
  --key-size 2048 \
  --validity-days 1825
```

**Options:**
- Same as Root CA, but with different defaults:
  - `--key-size` default: 2048
  - `--validity-days` default: 1825 (5 years)

#### Display CA Information

```bash
python pki_admin_cli.py ca info
```

Shows Root CA and Intermediate CA details:
- Subject information
- Serial numbers
- Validity periods
- Key sizes

---

### Certificate Operations

#### Issue New Certificate

```bash
python pki_admin_cli.py cert issue veritas-backend \
  --cn "veritas-backend.vcc.local" \
  --san-dns veritas-backend localhost \
  --san-ip 127.0.0.1 192.168.1.100 \
  --validity-days 365
```

**Arguments:**
- `service_id` (positional): Unique service identifier

**Options:**
- `--cn`, `--common-name` (required): Certificate Common Name
- `--san-dns` (optional): Subject Alternative Name - DNS names (space-separated)
- `--san-ip` (optional): Subject Alternative Name - IP addresses (space-separated)
- `--validity-days` (optional): Validity period in days (default: 365)

#### Renew Certificate

```bash
python pki_admin_cli.py cert renew veritas-backend \
  --validity-days 365
```

**Arguments:**
- `service_id` (positional): Service ID to renew

**Options:**
- `--validity-days` (optional): New validity period (default: 365)

#### Revoke Certificate

```bash
python pki_admin_cli.py cert revoke veritas-backend \
  --reason key_compromise
```

**Arguments:**
- `service_id` (positional): Service ID to revoke

**Options:**
- `--reason` (optional): Revocation reason (default: unspecified)
  - Choices: `unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`, `certificate_hold`

**Note:** Requires confirmation (yes/no prompt)

#### Display Certificate Info

```bash
python pki_admin_cli.py cert info veritas-backend
```

Shows detailed certificate information:
- Certificate ID, Serial Number
- Common Name, SANs
- Status, validity dates
- Days until expiry
- Revocation info (if revoked)

#### List Certificates

```bash
# List all certificates
python pki_admin_cli.py cert list

# Filter by status
python pki_admin_cli.py cert list --status active
python pki_admin_cli.py cert list --status expired
python pki_admin_cli.py cert list --status revoked

# Filter by service ID
python pki_admin_cli.py cert list --service-id veritas-backend
```

**Options:**
- `--status` (optional): Filter by status (active, expired, revoked)
- `--service-id` (optional): Filter by service ID

---

### Service Management

#### Register Service

```bash
python pki_admin_cli.py service register veritas-backend \
  --name "VERITAS Backend" \
  --endpoints https://veritas.vcc.local:8001 https://veritas-backup.vcc.local:8001 \
  --health-url https://veritas.vcc.local:8001/health \
  --metadata '{"version": "1.0.0", "environment": "production"}'
```

**Arguments:**
- `service_id` (positional): Unique service identifier

**Options:**
- `--name` (required): Human-readable service name
- `--endpoints` (required): Service endpoints (space-separated URLs)
- `--health-url` (optional): Health check endpoint URL
- `--metadata` (optional): JSON metadata string

#### List Services

```bash
python pki_admin_cli.py service list
```

Shows all registered services with:
- Service ID and Name
- Status
- Number of endpoints
- Registration date

#### Display Service Info

```bash
python pki_admin_cli.py service info veritas-backend
```

Shows detailed service information:
- Service ID, Name, Status
- Registration date
- All endpoints
- Health check URL
- Metadata
- Associated certificate info

---

### CRL Operations

#### Generate CRL

```bash
python pki_admin_cli.py crl generate
```

Generates a new Certificate Revocation List with:
- All revoked certificates
- CRL number
- Next update time

#### Display CRL Info

```bash
python pki_admin_cli.py crl info
```

Shows CRL details:
- Last update time
- Next update time
- Number of revoked certificates
- CRL number

---

### Health & Monitoring

#### Health Check

```bash
python pki_admin_cli.py health check
```

Performs comprehensive health check:
- Overall system status
- Component health (CA, Database, API)
- Statistics:
  - Total/Active/Revoked certificates
  - Registered/Active services
- Server version and uptime

#### Database Statistics

```bash
python pki_admin_cli.py db stats
```

Shows database metrics:
- Total certificates
- Active/Expired/Revoked certificates
- Registered/Active services

---

## Global Options

All commands support these global options:

```bash
--server <URL>          PKI server URL (default: https://localhost:8443)
--no-verify-ssl         Disable SSL verification (for self-signed certs)
--password <PASSWORD>   CA password (or use VCC_CA_PASSWORD env var)
```

### Examples

```bash
# Use different server
python pki_admin_cli.py --server https://pki.vcc.local:8443 cert list

# Disable SSL verification (development)
python pki_admin_cli.py --no-verify-ssl health check

# Provide CA password
python pki_admin_cli.py --password secret123 ca init-root ...
```

---

## Environment Variables

### VCC_CA_PASSWORD

Set the CA password to avoid passing it on command line:

```bash
# Windows (PowerShell)
$env:VCC_CA_PASSWORD = "your-secret-password"

# Linux/macOS
export VCC_CA_PASSWORD="your-secret-password"

# Then use CLI without --password
python pki_admin_cli.py ca init-root --cn "VCC Root CA" --country DE --org "VCC GmbH"
```

---

## Examples

### Complete Workflow

```bash
# 1. Start PKI Server
cd C:\VCC\PKI\src
python pki_server.py --port 8443

# 2. Initialize Root CA (one-time)
python pki_admin_cli.py ca init-root \
  --cn "VCC Root CA" \
  --country DE \
  --org "VCC GmbH"

# 3. Create Intermediate CA (one-time)
python pki_admin_cli.py ca create-intermediate \
  --cn "VCC Intermediate CA" \
  --country DE \
  --org "VCC GmbH"

# 4. Issue certificates for services
python pki_admin_cli.py cert issue veritas-backend \
  --cn "veritas-backend.vcc.local" \
  --san-dns veritas-backend localhost

python pki_admin_cli.py cert issue covina-backend \
  --cn "covina-backend.vcc.local" \
  --san-dns covina-backend localhost

# 5. Register services
python pki_admin_cli.py service register veritas-backend \
  --name "VERITAS Backend" \
  --endpoints https://veritas.vcc.local:8001 \
  --health-url https://veritas.vcc.local:8001/health

# 6. Check system health
python pki_admin_cli.py health check

# 7. List all certificates
python pki_admin_cli.py cert list

# 8. View CA information
python pki_admin_cli.py ca info
```

### Certificate Renewal Workflow

```bash
# Check certificate status
python pki_admin_cli.py cert info veritas-backend

# Renew if expiring soon
python pki_admin_cli.py cert renew veritas-backend --validity-days 365

# Verify renewal
python pki_admin_cli.py cert info veritas-backend
```

### Certificate Revocation Workflow

```bash
# Revoke certificate
python pki_admin_cli.py cert revoke compromised-service --reason key_compromise

# Generate updated CRL
python pki_admin_cli.py crl generate

# Verify revocation
python pki_admin_cli.py cert info compromised-service
python pki_admin_cli.py crl info
```

---

## Output Features

### Color Output

When `colorama` is installed, the CLI uses colors:
- ✅ **Green**: Success messages
- ✗ **Red**: Error messages
- ⚠ **Yellow**: Warnings
- ℹ **Cyan**: Info messages

### Table Formatting

When `tabulate` is installed, lists are displayed as formatted tables:

```
+------------------+--------------------------------+----------+------------------+------------+----------+
| Service ID       | Common Name                    | Status   | Serial           | Expires    | Days Left|
+==================+================================+==========+==================+============+==========+
| veritas-backend  | veritas-backend.vcc.local      | active   | 1a2b3c4d...      | 2026-01-15 | 365      |
| covina-backend   | covina-backend.vcc.local       | active   | 5e6f7g8h...      | 2026-02-20 | 390      |
+------------------+--------------------------------+----------+------------------+------------+----------+
```

Without `tabulate`, falls back to simple formatting.

---

## Error Handling

The CLI handles errors gracefully:

1. **Connection Errors**: If PKI server is not running
   ```
   ✗ Connection Error: [Errno 10061] No connection could be made
   ✗ Is the PKI server running at https://localhost:8443?
   ```

2. **HTTP Errors**: If API request fails
   ```
   ✗ HTTP Error 404: Certificate not found for service: unknown-service
   ```

3. **Validation Errors**: If parameters are invalid
   ```
   ✗ HTTP Error 400: service_id must match pattern ^[a-z0-9-]+$
   ```

4. **Keyboard Interrupt**: Ctrl+C handling
   ```
   Operation cancelled by user
   ```

---

## Integration with PKI Client Library

The CLI tool complements the Python PKI Client Library:

**CLI Tool (pki_admin_cli.py):**
- **Admin Operations**: Manual certificate management, CA operations
- **Interactive**: Human-friendly commands and output
- **Use Cases**: Initial setup, troubleshooting, manual interventions

**Client Library (vcc_pki_client):**
- **Service Integration**: Programmatic certificate management
- **Automated**: Auto-renewal, background operations
- **Use Cases**: Production services (VERITAS, Covina), applications

### Example Workflow

1. **Admin**: Initialize PKI infrastructure
   ```bash
   python pki_admin_cli.py ca init-root ...
   python pki_admin_cli.py ca create-intermediate ...
   ```

2. **Service**: Auto-request certificate on startup
   ```python
   from vcc_pki_client import PKIClient
   pki = PKIClient(pki_server_url="...", service_id="veritas-backend")
   pki.request_certificate(common_name="...")
   pki.enable_auto_renewal()
   ```

3. **Admin**: Monitor and manage
   ```bash
   python pki_admin_cli.py cert list
   python pki_admin_cli.py health check
   ```

4. **Service**: Automatic renewal (background)
   ```python
   # Renewal happens automatically every 6 hours
   # No manual intervention needed!
   ```

---

## Troubleshooting

### CLI Not Working

**Problem:** `python pki_admin_cli.py` command not found

**Solution:**
```bash
# Use full path
cd C:\VCC\PKI
python pki_admin_cli.py --help

# Or add to PATH
# (Windows) Add C:\VCC\PKI to your PATH environment variable
```

### No Colors in Output

**Problem:** No colored output

**Solution:**
```bash
# Install colorama
pip install colorama

# Or install all optional dependencies
pip install -r cli_requirements.txt
```

### Table Formatting Issues

**Problem:** Tables look messy

**Solution:**
```bash
# Install tabulate
pip install tabulate

# Or install all optional dependencies
pip install -r cli_requirements.txt
```

### SSL Verification Errors

**Problem:** SSL certificate verification failed

**Solution:**
```bash
# Use --no-verify-ssl flag for self-signed certificates
python pki_admin_cli.py --no-verify-ssl health check
```

### Connection Refused

**Problem:** Cannot connect to PKI server

**Solution:**
```bash
# 1. Check if PKI server is running
cd C:\VCC\PKI\src
python pki_server.py --port 8443

# 2. Use correct server URL
python pki_admin_cli.py --server https://localhost:8443 health check
```

---

## Development

### Project Structure

```
C:\VCC\PKI\
├── pki_admin_cli.py          # Main CLI tool
├── cli_requirements.txt       # Optional dependencies
└── docs\
    └── PKI_ADMIN_CLI.md      # This README
```

### Adding New Commands

1. Add command to `create_parser()` function
2. Implement handler method in `PKIAdminCLI` class
3. Add routing logic in `main()` function
4. Update this README with usage examples

### Code Style

- Type hints for all parameters
- Docstrings for all methods
- Color output with fallback
- Table formatting with fallback
- Comprehensive error handling

---

## License

Part of the VCC PKI Infrastructure project.

## Support

For issues, questions, or feature requests, please contact the VCC development team.

---

**Last Updated:** 2025-10-13  
**Version:** 1.0.0  
**Status:** ✅ Production Ready
