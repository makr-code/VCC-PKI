#!/bin/bash
# VCC-PKI Production Deployment Security Checklist
# Run this script before deploying to production
# Exit code 0 = all checks passed, non-zero = issues found

set -e

echo "========================================"
echo "VCC-PKI Security Deployment Checklist"
echo "========================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ISSUES=0
WARNINGS=0

# Function to print results
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((ISSUES++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARNINGS++))
}

echo "1. Environment Configuration Checks"
echo "======================================"

# Check for .env file
if [ -f ".env" ]; then
    check_warn ".env file found - ensure secrets are managed via vault in production"
else
    check_pass "No .env file in repository"
fi

# Check for hardcoded passwords
echo ""
echo "2. Source Code Security Checks"
echo "======================================"

if grep -r "password\s*=\s*['\"][^$]" src/ --include="*.py" | grep -v "password:" | grep -v "password=None" | grep -v "password=password" | grep -v "# " | grep -v "def " | grep -v "Args:" | grep -v "param" > /dev/null 2>&1; then
    check_fail "Potential hardcoded passwords found in source code"
    grep -r "password\s*=\s*['\"][^$]" src/ --include="*.py" | grep -v "password:" | grep -v "password=None" | grep -v "password=password" | grep -v "# " | grep -v "def " | grep -v "Args:" | grep -v "param" | head -5
else
    check_pass "No hardcoded passwords found"
fi

# Check for environment variable usage
if grep -r "VCC_INTERMEDIATE_CA_PASSWORD" src/ --include="*.py" > /dev/null; then
    check_pass "CA password uses environment variable"
else
    check_fail "CA password not using environment variable"
fi

echo ""
echo "3. File Permissions Checks"
echo "======================================"

# Check CA storage directory exists
if [ -d "ca_storage" ]; then
    # Check for private keys
    if find ca_storage -name "*.key" -o -name "*_key.pem" > /dev/null 2>&1; then
        check_warn "Private keys found in ca_storage - ensure proper permissions (400)"
        
        # Check permissions on key files
        for key in $(find ca_storage -name "*.key" -o -name "*_key.pem"); do
            perms=$(stat -c "%a" "$key" 2>/dev/null || stat -f "%A" "$key" 2>/dev/null)
            if [ "$perms" != "400" ] && [ "$perms" != "600" ]; then
                check_warn "Key file $key has permissions $perms (should be 400)"
            fi
        done
    fi
else
    check_warn "ca_storage directory not found - will be created on first run"
fi

# Check database permissions
if [ -f "database/pki_server.db" ]; then
    perms=$(stat -c "%a" "database/pki_server.db" 2>/dev/null || stat -f "%A" "database/pki_server.db" 2>/dev/null)
    if [ "$perms" = "600" ] || [ "$perms" = "644" ]; then
        check_pass "Database file has appropriate permissions ($perms)"
    else
        check_warn "Database file has permissions $perms (recommended: 600)"
    fi
fi

echo ""
echo "4. Configuration Security Checks"
echo "======================================"

# Check if mTLS is enabled in config
if grep -q "enabled: true" config/pki_server.yaml | grep -A 5 "mtls:" > /dev/null 2>&1; then
    check_pass "mTLS configuration found in config"
else
    check_warn "mTLS not enabled - recommended for production"
fi

# Check SSL configuration
if grep -q "enabled: true" config/pki_server.yaml | grep -A 5 "ssl:" > /dev/null 2>&1; then
    check_pass "SSL/TLS enabled in configuration"
else
    check_fail "SSL/TLS not enabled in configuration"
fi

echo ""
echo "5. Cryptographic Standards Checks"
echo "======================================"

# Check for weak algorithms
if grep -r "SHA1\|MD5\|DES\|RC4" src/ --include="*.py" | grep -v "SHA256\|SHA384\|SHA512" > /dev/null 2>&1; then
    check_fail "Weak cryptographic algorithms found (SHA1, MD5, DES, RC4)"
    grep -r "SHA1\|MD5\|DES\|RC4" src/ --include="*.py" | grep -v "SHA256\|SHA384\|SHA512" | head -3
else
    check_pass "No weak cryptographic algorithms found"
fi

# Check for strong key sizes
if grep -r "key_size.*=.*1024" src/ --include="*.py" > /dev/null 2>&1; then
    check_fail "1024-bit keys found - minimum 2048 bits required"
else
    check_pass "No weak key sizes (< 2048 bits) found"
fi

echo ""
echo "6. Dependency Security Checks"
echo "======================================"

# Check if pip-audit is available
if command -v pip-audit &> /dev/null; then
    echo "Running pip-audit to check for vulnerabilities..."
    if pip-audit --desc > /tmp/pip-audit-output.txt 2>&1; then
        check_pass "No known vulnerabilities in dependencies"
    else
        check_warn "Vulnerabilities found in dependencies - review /tmp/pip-audit-output.txt"
        head -20 /tmp/pip-audit-output.txt
    fi
else
    check_warn "pip-audit not installed - install with: pip install pip-audit"
fi

echo ""
echo "7. Git Security Checks"
echo "======================================"

# Check .gitignore for sensitive files
required_ignores=(".env" "*.key" "*.pem" "*.crt" "*.p12" "*.pfx")
for pattern in "${required_ignores[@]}"; do
    if grep -q "^$pattern" .gitignore; then
        check_pass "$pattern is in .gitignore"
    else
        check_fail "$pattern should be in .gitignore"
    fi
done

# Check for secrets in git history
if git log --all --pretty=format: -S "password" -S "secret" -S "key" | wc -l | grep -q "^0$"; then
    check_pass "No obvious secrets in git history"
else
    check_warn "Potential secrets found in git history - review carefully"
fi

echo ""
echo "8. Documentation Checks"
echo "======================================"

if [ -f "SECURITY.md" ]; then
    check_pass "SECURITY.md documentation exists"
else
    check_warn "SECURITY.md not found - create security documentation"
fi

if [ -f ".env.example" ]; then
    check_pass ".env.example template exists"
else
    check_warn ".env.example not found - create environment template"
fi

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo -e "${RED}Critical Issues: $ISSUES${NC}"
echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
echo ""

if [ $ISSUES -gt 0 ]; then
    echo -e "${RED}DEPLOYMENT BLOCKED${NC}"
    echo "Fix critical issues before deploying to production"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}DEPLOYMENT WITH CAUTION${NC}"
    echo "Review warnings and address before production deployment"
    exit 2
else
    echo -e "${GREEN}ALL CHECKS PASSED${NC}"
    echo "System is ready for production deployment"
    exit 0
fi
