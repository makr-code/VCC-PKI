#!/bin/bash
# VCC PKI Health Check Script
# Überprüft die Gesundheit aller VCC Services und deren PKI-Integration

set -e

VCC_PKI_API_URL="https://vcc-pki-api:8443"
VCC_SERVICES=("argus" "covina" "clara" "veritas" "vpb")

echo "🔍 VCC PKI Ecosystem Health Check"
echo "================================="

# Funktion für Service Health Check
check_service_health() {
    local service_name=$1
    local service_url=$2
    
    echo -n "Checking $service_name... "
    
    if curl -s --connect-timeout 5 "$service_url" > /dev/null 2>&1; then
        echo "✅ OK"
        return 0
    else
        echo "❌ FAILED"
        return 1
    fi
}

# Funktion für PKI Certificate Check
check_service_certificate() {
    local service_name=$1
    
    echo -n "Checking $service_name certificate... "
    
    # VCC PKI API aufrufen für Certificate Status
    cert_status=$(curl -s -k "$VCC_PKI_API_URL/api/v1/services/$service_name/certificate/status" 2>/dev/null || echo "ERROR")
    
    if [[ "$cert_status" == *"valid"* ]]; then
        echo "✅ VALID"
        return 0
    else
        echo "❌ INVALID"
        return 1
    fi
}

# Main Health Check
main() {
    local failed_checks=0
    
    echo "1. VCC PKI API Health"
    echo "--------------------"
    if check_service_health "VCC PKI API" "$VCC_PKI_API_URL/health"; then
        echo "   PKI API is operational"
    else
        echo "   ⚠️  PKI API is not accessible - VCC security compromised!"
        ((failed_checks++))
    fi
    
    echo
    echo "2. VCC Service Health"
    echo "--------------------"
    
    # Check individual VCC services
    service_urls=(
        "http://argus-backend:8000/health"
        "http://covina-core:8001/health"  
        "http://clara-engine:8002/health"
        "http://veritas-orchestrator:8003/health"
        "http://vpb-services:8004/health"
    )
    
    for i in "${!VCC_SERVICES[@]}"; do
        service="${VCC_SERVICES[$i]}"
        url="${service_urls[$i]}"
        
        if ! check_service_health "$service" "$url"; then
            ((failed_checks++))
        fi
    done
    
    echo
    echo "3. VCC PKI Certificate Status"  
    echo "----------------------------"
    
    for service in "${VCC_SERVICES[@]}"; do
        if ! check_service_certificate "$service"; then
            ((failed_checks++))
        fi
    done
    
    echo
    echo "4. Cross-Service mTLS Connectivity"
    echo "---------------------------------"
    
    # Test mTLS zwischen kritischen Services
    echo -n "Testing Argus -> Covina mTLS... "
    if docker exec argus-backend curl -s --cert /app/certs/argus-service.crt --key /app/certs/argus-service.key https://covina-core:8001/api/health > /dev/null 2>&1; then
        echo "✅ OK"
    else
        echo "❌ FAILED"
        ((failed_checks++))
    fi
    
    echo -n "Testing Veritas -> Clara mTLS... "
    if docker exec veritas-orchestrator curl -s --cert /app/certs/veritas-service.crt --key /app/certs/veritas-service.key https://clara-engine:8002/api/health > /dev/null 2>&1; then
        echo "✅ OK"
    else
        echo "❌ FAILED"
        ((failed_checks++))
    fi
    
    echo
    echo "5. Certificate Expiry Check"
    echo "--------------------------"
    
    # Check certificate expiration warnings
    expiry_check=$(curl -s -k "$VCC_PKI_API_URL/api/v1/certificates/expiry-warnings" 2>/dev/null || echo "[]")
    
    if [[ "$expiry_check" == "[]" ]]; then
        echo "✅ No certificates expiring soon"
    else
        echo "⚠️  Certificates expiring soon:"
        echo "$expiry_check" | jq -r '.[] | "   - \(.service_name): expires \(.expires_in_days) days"'
    fi
    
    echo
    echo "================================="
    
    if [[ $failed_checks -eq 0 ]]; then
        echo "🎉 All VCC PKI health checks passed!"
        echo "   VCC Ecosystem is secure and operational."
        exit 0
    else
        echo "💥 $failed_checks health check(s) failed!"
        echo "   VCC Ecosystem requires attention."
        exit 1
    fi
}

# Helper function für VCC Certificate Renewal
renew_expiring_certificates() {
    echo "🔄 Auto-renewing expiring VCC certificates..."
    
    for service in "${VCC_SERVICES[@]}"; do
        echo "Checking renewal for $service..."
        
        renewal_result=$(curl -s -k -X POST "$VCC_PKI_API_URL/api/v1/services/$service/certificate/renew" 2>/dev/null)
        
        if [[ "$renewal_result" == *"renewed"* ]]; then
            echo "✅ $service certificate renewed"
            
            # Restart service für neues Zertifikat
            docker restart "${service}-backend" 2>/dev/null || docker restart "${service}-core" 2>/dev/null || docker restart "${service}-engine" 2>/dev/null || docker restart "${service}-orchestrator" 2>/dev/null || docker restart "${service}-services" 2>/dev/null || true
        fi
    done
}

# Command line interface
case "${1:-health}" in
    "health"|"check")
        main
        ;;
    "renew")
        renew_expiring_certificates
        ;;
    "monitor")
        echo "🔄 Starting continuous VCC PKI monitoring..."
        while true; do
            main
            echo "Waiting 5 minutes..."
            sleep 300
        done
        ;;
    *)
        echo "Usage: $0 {health|renew|monitor}"
        echo "  health  - Run comprehensive VCC PKI health check"
        echo "  renew   - Auto-renew expiring certificates"  
        echo "  monitor - Continuous health monitoring"
        exit 1
        ;;
esac