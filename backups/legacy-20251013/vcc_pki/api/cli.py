"""VCC PKI CLI - Command Line Interface

CLI tool for PKI management operations.
"""

import click
import json
import sys
from pathlib import Path
from typing import Optional
from .pki_service import PKIService


@click.group()
@click.version_option(version="0.1.0", prog_name="vcc-pki")
@click.option('--mode', type=click.Choice(['mock', 'real']), default='mock',
              help='PKI mode: mock (testing) or real (production)')
@click.pass_context
def main(ctx, mode):
    """VCC PKI - Certificate & Signing Management
    
    PKI/CA Library für das Covina Framework.
    
    Examples:
    
      # Certificate erstellen
      vcc-pki create-cert --common-name test.local --output cert.json
      
      # Dokument signieren
      vcc-pki sign --document file.txt --cert cert.json --output sig.json
      
      # Signatur verifizieren
      vcc-pki verify --document file.txt --signature sig.json --cert cert.json
    """
    ctx.ensure_object(dict)
    ctx.obj['mode'] = mode
    ctx.obj['pki'] = PKIService(mode=mode)


@main.command()
@click.option('--common-name', '-cn', required=True, help='Common Name (CN)')
@click.option('--organization', '-o', help='Organization (O)')
@click.option('--organizational-unit', '-ou', help='Organizational Unit (OU)')
@click.option('--locality', '-l', help='Locality (L)')
@click.option('--state', '-st', help='State/Province (ST)')
@click.option('--country', '-c', help='Country (C)')
@click.option('--validity-days', '-v', default=365, type=int, help='Validity in days')
@click.option('--output', '-out', required=True, type=click.Path(), help='Output JSON file')
@click.pass_context
def create_cert(ctx, common_name, organization, organizational_unit, locality, 
                state, country, validity_days, output):
    """Erstellt ein neues Zertifikat mit Keypair
    
    Das Zertifikat wird als JSON-Datei gespeichert mit:
    - certificate (PEM/JSON)
    - private_key
    - public_key
    - subject DN
    - certificate info
    
    Example:
      vcc-pki create-cert --common-name test.covina.local \\
                         --organization Covina \\
                         --validity-days 365 \\
                         --output mycert.json
    """
    
    pki = ctx.obj['pki']
    
    try:
        click.echo(f"📋 Creating certificate for: {common_name}")
        
        result = pki.create_certificate(
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            locality=locality,
            state=state,
            country=country,
            validity_days=validity_days
        )
        
        # Als JSON speichern
        output_data = {
            "certificate": result["certificate"].decode('utf-8'),
            "private_key": result["private_key"].decode('utf-8'),
            "public_key": result["public_key"].decode('utf-8'),
            "subject": result["subject"],
            "info": result["info"]
        }
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        click.echo(f"✅ Certificate created: {output}")
        click.echo(f"   Serial: {result['info']['serial']}")
        click.echo(f"   Subject: {result['subject']}")
        click.echo(f"   Valid: {result['info']['valid_from']} → {result['info']['valid_until']}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--document', '-d', required=True, type=click.Path(exists=True), 
              help='Document to sign')
@click.option('--cert', '-c', required=True, type=click.Path(exists=True), 
              help='Certificate JSON file')
@click.option('--output', '-out', required=True, type=click.Path(), 
              help='Output signature file')
@click.option('--metadata', '-m', type=str, help='Metadata as JSON string')
@click.pass_context
def sign(ctx, document, cert, output, metadata):
    """Signiert ein Dokument
    
    Erstellt eine detached signature (separate Datei).
    Die Signatur enthält SHA256-Hash des Dokuments und Signer-Informationen.
    
    Example:
      vcc-pki sign --document report.pdf \\
                   --cert mycert.json \\
                   --output report.sig.json \\
                   --metadata '{"purpose":"verification"}'
    """
    
    pki = ctx.obj['pki']
    
    try:
        click.echo(f"📝 Signing document: {document}")
        
        # Certificate laden
        with open(cert, 'r', encoding='utf-8') as f:
            cert_data = json.load(f)
        
        certificate = cert_data["certificate"].encode('utf-8')
        private_key = cert_data["private_key"].encode('utf-8')
        
        # Metadata parsen (optional)
        metadata_dict = None
        if metadata:
            try:
                metadata_dict = json.loads(metadata)
            except json.JSONDecodeError:
                click.echo("⚠️  Invalid metadata JSON, ignoring", err=True)
        
        # Signieren
        signature = pki.sign_document(
            document_path=Path(document),
            certificate=certificate,
            private_key=private_key,
            metadata=metadata_dict
        )
        
        # Speichern
        with open(output, 'wb') as f:
            f.write(signature)
        
        # Signature Info
        sig_info = pki.get_signature_info(signature)
        
        click.echo(f"✅ Document signed: {output}")
        click.echo(f"   Algorithm: {sig_info['algorithm']}")
        click.echo(f"   Document Hash: {sig_info['document_hash'][:32]}...")
        click.echo(f"   Signer: {sig_info['signer'].get('CN', 'N/A')}")
        click.echo(f"   Timestamp: {sig_info['timestamp']}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--document', '-d', required=True, type=click.Path(exists=True), 
              help='Document to verify')
@click.option('--signature', '-s', required=True, type=click.Path(exists=True), 
              help='Signature file')
@click.option('--cert', '-c', required=True, type=click.Path(exists=True), 
              help='Certificate JSON file')
@click.option('--no-cert-check', is_flag=True, 
              help='Skip certificate validation (signature only)')
@click.pass_context
def verify(ctx, document, signature, cert, no_cert_check):
    """Verifiziert eine Dokument-Signatur
    
    Prüft:
    - Signatur kryptographisch korrekt
    - Dokument unverändert (Hash-Vergleich)
    - Certificate gültig (optional)
    
    Exit Codes:
      0 = Signature valid
      1 = Signature invalid or error
    
    Example:
      vcc-pki verify --document report.pdf \\
                     --signature report.sig.json \\
                     --cert mycert.json
    """
    
    pki = ctx.obj['pki']
    
    try:
        click.echo(f"🔍 Verifying signature for: {document}")
        
        # Laden
        with open(cert, 'r', encoding='utf-8') as f:
            cert_data = json.load(f)
        certificate = cert_data["certificate"].encode('utf-8')
        
        with open(signature, 'rb') as f:
            sig_bytes = f.read()
        
        # Signature Info anzeigen
        sig_info = pki.get_signature_info(sig_bytes)
        click.echo(f"   Signer: {sig_info['signer'].get('CN', 'N/A')}")
        click.echo(f"   Timestamp: {sig_info['timestamp']}")
        click.echo(f"   Algorithm: {sig_info['algorithm']}")
        
        # Verifizieren
        is_valid = pki.verify_document(
            document_path=Path(document),
            signature=sig_bytes,
            certificate=certificate,
            check_certificate_validity=not no_cert_check
        )
        
        if is_valid:
            click.secho("✅ Signature VALID", fg='green')
            sys.exit(0)
        else:
            click.secho("❌ Signature INVALID", fg='red', err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--cert', '-c', required=True, type=click.Path(exists=True), 
              help='Certificate JSON file')
@click.pass_context
def cert_info(ctx, cert):
    """Zeigt Certificate-Informationen an
    
    Example:
      vcc-pki cert-info --cert mycert.json
    """
    
    pki = ctx.obj['pki']
    
    try:
        # Certificate laden
        with open(cert, 'r', encoding='utf-8') as f:
            cert_data = json.load(f)
        certificate = cert_data["certificate"].encode('utf-8')
        
        # Info holen
        info = pki.get_certificate_info(certificate)
        
        click.echo("\n📜 Certificate Information:")
        click.echo(f"   Serial Number: {info['serial']}")
        click.echo(f"   Subject: {json.dumps(info['subject'], indent=6)}")
        click.echo(f"   Issuer: {json.dumps(info['issuer'], indent=6)}")
        click.echo(f"   Valid From: {info['valid_from']}")
        click.echo(f"   Valid Until: {info['valid_until']}")
        click.echo(f"   Is Revoked: {info['is_revoked']}")
        
        if info.get('extensions'):
            click.echo(f"   Extensions: {json.dumps(info['extensions'], indent=6)}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--serial', '-s', required=True, help='Certificate serial number')
@click.option('--reason', '-r', default='unspecified', 
              help='Revocation reason')
@click.pass_context
def revoke(ctx, serial, reason):
    """Widerruft ein Zertifikat
    
    Reasons: unspecified, keyCompromise, CACompromise, 
             affiliationChanged, superseded, cessationOfOperation,
             certificateHold, removeFromCRL
    
    Example:
      vcc-pki revoke --serial 1234 --reason keyCompromise
    """
    
    pki = ctx.obj['pki']
    
    try:
        click.echo(f"🚫 Revoking certificate: {serial}")
        
        pki.revoke_certificate(serial, reason)
        
        click.echo(f"✅ Certificate {serial} revoked (Reason: {reason})")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.pass_context
def status(ctx):
    """Zeigt PKI Service Status an
    
    Example:
      vcc-pki status
    """
    
    pki = ctx.obj['pki']
    
    try:
        info = pki.get_service_info()
        
        click.echo("\n📊 VCC PKI Service Status:")
        click.echo(f"   Mode: {info['mode'].upper()}")
        click.echo(f"   Version: {info['version']}")
        click.echo(f"   CA Type: {info['ca_type']}")
        click.echo(f"   Signer Type: {info['signer_type']}")
        
        if 'ca_stats' in info:
            stats = info['ca_stats']
            click.echo("\n   CA Statistics:")
            click.echo(f"     CA Name: {stats.get('ca_name', 'N/A')}")
            click.echo(f"     Total Certificates Issued: {stats.get('total_certificates_issued', 0)}")
            click.echo(f"     Total Certificates Revoked: {stats.get('total_certificates_revoked', 0)}")
            click.echo(f"     Active Certificates: {stats.get('active_certificates', 0)}")
        
        click.echo("\n✅ PKI Service operational")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--output', '-out', type=click.Path(), help='Output CRL file (optional)')
@click.pass_context
def get_crl(ctx, output):
    """Holt die aktuelle Certificate Revocation List (CRL)
    
    Example:
      vcc-pki get-crl --output crl.json
      vcc-pki get-crl  # Print to stdout
    """
    
    pki = ctx.obj['pki']
    
    try:
        crl = pki.get_crl()
        
        if output:
            with open(output, 'wb') as f:
                f.write(crl)
            click.echo(f"✅ CRL saved to: {output}")
        else:
            # Print to stdout
            click.echo(crl.decode('utf-8'))
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
