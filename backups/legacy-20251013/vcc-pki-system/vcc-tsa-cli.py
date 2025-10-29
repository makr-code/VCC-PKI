#!/usr/bin/env python3
# VCC PKI System - TSA Management CLI
# Command-line interface for TSA administration and monitoring

import click
import asyncio
import logging
import json
import base64
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

# VCC PKI imports
from app.services.timestamp_authority import VCCTimestampAuthorityFactory, HashAlgorithm
from app.models.tsa_models import TSARequest, TSAToken, TSAPerformanceMetrics
from app.core.database import get_db_session
from production.environment_config import get_environment_manager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@click.group()
@click.option('--environment', '-e', default='development', 
              type=click.Choice(['development', 'testing', 'staging', 'production']),
              help='Environment to operate on')
@click.pass_context
def tsa_cli(ctx, environment):
    """VCC PKI Timestamp Authority Management CLI"""
    ctx.ensure_object(dict)
    ctx.obj['environment'] = environment
    click.echo(f"🕐 VCC TSA CLI - Environment: {environment}")

@tsa_cli.command()
@click.pass_context
async def init(ctx):
    """Initialize TSA service"""
    try:
        environment = ctx.obj['environment']
        click.echo(f"Initializing TSA service for {environment}...")
        
        tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service(environment)
        
        click.echo("✅ TSA service initialized successfully")
        click.echo(f"   TSA Certificate Subject: {tsa_service.tsa_certificate.subject}")
        click.echo(f"   TSA Certificate Expires: {tsa_service.tsa_certificate.not_valid_after}")
        click.echo(f"   Policy OID: {tsa_service.policy_oid}")
        
    except Exception as e:
        click.echo(f"❌ TSA initialization failed: {e}")
        raise click.Abort()

@tsa_cli.command()
@click.option('--data', '-d', required=True, help='Data to timestamp (string or file path)')
@click.option('--service', '-s', help='VCC service name')
@click.option('--algorithm', '-a', default='sha256', 
              type=click.Choice(['sha256', 'sha384', 'sha512']),
              help='Hash algorithm')
@click.option('--output', '-o', help='Output file for timestamp token')
@click.pass_context
async def timestamp(ctx, data, service, algorithm, output):
    """Create timestamp for data"""
    try:
        environment = ctx.obj['environment']
        tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service(environment)
        
        # Determine if data is file or string
        if Path(data).exists():
            with open(data, 'rb') as f:
                data_bytes = f.read()
            click.echo(f"📁 Timestamping file: {data} ({len(data_bytes)} bytes)")
        else:
            data_bytes = data.encode('utf-8')
            click.echo(f"📝 Timestamping string: {data[:50]}...")
        
        # Create timestamp
        hash_algo = HashAlgorithm(algorithm.replace('-', '_'))
        
        response = await tsa_service.process_vcc_timestamp_request(
            data_to_timestamp=data_bytes,
            vcc_service=service or "cli",
            hash_algorithm=hash_algo,
            metadata={"cli_user": "admin", "data_source": "cli"}
        )
        
        if response.status.name.lower() == 'granted':
            click.echo("✅ Timestamp created successfully")
            click.echo(f"   Response ID: {response.response_id}")
            click.echo(f"   Processing time: {response.processing_time_ms:.2f}ms")
            click.echo(f"   Token size: {len(response.time_stamp_token)} bytes")
            
            # Save to file if specified
            if output:
                with open(output, 'wb') as f:
                    f.write(response.time_stamp_token)
                click.echo(f"   Token saved to: {output}")
            else:
                # Display base64 encoded token
                token_b64 = base64.b64encode(response.time_stamp_token).decode()
                click.echo(f"   Token (base64): {token_b64[:100]}...")
        else:
            click.echo(f"❌ Timestamp failed: {response.status.name}")
            if response.failure_info:
                for failure in response.failure_info:
                    click.echo(f"   Failure: {failure.name}")
        
    except Exception as e:
        click.echo(f"❌ Timestamp creation failed: {e}")
        raise click.Abort()

@tsa_cli.command()
@click.option('--token-file', '-t', required=True, help='Timestamp token file')
@click.option('--data-file', '-d', help='Original data file for verification')
@click.pass_context
async def verify(ctx, token_file, data_file):
    """Verify timestamp token"""
    try:
        environment = ctx.obj['environment']
        tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service(environment)
        
        # Read token
        if not Path(token_file).exists():
            click.echo(f"❌ Token file not found: {token_file}")
            raise click.Abort()
        
        with open(token_file, 'rb') as f:
            token_data = f.read()
        
        # Read original data if provided
        original_data = None
        if data_file:
            if not Path(data_file).exists():
                click.echo(f"❌ Data file not found: {data_file}")
                raise click.Abort()
            
            with open(data_file, 'rb') as f:
                original_data = f.read()
        
        # Verify token
        verification_result = await tsa_service.verify_timestamp_token(
            timestamp_token=token_data,
            original_data=original_data
        )
        
        if verification_result["valid"]:
            click.echo("✅ Timestamp token is valid")
            click.echo(f"   Timestamp: {verification_result.get('timestamp')}")
            click.echo(f"   Serial Number: {verification_result.get('serial_number')}")
            click.echo(f"   Policy OID: {verification_result.get('policy_oid')}")
            
            if original_data:
                click.echo("   ✅ Original data hash matches")
        else:
            click.echo("❌ Timestamp token is invalid")
            for error in verification_result.get("errors", []):
                click.echo(f"   Error: {error}")
        
    except Exception as e:
        click.echo(f"❌ Token verification failed: {e}")
        raise click.Abort()

@tsa_cli.command()
@click.pass_context
async def status(ctx):
    """Show TSA service status and metrics"""
    try:
        environment = ctx.obj['environment']
        tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service(environment)
        
        # Get performance metrics
        metrics = tsa_service.get_performance_metrics()
        
        click.echo("📊 TSA Service Status")
        click.echo("=" * 50)
        click.echo(f"Environment: {environment}")
        click.echo(f"Total Requests: {metrics['total_requests']}")
        click.echo(f"Total Errors: {metrics['total_errors']}")
        click.echo(f"Error Rate: {metrics['error_rate_percent']:.2f}%")
        click.echo(f"Average Processing Time: {metrics['average_processing_time_ms']:.2f}ms")
        click.echo(f"Current Serial Number: {metrics['current_serial_number']}")
        
        click.echo("\n🔐 TSA Certificate Information")
        click.echo("=" * 50)
        cert = tsa_service.tsa_certificate
        click.echo(f"Subject: {cert.subject.rfc4514_string()}")
        click.echo(f"Issuer: {cert.issuer.rfc4514_string()}")
        click.echo(f"Serial: {cert.serial_number}")
        click.echo(f"Not Before: {cert.not_valid_before}")
        click.echo(f"Not After: {cert.not_valid_after}")
        
        days_until_expiry = (cert.not_valid_after - datetime.now()).days
        if days_until_expiry < 30:
            click.echo(f"⚠️  Certificate expires in {days_until_expiry} days!")
        else:
            click.echo(f"✅ Certificate expires in {days_until_expiry} days")
        
        click.echo("\n🔧 Supported Hash Algorithms")
        click.echo("=" * 50)
        for algo in metrics['supported_algorithms']:
            click.echo(f"   • {algo}")
        
    except Exception as e:
        click.echo(f"❌ Failed to get TSA status: {e}")
        raise click.Abort()

@tsa_cli.command()
@click.option('--days', '-d', default=7, help='Number of days to analyze')
@click.option('--service', '-s', help='Filter by VCC service')
@click.option('--output', '-o', help='Output file for report')
@click.pass_context
async def report(ctx, days, service, output):
    """Generate TSA usage report"""
    try:
        click.echo(f"📈 Generating TSA report for last {days} days...")
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Query database for TSA requests
        async with get_db_session() as session:
            from sqlalchemy import func, and_
            
            # Base query
            query = session.query(TSARequest).filter(
                TSARequest.created_at >= start_date
            )
            
            # Filter by service if specified
            if service:
                query = query.filter(TSARequest.vcc_service == service)
            
            requests = await query.all()
        
        # Generate statistics
        total_requests = len(requests)
        successful_requests = len([r for r in requests if r.status == 'granted'])
        failed_requests = total_requests - successful_requests
        
        # Service breakdown
        service_stats = {}
        for request in requests:
            service_name = request.vcc_service or 'external'
            service_stats[service_name] = service_stats.get(service_name, 0) + 1
        
        # Performance stats
        processing_times = [r.processing_time_ms for r in requests if r.processing_time_ms]
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        
        # Generate report
        report_data = {
            "report_period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "summary": {
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate_percent": (successful_requests / total_requests * 100) if total_requests > 0 else 0,
                "average_processing_time_ms": avg_processing_time
            },
            "service_breakdown": service_stats,
            "daily_stats": {}  # Could add daily breakdown here
        }
        
        # Display report
        click.echo("\n📊 TSA Usage Report")
        click.echo("=" * 60)
        click.echo(f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        click.echo(f"Total Requests: {total_requests}")
        click.echo(f"Successful: {successful_requests}")
        click.echo(f"Failed: {failed_requests}")
        click.echo(f"Success Rate: {report_data['summary']['success_rate_percent']:.1f}%")
        click.echo(f"Average Processing Time: {avg_processing_time:.2f}ms")
        
        if service_stats:
            click.echo("\n🏢 Service Breakdown:")
            for service_name, count in sorted(service_stats.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_requests * 100) if total_requests > 0 else 0
                click.echo(f"   {service_name}: {count} requests ({percentage:.1f}%)")
        
        # Save to file if specified
        if output:
            with open(output, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            click.echo(f"\n💾 Report saved to: {output}")
        
    except Exception as e:
        click.echo(f"❌ Report generation failed: {e}")
        raise click.Abort()

@tsa_cli.command()
@click.option('--model-file', '-m', required=True, help='Clara model file to timestamp')
@click.option('--model-id', required=True, help='Model identifier')
@click.option('--version', '-v', default='1.0.0', help='Model version')
@click.option('--output', '-o', help='Output file for timestamp')
@click.pass_context
async def clara_model(ctx, model_file, model_id, version, output):
    """Timestamp Clara KI model"""
    try:
        environment = ctx.obj['environment']
        tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service(environment)
        
        if not Path(model_file).exists():
            click.echo(f"❌ Model file not found: {model_file}")
            raise click.Abort()
        
        # Read model data
        with open(model_file, 'rb') as f:
            model_data = f.read()
        
        click.echo(f"🤖 Timestamping Clara model: {model_id}")
        click.echo(f"   File: {model_file} ({len(model_data)} bytes)")
        click.echo(f"   Version: {version}")
        
        # Create timestamp
        response = await tsa_service.timestamp_clara_model(
            model_data=model_data,
            model_id=model_id,
            version=version
        )
        
        if response.status.name.lower() == 'granted':
            click.echo("✅ Clara model timestamped successfully")
            click.echo(f"   Response ID: {response.response_id}")
            click.echo(f"   Processing time: {response.processing_time_ms:.2f}ms")
            
            # Save timestamp
            if output:
                with open(output, 'wb') as f:
                    f.write(response.time_stamp_token)
                click.echo(f"   Timestamp saved to: {output}")
        else:
            click.echo(f"❌ Clara model timestamp failed: {response.status.name}")
        
    except Exception as e:
        click.echo(f"❌ Clara model timestamp failed: {e}")
        raise click.Abort()

@tsa_cli.command()
@click.option('--count', '-c', default=100, help='Number of test requests')
@click.option('--concurrent', default=10, help='Concurrent requests')
@click.pass_context
async def benchmark(ctx, count, concurrent):
    """Run TSA performance benchmark"""
    try:
        environment = ctx.obj['environment']
        tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service(environment)
        
        click.echo(f"🏃 Running TSA benchmark...")
        click.echo(f"   Total requests: {count}")
        click.echo(f"   Concurrent: {concurrent}")
        
        # Prepare test data
        test_data = b"Benchmark test data for VCC TSA performance testing"
        
        # Performance tracking
        start_time = datetime.now()
        successful_requests = 0
        failed_requests = 0
        processing_times = []
        
        # Run benchmark
        semaphore = asyncio.Semaphore(concurrent)
        
        async def benchmark_request():
            nonlocal successful_requests, failed_requests, processing_times
            
            async with semaphore:
                try:
                    request_start = datetime.now()
                    
                    response = await tsa_service.process_vcc_timestamp_request(
                        data_to_timestamp=test_data,
                        vcc_service="benchmark",
                        hash_algorithm=HashAlgorithm.SHA256
                    )
                    
                    request_end = datetime.now()
                    processing_time = (request_end - request_start).total_seconds() * 1000
                    processing_times.append(processing_time)
                    
                    if response.status.name.lower() == 'granted':
                        successful_requests += 1
                    else:
                        failed_requests += 1
                        
                except Exception as e:
                    failed_requests += 1
                    logger.error(f"Benchmark request failed: {e}")
        
        # Execute benchmark
        tasks = [benchmark_request() for _ in range(count)]
        await asyncio.gather(*tasks)
        
        # Calculate results
        end_time = datetime.now()
        total_time = (end_time - start_time).total_seconds()
        requests_per_second = count / total_time if total_time > 0 else 0
        
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        min_processing_time = min(processing_times) if processing_times else 0
        max_processing_time = max(processing_times) if processing_times else 0
        
        # Display results
        click.echo("\n📊 Benchmark Results")
        click.echo("=" * 40)
        click.echo(f"Total requests: {count}")
        click.echo(f"Successful: {successful_requests}")
        click.echo(f"Failed: {failed_requests}")
        click.echo(f"Success rate: {(successful_requests/count*100):.1f}%")
        click.echo(f"Total time: {total_time:.2f}s")
        click.echo(f"Requests/second: {requests_per_second:.1f}")
        click.echo(f"Avg processing time: {avg_processing_time:.2f}ms")
        click.echo(f"Min processing time: {min_processing_time:.2f}ms")
        click.echo(f"Max processing time: {max_processing_time:.2f}ms")
        
        # Performance assessment
        if requests_per_second > 50:
            click.echo("✅ Performance: Excellent")
        elif requests_per_second > 20:
            click.echo("⚠️  Performance: Good")
        else:
            click.echo("❌ Performance: Needs improvement")
        
    except Exception as e:
        click.echo(f"❌ Benchmark failed: {e}")
        raise click.Abort()

def run_async_command(func):
    """Decorator to run async click commands"""
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

# Apply async decorator to all async commands
for name, command in tsa_cli.commands.items():
    if asyncio.iscoroutinefunction(command.callback):
        command.callback = run_async_command(command.callback)

if __name__ == '__main__':
    tsa_cli()