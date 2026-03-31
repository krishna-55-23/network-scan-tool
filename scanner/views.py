"""
Scanner Views - handles all web requests for the network scanner.
"""

import json
import time
import threading
from datetime import datetime

from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.conf import settings

from .models import ScanJob, PortResult
from .engine import run_scan, resolve_target, parse_port_range, nmap_available


# ─── Dashboard ───────────────────────────────────────────────────────────────

def index(request):
    """Main dashboard / scan launcher."""
    recent_scans = ScanJob.objects.all()[:10]
    stats = {
        'total_scans': ScanJob.objects.count(),
        'completed': ScanJob.objects.filter(status='completed').count(),
        'total_open_ports': sum(
            s.open_ports_count for s in ScanJob.objects.filter(status='completed')
        ),
    }
    return render(request, 'scanner/index.html', {
        'recent_scans': recent_scans,
        'stats': stats,
        'nmap_available': nmap_available(),
    })


# ─── Start Scan (API) ─────────────────────────────────────────────────────────

@csrf_exempt
def start_scan(request):
    """POST: start a new scan job. Returns job id for polling."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    target = data.get('target', '').strip()
    port_range = data.get('port_range', '1-1024').strip() or '1-1024'
    scan_type = data.get('scan_type', 'tcp')

    if not target:
        return JsonResponse({'error': 'Target is required'}, status=400)

    # Validate port range
    ports = parse_port_range(port_range)
    if not ports:
        return JsonResponse({'error': 'Invalid port range'}, status=400)
    if len(ports) > 10000:
        return JsonResponse({'error': 'Port range too large (max 10000 ports)'}, status=400)

    # Try to resolve early
    try:
        resolve_target(target)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    # Create DB record
    job = ScanJob.objects.create(
        target=target,
        port_range=port_range,
        scan_type=scan_type,
        status='running',
        total_ports_scanned=len(ports),
    )

    # Run scan in background thread
    def do_scan():
        try:
            scan_data = run_scan(
                target=target,
                port_range=port_range,
                max_threads=getattr(settings, 'MAX_THREADS', 100),
                timeout=getattr(settings, 'SCAN_TIMEOUT', 2),
            )
            # Save results
            for r in scan_data['results']:
                if r['is_open']:
                    PortResult.objects.create(
                        scan=job,
                        port=r['port'],
                        is_open=True,
                        protocol=r['protocol'],
                        service=r['service'],
                        service_version=r['service_version'],
                        banner=r['banner'],
                        response_time_ms=r['response_time_ms'],
                    )
            job.status = 'completed'
            job.completed_at = timezone.now()
            job.duration_seconds = scan_data['duration']
            job.open_ports_count = scan_data['open_count']
            job.save()
        except Exception as e:
            job.status = 'failed'
            job.error_message = str(e)
            job.save()

    thread = threading.Thread(target=do_scan, daemon=True)
    thread.start()

    return JsonResponse({'job_id': job.id, 'status': 'running'})


# ─── Poll Scan Status (API) ───────────────────────────────────────────────────

def scan_status(request, job_id):
    """GET: poll scan status and results."""
    job = get_object_or_404(ScanJob, id=job_id)
    open_ports = []
    if job.status == 'completed':
        for p in job.get_results():
            open_ports.append({
                'port': p.port,
                'protocol': p.protocol,
                'service': p.service,
                'service_version': p.service_version,
                'banner': p.banner,
                'response_time_ms': p.response_time_ms,
                'icon': p.get_service_icon(),
            })

    return JsonResponse({
        'job_id': job.id,
        'status': job.status,
        'target': job.target,
        'port_range': job.port_range,
        'total_ports': job.total_ports_scanned,
        'open_count': job.open_ports_count,
        'duration': job.duration_seconds,
        'error': job.error_message,
        'open_ports': open_ports,
        'created_at': job.created_at.isoformat(),
    })


# ─── Scan Result Page ─────────────────────────────────────────────────────────

def scan_result(request, job_id):
    """Full result page for a completed scan."""
    job = get_object_or_404(ScanJob, id=job_id)
    open_ports = job.get_results() if job.status == 'completed' else []
    return render(request, 'scanner/result.html', {
        'job': job,
        'open_ports': open_ports,
    })


# ─── Scan History ─────────────────────────────────────────────────────────────

def scan_history(request):
    """List all past scans."""
    scans = ScanJob.objects.all()
    return render(request, 'scanner/history.html', {'scans': scans})


# ─── Delete Scan ─────────────────────────────────────────────────────────────

@csrf_exempt
def delete_scan(request, job_id):
    """Delete a scan job."""
    if request.method == 'POST':
        job = get_object_or_404(ScanJob, id=job_id)
        job.delete()
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'POST required'}, status=405)
