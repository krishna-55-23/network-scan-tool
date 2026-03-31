"""
Network Scanner Engine
Core scanning module combining socket-based scanning with optional nmap integration.
Handles: Port scanning, Service detection, Banner grabbing
"""

import socket
import threading
import time
import re
import subprocess
import concurrent.futures
from typing import Dict, List, Optional, Tuple


# ─── Service Fingerprints ────────────────────────────────────────────────────

SERVICE_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    1433: 'MSSQL', 1521: 'Oracle', 5000: 'UPnP', 8888: 'HTTP-Alt',
    9200: 'Elasticsearch', 11211: 'Memcached', 2375: 'Docker',
}

BANNER_PROBES = {
    21:  b'',
    22:  b'',
    23:  b'',
    25:  b'EHLO scanner\r\n',
    80:  b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    8080: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    110: b'',
    143: b'',
    443: None,  # Skip raw banner for SSL
    8443: None,
}


# ─── Resolver ────────────────────────────────────────────────────────────────

def resolve_target(target: str) -> Tuple[str, str]:
    """Resolve domain to IP. Returns (ip, hostname)."""
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target if target != ip else ''
        return ip, hostname
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve target '{target}': {e}")


# ─── Port Scanner ────────────────────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 2.0) -> Dict:
    """Scan a single TCP port. Returns result dict."""
    result = {
        'port': port,
        'is_open': False,
        'protocol': 'tcp',
        'service': SERVICE_PORTS.get(port, 'Unknown'),
        'service_version': '',
        'banner': '',
        'response_time_ms': None,
    }

    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = sock.connect_ex((ip, port))
        elapsed = (time.time() - start) * 1000

        if conn == 0:
            result['is_open'] = True
            result['response_time_ms'] = round(elapsed, 2)
            # Attempt banner grab
            banner = grab_banner(sock, ip, port, timeout)
            if banner:
                result['banner'] = banner
                result['service_version'] = parse_service_version(banner, port)
        sock.close()
    except Exception:
        pass

    return result


def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Grab service banner from open socket."""
    try:
        probe = BANNER_PROBES.get(port, b'')
        if probe is None:
            return ''
        if probe:
            formatted = probe.replace(b'{host}', host.encode())
            sock.send(formatted)
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        return banner[:500]  # Limit banner length
    except Exception:
        return ''


def parse_service_version(banner: str, port: int) -> str:
    """Extract service version from banner string."""
    patterns = [
        r'SSH-[\d.]+-([^\r\n]+)',           # SSH
        r'Server: ([^\r\n]+)',               # HTTP Server header
        r'220[- ]([^\r\n]+)',                # FTP/SMTP banner
        r'\+OK ([^\r\n]+)',                  # POP3
        r'\* OK ([^\r\n]+)',                 # IMAP
        r'([A-Za-z]+[\d./][\w./\-]+)',       # Generic version string
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            version = match.group(1).strip()
            if len(version) > 3:
                return version[:100]
    return ''


# ─── Port Range Parser ───────────────────────────────────────────────────────

def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string like '1-1024,8080,8443' into list of ports."""
    ports = set()
    for part in port_range.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            try:
                s, e = int(start.strip()), int(end.strip())
                ports.update(range(max(1, s), min(65535, e) + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


# ─── Main Scanner ────────────────────────────────────────────────────────────

def run_scan(
    target: str,
    port_range: str = '1-1024',
    max_threads: int = 100,
    timeout: float = 2.0,
    progress_callback=None
) -> Dict:
    """
    Full scan pipeline.
    Returns dict with: ip, hostname, ports (list of result dicts), duration
    """
    start_time = time.time()

    # Resolve target
    ip, hostname = resolve_target(target)

    ports = parse_port_range(port_range)
    total = len(ports)
    results = []
    scanned = [0]
    lock = threading.Lock()

    def scan_with_progress(port):
        result = scan_port(ip, port, timeout)
        with lock:
            scanned[0] += 1
            if progress_callback:
                pct = int((scanned[0] / total) * 100)
                progress_callback(pct, scanned[0], total)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_with_progress, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    duration = time.time() - start_time
    open_ports = [r for r in results if r['is_open']]
    results.sort(key=lambda x: x['port'])

    return {
        'target': target,
        'ip': ip,
        'hostname': hostname,
        'port_range': port_range,
        'total_ports': total,
        'open_count': len(open_ports),
        'results': results,
        'open_ports': open_ports,
        'duration': round(duration, 2),
    }


# ─── nmap Integration (optional) ─────────────────────────────────────────────

def nmap_available() -> bool:
    """Check if nmap is installed."""
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def run_nmap_scan(target: str, port_range: str = '1-1024') -> Optional[str]:
    """Run nmap and return raw output."""
    if not nmap_available():
        return None
    try:
        ports = port_range.replace(' ', '')
        result = subprocess.run(
            ['nmap', '-sV', '-p', ports, '--open', target],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout
    except Exception as e:
        return f"nmap error: {e}"
