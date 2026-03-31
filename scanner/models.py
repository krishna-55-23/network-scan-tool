from django.db import models
import json


class ScanJob(models.Model):
    """Represents a single scan job."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    target = models.CharField(max_length=255, help_text="IP address or domain")
    port_range = models.CharField(max_length=50, default='1-1024')
    scan_type = models.CharField(max_length=50, default='tcp')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    total_ports_scanned = models.IntegerField(default=0)
    open_ports_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Scan [{self.target}] @ {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    def get_results(self):
        return self.portresult_set.filter(is_open=True).order_by('port')


class PortResult(models.Model):
    """Result for a single port scan."""
    scan = models.ForeignKey(ScanJob, on_delete=models.CASCADE)
    port = models.IntegerField()
    is_open = models.BooleanField(default=False)
    protocol = models.CharField(max_length=10, default='tcp')
    service = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=200, blank=True)
    banner = models.TextField(blank=True)
    response_time_ms = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ['port']
        unique_together = ['scan', 'port', 'protocol']

    def __str__(self):
        return f"Port {self.port}/{self.protocol} - {'OPEN' if self.is_open else 'CLOSED'}"

    def get_service_icon(self):
        icons = {
            'http': '🌐', 'https': '🔒', 'ssh': '🔑', 'ftp': '📁',
            'smtp': '📧', 'dns': '🌍', 'mysql': '🗄️', 'rdp': '🖥️',
            'telnet': '💻', 'smb': '📂', 'unknown': '❓'
        }
        svc = self.service.lower() if self.service else 'unknown'
        for key in icons:
            if key in svc:
                return icons[key]
        return icons['unknown']
