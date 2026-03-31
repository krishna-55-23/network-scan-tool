from django.contrib import admin
from .models import ScanJob, PortResult


class PortResultInline(admin.TabularInline):
    model = PortResult
    extra = 0
    fields = ['port', 'protocol', 'service', 'service_version', 'banner', 'response_time_ms']
    readonly_fields = fields


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ['target', 'port_range', 'status', 'open_ports_count',
                    'duration_seconds', 'created_at']
    list_filter = ['status', 'scan_type']
    search_fields = ['target']
    readonly_fields = ['created_at', 'completed_at']
    inlines = [PortResultInline]


@admin.register(PortResult)
class PortResultAdmin(admin.ModelAdmin):
    list_display = ['scan', 'port', 'protocol', 'service', 'is_open']
    list_filter = ['is_open', 'protocol']
    search_fields = ['service', 'banner']
