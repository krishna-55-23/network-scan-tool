"""
Reports module - Export scan results as PDF or CSV
"""

import csv
import io
from datetime import datetime

from django.shortcuts import get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.conf import settings

from scanner.models import ScanJob


def export_csv(request, job_id):
    """Export scan results as CSV."""
    job = get_object_or_404(ScanJob, id=job_id)
    open_ports = job.get_results()

    response = HttpResponse(content_type='text/csv')
    filename = f"scan_{job.target}_{job.created_at.strftime('%Y%m%d_%H%M%S')}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    # Header rows
    writer.writerow(['Network Scanner Tool - Scan Report'])
    writer.writerow(['Target', job.target])
    writer.writerow(['Port Range', job.port_range])
    writer.writerow(['Status', job.status])
    writer.writerow(['Scan Date', job.created_at.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow(['Duration (s)', job.duration_seconds or 'N/A'])
    writer.writerow(['Total Ports Scanned', job.total_ports_scanned])
    writer.writerow(['Open Ports Found', job.open_ports_count])
    writer.writerow([])  # blank row
    writer.writerow(['Port', 'Protocol', 'Service', 'Version', 'Banner', 'Response Time (ms)'])

    for port in open_ports:
        writer.writerow([
            port.port,
            port.protocol.upper(),
            port.service,
            port.service_version,
            port.banner[:200] if port.banner else '',
            port.response_time_ms or '',
        ])

    return response


def export_pdf(request, job_id):
    """Export scan results as PDF using reportlab."""
    job = get_object_or_404(ScanJob, id=job_id)
    open_ports = list(job.get_results())

    try:
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm, inch
        from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                         Paragraph, Spacer, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return HttpResponse(
            "reportlab not installed. Run: pip install reportlab",
            content_type='text/plain',
            status=500
        )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    # Colors
    DARK = colors.HexColor('#0a0e1a')
    GREEN = colors.HexColor('#00ff88')
    BLUE = colors.HexColor('#00d4ff')
    GRAY = colors.HexColor('#8892a4')
    LIGHT = colors.HexColor('#f0f4f8')
    WHITE = colors.white

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title', parent=styles['Title'],
        fontSize=24, textColor=DARK, spaceAfter=6,
        fontName='Helvetica-Bold', alignment=TA_CENTER
    )
    sub_style = ParagraphStyle(
        'Sub', parent=styles['Normal'],
        fontSize=11, textColor=GRAY, alignment=TA_CENTER, spaceAfter=20
    )
    label_style = ParagraphStyle(
        'Label', parent=styles['Normal'],
        fontSize=10, textColor=GRAY, fontName='Helvetica-Bold'
    )
    value_style = ParagraphStyle(
        'Value', parent=styles['Normal'],
        fontSize=10, textColor=DARK
    )
    section_style = ParagraphStyle(
        'Section', parent=styles['Heading2'],
        fontSize=14, textColor=DARK, fontName='Helvetica-Bold',
        spaceBefore=16, spaceAfter=8
    )

    story = []

    # Title
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("🔍 Network Scanner Tool", title_style))
    story.append(Paragraph("Security Scan Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=2, color=GREEN, spaceAfter=20))

    # Summary Table
    summary_data = [
        ['Target', job.target, 'Scan Date', job.created_at.strftime('%Y-%m-%d %H:%M')],
        ['Port Range', job.port_range, 'Duration', f"{job.duration_seconds or 'N/A'}s"],
        ['Status', job.status.upper(), 'Total Scanned', str(job.total_ports_scanned)],
        ['Open Ports', str(job.open_ports_count), 'Scan Type', job.scan_type.upper()],
    ]
    summary_table = Table(summary_data, colWidths=[3.5*cm, 6*cm, 3.5*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#eef2f7')),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#eef2f7')),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (1,0), (1,-1), [WHITE]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dde3ec')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))

    # Open Ports Table
    story.append(Paragraph(f"Open Ports ({len(open_ports)} found)", section_style))

    if open_ports:
        headers = ['Port', 'Protocol', 'Service', 'Version', 'Response (ms)']
        table_data = [headers]
        for p in open_ports:
            table_data.append([
                str(p.port),
                p.protocol.upper(),
                p.service or 'Unknown',
                (p.service_version or '')[:40],
                str(round(p.response_time_ms, 1)) if p.response_time_ms else 'N/A',
            ])

        port_table = Table(table_data, colWidths=[2*cm, 2.5*cm, 3.5*cm, 7*cm, 2.5*cm])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, colors.HexColor('#f7f9fc')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dde3ec')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,0), (1,-1), 'CENTER'),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("No open ports found.", value_style))

    # Banners section
    ports_with_banners = [p for p in open_ports if p.banner]
    if ports_with_banners:
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("Banner Grabs", section_style))
        banner_data = [['Port', 'Service', 'Banner']]
        for p in ports_with_banners:
            banner_text = p.banner[:150].replace('\n', ' ').replace('\r', '')
            banner_data.append([str(p.port), p.service, banner_text])

        banner_table = Table(banner_data, colWidths=[2*cm, 3*cm, 12.5*cm])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, colors.HexColor('#f7f9fc')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dde3ec')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(banner_table)

    # Footer
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dde3ec')))
    story.append(Spacer(1, 0.3*cm))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
                                   fontSize=8, textColor=GRAY, alignment=TA_CENTER)
    story.append(Paragraph(
        f"Generated by Network Scanner Tool | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | For authorized use only",
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)

    filename = f"scan_{job.target}_{job.created_at.strftime('%Y%m%d_%H%M%S')}.pdf"
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
