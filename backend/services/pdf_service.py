"""
pdf_service.py
Enterprise-grade PDF report generation for security scans.
Professional executive security report suitable for enterprise presentation.
"""

import os
from datetime import datetime
from typing import Dict, Any, List

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, 
    KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib import colors
from reportlab.lib.units import inch, mm
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "backend", "data", "exports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def safe_table_data(data, min_cols=1):
    """
    Normalize table data to ensure all rows have the same number of columns.
    Prevents ReportLab IndexError when table styles reference invalid column indices.
    """
    if not data:
        return [["No Data Available"]]

    # Filter out non-list rows and convert to lists
    clean_rows = []
    for row in data:
        if not isinstance(row, (list, tuple)):
            row = [str(row)]
        else:
            row = list(row)
        clean_rows.append(row)

    if not clean_rows:
        return [["No Data Available"]]

    # Find max column count
    max_cols = max(len(row) for row in clean_rows)
    max_cols = max(max_cols, min_cols)

    # Normalize all rows to have the same number of columns
    normalized = []
    for row in clean_rows:
        # Extend short rows with empty strings
        while len(row) < max_cols:
            row.append("")
        # Truncate long rows
        if len(row) > max_cols:
            row = row[:max_cols]
        normalized.append(row)

    return normalized


class EnterpriseTheme:
    """Professional color palette for enterprise security reports."""
    # Primary palette - deep professional blues
    PRIMARY = colors.HexColor("#1e3a5f")      # Deep navy
    PRIMARY_DARK = colors.HexColor("#0f1f33") # Darker navy
    SECONDARY = colors.HexColor("#2d4a6f")    # Medium navy
    ACCENT = colors.HexColor("#3b82f6")       # Corporate blue
    ACCENT_LIGHT = colors.HexColor("#60a5fa") # Light blue
    
    # Background colors
    BACKGROUND = colors.HexColor("#ffffff")   # White background
    PANEL_BG = colors.HexColor("#f8fafc")     # Light gray panels
    HEADER_BG = colors.HexColor("#f1f5f9")    # Header background
    
    # Severity colors - professional risk palette
    CRITICAL = colors.HexColor("#dc2626")     # Red
    CRITICAL_BG = colors.HexColor("#fef2f2")    # Light red bg
    HIGH = colors.HexColor("#ea580c")         # Orange
    HIGH_BG = colors.HexColor("#fff7ed")      # Light orange bg
    MEDIUM = colors.HexColor("#ca8a04")       # Yellow/Amber
    MEDIUM_BG = colors.HexColor("#fefce8")    # Light yellow bg
    LOW = colors.HexColor("#16a34a")          # Green
    LOW_BG = colors.HexColor("#f0fdf4")       # Light green bg
    
    # Text colors
    TEXT = colors.HexColor("#1e293b")         # Dark slate
    TEXT_LIGHT = colors.HexColor("#475569")     # Medium slate
    TEXT_MUTED = colors.HexColor("#64748b")     # Light slate
    WHITE = colors.white
    
    # Border colors
    BORDER = colors.HexColor("#e2e8f0")
    BORDER_DARK = colors.HexColor("#cbd5e1")

def _normalize_scan_data(scan_data: Dict) -> Dict:
    """
    Normalize scan data from various sources to a unified format.
    Supports:
    1. phase3 scan_report.json (OS Inspection) - list format with 'results' key
    2. vuln_engine report.json (Port Scan) - dict format with 'data' key
    3. Database/API format - dict with 'result' key containing 'data'
    """
    if not scan_data:
        return {
            "scan_type": "unknown",
            "target": "unknown",
            "summary": {},
            "findings": [],
            "scan_info": {}
        }

    # OS Inspection JSON - list format from phase3/output/scan_report.json
    if isinstance(scan_data, list) and len(scan_data) > 0:
        latest = scan_data[-1]
        return {
            "scan_type": "os_inspection",
            "target": "localhost",
            "summary": latest.get("summary", {}),
            "findings": latest.get("results", []),
            "scan_info": latest.get("scan_info", {})
        }

    # Port Analysis JSON from vuln_engine/report.json
    if isinstance(scan_data, dict):
        # Direct port scan format
        if "data" in scan_data and "scan_info" in scan_data:
            return {
                "scan_type": "port_scan",
                "target": scan_data.get("scan_info", {}).get("target", "unknown"),
                "summary": scan_data.get("summary", {}),
                "findings": scan_data.get("data", []),
                "scan_info": scan_data.get("scan_info", {})
            }

        # Database/API format with nested result
        result = scan_data.get("result", {})
        if result:
            # Check if result has findings in 'data' (port_scan) or 'results' (os_inspection)
            findings = result.get("data", []) or result.get("results", [])
            return {
                "scan_type": scan_data.get("scan_type", "unknown"),
                "target": scan_data.get("target", "unknown"),
                "summary": result.get("summary", {}),
                "findings": findings,
                "scan_info": scan_data.get("scan_info", {}),
                "scan_id": scan_data.get("scan_id", "unknown"),
                "timestamp": scan_data.get("timestamp", "unknown")
            }

    # Existing DB/API format fallback
    return {
        "scan_type": scan_data.get("scan_type", "unknown"),
        "target": scan_data.get("target", "unknown"),
        "summary": scan_data.get("summary", {}),
        "findings": scan_data.get("findings", []),
        "scan_info": scan_data.get("scan_info", {})
    }


def _get_risk_level(score: float) -> str:
    if score >= 7.5: return "CRITICAL"
    elif score >= 4.0: return "HIGH"
    elif score >= 2.0: return "MEDIUM"
    return "LOW"

def _get_risk_color(level: str) -> colors.Color:
    """Get risk color for severity level."""
    return getattr(EnterpriseTheme, level.upper(), EnterpriseTheme.LOW)

def _get_risk_bg_color(level: str) -> colors.Color:
    """Get light background color for severity level."""
    bg_map = {
        "CRITICAL": EnterpriseTheme.CRITICAL_BG,
        "HIGH": EnterpriseTheme.HIGH_BG,
        "MEDIUM": EnterpriseTheme.MEDIUM_BG,
        "LOW": EnterpriseTheme.LOW_BG,
    }
    return bg_map.get(level.upper(), EnterpriseTheme.LOW_BG)

def _format_timestamp(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y at %I:%M %p UTC")
    except:
        return ts

def _create_cover_page(elements, styles, scan_data: Dict):
    """Create professional executive cover page with modern design."""
    scan_type = scan_data.get("scan_type", "Unknown")
    target = scan_data.get("target", "Unknown")
    timestamp = _format_timestamp(scan_data.get("timestamp", "Unknown"))
    scan_id = str(scan_data.get("scan_id", 'Unknown'))[:8].upper()
    
    # Top accent bar
    elements.append(HRFlowable(
        width="100%", thickness=8, 
        color=EnterpriseTheme.PRIMARY, 
        spaceBefore=0, spaceAfter=40
    ))
    
    # Main spacing
    elements.append(Spacer(1, 1.2*inch))
    
    # Title styling - modern, bold, professional
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=EnterpriseTheme.PRIMARY,
        spaceAfter=8,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        leading=34
    )
    
    elements.append(Paragraph("SECURITY ASSESSMENT REPORT", title_style))
    
    # Document type badge
    scan_label = "Network Exposure Analysis" if scan_type == "port_scan" else "System Configuration Audit"
    badge_style = ParagraphStyle(
        'CoverBadge',
        parent=styles['Normal'],
        fontSize=12,
        textColor=EnterpriseTheme.ACCENT,
        alignment=TA_CENTER,
        spaceAfter=60,
        fontName="Helvetica-Bold"
    )
    elements.append(Paragraph(f"&#9679; {scan_label.upper()} &#9679;", badge_style))
    
    # Horizontal line separator
    elements.append(HRFlowable(
        width="60%", thickness=1, 
        color=EnterpriseTheme.BORDER_DARK, 
        spaceBefore=0, spaceAfter=40
    ))
    
    # Metadata grid - professional two-column layout
    meta_data = [
        ["TARGET", target],
        ["GENERATED", timestamp],
        ["REPORT ID", f"SEC-{scan_id}"],
        ["CLASSIFICATION", "CONFIDENTIAL"]
    ]
    
    meta_table = []
    for label, value in meta_data:
        meta_table.append([
            Paragraph(f"<b>{label}</b>", ParagraphStyle(
                'MetaLabel', fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED,
                fontName="Helvetica-Bold", alignment=TA_LEFT
            )),
            Paragraph(str(value), ParagraphStyle(
                'MetaValue', fontSize=11, textColor=EnterpriseTheme.TEXT,
                fontName="Helvetica", alignment=TA_LEFT
            ))
        ])
    
    # Normalize table data to ensure consistent dimensions
    meta_table = safe_table_data(meta_table)
    t = Table(meta_table, colWidths=[1.5*inch, 4*inch])
    t.setStyle(TableStyle([
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, EnterpriseTheme.BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(t)
    
    # Footer section
    elements.append(Spacer(1, 2*inch))
    
    footer_style = ParagraphStyle(
        'CoverFooter',
        fontSize=9,
        textColor=EnterpriseTheme.TEXT_MUTED,
        alignment=TA_CENTER,
        leading=14
    )
    elements.append(Paragraph(
        "This report contains confidential security information.<br/>"
        "Distribution is restricted to authorized personnel only.",
        footer_style
    ))
    
    # Bottom accent
    elements.append(Spacer(1, 0.5*inch))
    elements.append(HRFlowable(
        width="100%", thickness=4, 
        color=EnterpriseTheme.ACCENT, 
        spaceBefore=0, spaceAfter=0
    ))
    
    elements.append(PageBreak())

def _create_executive_summary(elements, styles, summary: Dict, scan_type: str):
    """Create professional executive summary with score cards and metrics."""
    elements.append(Paragraph("1. Executive Summary", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    # Professional narrative paragraph
    narrative_style = ParagraphStyle(
        'Narrative', 
        parent=styles['Normal'], 
        fontSize=10.5, 
        leading=16, 
        spaceAfter=20,
        alignment=TA_JUSTIFY
    )
    
    if scan_type == "port_scan":
        score = summary.get('risk_score', 0)
        level = _get_risk_level(score)
        color = _get_risk_color(level)
        bg_color = _get_risk_bg_color(level)
        
        narrative = (
            f"This network exposure assessment evaluated the target infrastructure and identified "
            f"<b>{summary.get('total_findings', 0)} security findings</b> across "
            f"<b>{summary.get('open_ports', 0)} open ports</b>. The calculated risk score of "
            f"<b>{score}/10</b> indicates a <font color='{color.hexval()}'><b>{level}</b></font> "
            f"risk posture. Immediate remediation should be prioritized for all critical and high-severity findings "
            f"to reduce the attack surface and align with security best practices."
        )
    else:
        crit = summary.get('critical', 0)
        high = summary.get('high', 0)
        level = "CRITICAL" if crit > 0 else "HIGH" if high > 0 else "MEDIUM"
        color = _get_risk_color(level)
        bg_color = _get_risk_bg_color(level)
        
        narrative = (
            f"The operating system security audit completed <b>{summary.get('total_checks', 0)} configuration checks</b> "
            f"across 13 security categories. The assessment identified "
            f"<b>{crit} critical</b> and <b>{high} high-severity</b> issues requiring immediate attention. "
            f"The overall risk posture is <font color='{color.hexval()}'><b>{level}</b></font>. "
            f"Remediation efforts should focus on patch management, access controls, and security configuration hardening."
        )
    
    elements.append(Paragraph(narrative, narrative_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Risk Assessment Summary Card
    risk_header = Paragraph(
        f"<font color='white' size=11><b>RISK ASSESSMENT: {level}</b></font>",
        ParagraphStyle('RiskHeader', alignment=TA_CENTER, fontName="Helvetica-Bold")
    )
    
    risk_data = [[risk_header]]
    risk_table = Table(risk_data, colWidths=[6*inch], rowHeights=[0.5*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('BOX', (0,0), (-1,-1), 1, color),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), 4),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Metrics Summary Grid
    if scan_type == "port_scan":
        dist = summary.get("risk_distribution", {})
        metrics = [
            ("Total Findings", str(summary.get('total_findings', 0)), EnterpriseTheme.TEXT),
            ("Open Ports", str(summary.get('open_ports', 0)), EnterpriseTheme.ACCENT),
            ("Risk Score", f"{summary.get('risk_score', 0)}/10", color),
            ("Critical", str(dist.get('Critical', 0)), EnterpriseTheme.CRITICAL),
            ("High", str(dist.get('High', 0)), EnterpriseTheme.HIGH),
            ("Medium", str(dist.get('Medium', 0)), EnterpriseTheme.MEDIUM),
        ]
    else:
        metrics = [
            ("Checks Performed", str(summary.get('total_checks', 0)), EnterpriseTheme.TEXT),
            ("Critical Issues", str(summary.get('critical', 0)), EnterpriseTheme.CRITICAL),
            ("High Issues", str(summary.get('high', 0)), EnterpriseTheme.HIGH),
            ("Medium Issues", str(summary.get('medium', 0)), EnterpriseTheme.MEDIUM),
            ("Low Issues", str(summary.get('low', 0)), EnterpriseTheme.LOW),
            ("Failed Checks", str(summary.get('failed', 0)), EnterpriseTheme.TEXT_MUTED),
        ]
    
    # Create metrics grid (3 columns x 2 rows)
    metric_table_data = []
    for i in range(0, len(metrics), 3):
        row = []
        for j in range(3):
            if i + j < len(metrics):
                label, value, val_color = metrics[i + j]
                cell_content = [
                    Paragraph(value, ParagraphStyle(
                        'MetricValue', fontSize=20, textColor=val_color,
                        fontName="Helvetica-Bold", alignment=TA_CENTER
                    )),
                    Paragraph(label, ParagraphStyle(
                        'MetricLabel', fontSize=9, textColor=EnterpriseTheme.TEXT_MUTED,
                        fontName="Helvetica", alignment=TA_CENTER, spaceBefore=4
                    ))
                ]
                row.append(cell_content)
            else:
                # Empty cell placeholder - must be consistent
                row.append('')
        # Ensure row has exactly 3 columns
        while len(row) < 3:
            row.append('')
        metric_table_data.append(row[:3])

    # Normalize table data to ensure consistent dimensions
    metric_table_data = safe_table_data(metric_table_data)
    metrics_table = Table(metric_table_data, colWidths=[2*inch, 2*inch, 2*inch])
    metrics_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('BOX', (0,0), (-1,-1), 0.5, EnterpriseTheme.BORDER),
        ('GRID', (0,0), (-1,-1), 0.5, EnterpriseTheme.BORDER),
        ('BACKGROUND', (0,0), (-1,-1), EnterpriseTheme.PANEL_BG),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 0.3*inch))

def _create_heatmap(elements, styles, summary: Dict, scan_type: str):
    """Create professional severity distribution with chart and summary table."""
    elements.append(Paragraph("2. Risk Distribution Analysis", styles['SectionHeading']))
    elements.append(Spacer(1, 0.1*inch))
    
    dist = summary.get("risk_distribution", {}) if scan_type == "port_scan" else summary
    
    crit = dist.get("Critical", 0) if scan_type == "port_scan" else dist.get("critical", 0)
    high = dist.get("High", 0) if scan_type == "port_scan" else dist.get("high", 0)
    med = dist.get("Medium", 0) if scan_type == "port_scan" else dist.get("medium", 0)
    low = dist.get("Low", 0) if scan_type == "port_scan" else dist.get("low", 0)
    
    total = sum([crit, high, med, low])
    if total == 0:
        elements.append(Paragraph("No severity data available.", styles['Normal']))
        return
    
    # Risk distribution table with visual bars
    risk_table_data = [[
        Paragraph("<b>Severity</b>", ParagraphStyle('TableHeader', fontSize=10, textColor=EnterpriseTheme.TEXT, fontName="Helvetica-Bold")),
        Paragraph("<b>Count</b>", ParagraphStyle('TableHeader', fontSize=10, textColor=EnterpriseTheme.TEXT, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Percentage</b>", ParagraphStyle('TableHeader', fontSize=10, textColor=EnterpriseTheme.TEXT, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Distribution</b>", ParagraphStyle('TableHeader', fontSize=10, textColor=EnterpriseTheme.TEXT, fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]]
    
    severity_levels = [
        ("Critical", crit, EnterpriseTheme.CRITICAL, EnterpriseTheme.CRITICAL_BG),
        ("High", high, EnterpriseTheme.HIGH, EnterpriseTheme.HIGH_BG),
        ("Medium", med, EnterpriseTheme.MEDIUM, EnterpriseTheme.MEDIUM_BG),
        ("Low", low, EnterpriseTheme.LOW, EnterpriseTheme.LOW_BG),
    ]
    
    for level, count, color, bg_color in severity_levels:
        pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
        bar_width = int((count / max(total, 1)) * 150)
        
        risk_table_data.append([
            Paragraph(f"<font color='{color.hexval()}'><b>{level}</b></font>", 
                     ParagraphStyle('RiskLevel', fontSize=10, fontName="Helvetica-Bold")),
            Paragraph(str(count), ParagraphStyle('RiskCount', fontSize=10, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            Paragraph(pct, ParagraphStyle('RiskPct', fontSize=10, alignment=TA_CENTER)),
            Table([[""]], colWidths=[bar_width], rowHeights=[12], 
                  style=TableStyle([
                      ('BACKGROUND', (0,0), (-1,-1), color),
                      ('LEFTPADDING', (0,0), (-1,-1), 0),
                      ('RIGHTPADDING', (0,0), (-1,-1), 0),
                      ('TOPPADDING', (0,0), (-1,-1), 0),
                      ('BOTTOMPADDING', (0,0), (-1,-1), 0),
                  ])) if count > 0 else Paragraph("—", ParagraphStyle('EmptyBar', fontSize=10, alignment=TA_CENTER, textColor=EnterpriseTheme.TEXT_MUTED)),
        ])
    
    # Normalize table data to ensure consistent dimensions
    risk_table_data = safe_table_data(risk_table_data)
    risk_table = Table(risk_table_data, colWidths=[1.2*inch, 0.9*inch, 1*inch, 2.9*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.HEADER_BG),
        ('TEXTCOLOR', (0,0), (-1,0), EnterpriseTheme.TEXT),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('ALIGN', (0,0), (1,-1), 'LEFT'),
        ('ALIGN', (1,0), (2,-1), 'CENTER'),
        ('ALIGN', (3,0), (3,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, EnterpriseTheme.BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Summary text
    summary_text = f"Total Findings: <b>{total}</b> | Critical/High Ratio: <b>{crit+high}/{total}</b> ({((crit+high)/max(total,1)*100):.1f}%)"
    elements.append(Paragraph(summary_text, ParagraphStyle(
        'DistSummary', fontSize=10, textColor=EnterpriseTheme.TEXT_LIGHT, alignment=TA_CENTER
    )))
    elements.append(Spacer(1, 0.3*inch))
    elements.append(PageBreak())

def _create_detailed_findings(elements, styles, findings: List[Dict], scan_type: str):
    """Create professional detailed findings section with clean formatting."""
    elements.append(Paragraph("3. Detailed Findings", styles['SectionHeading']))
    elements.append(Paragraph(
        "Comprehensive list of all identified security findings with risk assessment and remediation guidance.",
        ParagraphStyle('SubText', parent=styles['Normal'], fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, spaceAfter=16)
    ))

    if not findings:
        elements.append(Paragraph("No findings were detected.", styles['Normal']))
        return

    # Sort findings by risk level (Critical first)
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        [f for f in findings if isinstance(f, dict)],
        key=lambda x: risk_order.get(str(x.get("risk", "Low")).upper(), 4)
    )

    for idx, item in enumerate(sorted_findings[:50]):  # Limit to first 50 for PDF size
        risk = str(item.get("risk", "Low")).upper()
        risk_color = _get_risk_color(risk)
        risk_bg = _get_risk_bg_color(risk)

        # Determine title based on scan type
        if scan_type == "port_scan":
            port = item.get("port", "N/A")
            service = item.get("service", "Unknown")
            title = f"Finding #{idx+1}: Port {port} ({service})"
            finding_type = "Port Exposure"
        else:
            category = item.get("category", "Unknown")
            title = f"Finding #{idx+1}: {category}"
            finding_type = "Configuration Issue"

        # Create finding card container
        finding_elements = []
        
        # Header row with risk badge
        header_data = [[
            Paragraph(f"<b>{title}</b>", ParagraphStyle(
                'FindingTitle', fontSize=11, textColor=EnterpriseTheme.TEXT, fontName="Helvetica-Bold"
            )),
            Paragraph(f"<b>{risk}</b>", ParagraphStyle(
                'RiskBadge', fontSize=9, textColor=risk_color, fontName="Helvetica-Bold", alignment=TA_CENTER
            ))
        ]]
        
        header_table = Table(header_data, colWidths=[5*inch, 1*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (1,0), (1,0), risk_bg),
            ('BOX', (1,0), (1,0), 1, risk_color),
            ('LEFTPADDING', (0,0), (0,0), 0),
            ('RIGHTPADDING', (1,0), (1,0), 8),
            ('TOPPADDING', (0,0), (-1,0), 4),
            ('BOTTOMPADDING', (0,0), (-1,0), 4),
            ('VALIGN', (0,0), (-1,0), 'MIDDLE'),
        ]))
        finding_elements.append(header_table)
        finding_elements.append(Spacer(1, 8))
        
        # Finding type label
        finding_elements.append(Paragraph(
            f"<font size='9' color='{EnterpriseTheme.TEXT_MUTED.hexval()}'>Type: {finding_type}</font>",
            ParagraphStyle('FindingType', fontSize=9, textColor=EnterpriseTheme.TEXT_MUTED)
        ))

        # Description content based on scan type
        content_style = ParagraphStyle(
            'FindingContent', 
            parent=styles['Normal'], 
            fontSize=9.5, 
            leading=14,
            spaceAfter=6
        )
        
        if scan_type == "port_scan":
            issue = item.get("issue", "")
            if issue:
                finding_elements.append(Paragraph(f"<b>Issue:</b> {issue}", content_style))
            note = item.get("note", "")
            if note:
                finding_elements.append(Paragraph(f"<b>Details:</b> {note}", content_style))
            version = item.get("version", "")
            if version:
                finding_elements.append(Paragraph(f"<b>Version Detected:</b> <code>{version}</code>", content_style))
            state = item.get("state", "")
            if state:
                finding_elements.append(Paragraph(f"<b>Port State:</b> {state.title()}", content_style))
        else:
            # OS inspection format - safely handle analysis
            analysis = item.get("analysis", {}) if isinstance(item.get("analysis"), dict) else {}
            summary_text = analysis.get("summary") or ""
            if summary_text:
                finding_elements.append(Paragraph(f"<b>Assessment:</b> {summary_text}", content_style))
            logic_text = analysis.get("logic") or ""
            if logic_text:
                finding_elements.append(Paragraph(f"<b>Rationale:</b> {logic_text}", content_style))

            # Show findings dict
            findings_dict = item.get("findings", {})
            if findings_dict and isinstance(findings_dict, dict):
                for key, value in findings_dict.items():
                    if value and str(value).strip():
                        display_value = str(value)[:150] + "..." if len(str(value)) > 150 else str(value)
                        finding_elements.append(Paragraph(
                            f"<b>{key.replace('_', ' ').title()}:</b> {display_value}", 
                            content_style
                        ))

        # CVEs section
        cves = item.get("cves", []) or item.get("nvd", [])
        if cves:
            cve_text = _format_cves(cves)
            if cve_text:
                finding_elements.append(Spacer(1, 4))
                cve_para = Paragraph(
                    f"<b>Security References:</b> <font color='{EnterpriseTheme.CRITICAL.hexval()}'>{cve_text}</font>",
                    ParagraphStyle('CVEText', fontSize=9, textColor=EnterpriseTheme.TEXT)
                )
                finding_elements.append(cve_para)

        # Wrap finding in a bordered container
        finding_content = Table([[e] for e in finding_elements], colWidths=[6*inch])
        finding_content.setStyle(TableStyle([
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('RIGHTPADDING', (0,0), (-1,-1), 12),
            ('TOPPADDING', (0,0), (-1,0), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('BOX', (0,0), (-1,-1), 0.5, EnterpriseTheme.BORDER),
            ('BACKGROUND', (0,0), (-1,-1), EnterpriseTheme.PANEL_BG),
            ('ROUNDEDCORNERS', (0,0), (-1,-1), 4),
        ]))
        
        elements.append(KeepTogether([
            finding_content,
            Spacer(1, 0.15*inch)
        ]))

    elements.append(PageBreak())

def _format_cves(cves) -> str:
    """Format CVE list for display."""
    if not cves:
        return ""
    cve_strings = []
    for cve in cves[:5]:  # Limit to first 5 CVEs
        if isinstance(cve, dict):
            cve_id = cve.get("cve_id", "")
            if cve_id:
                cve_strings.append(cve_id)
        elif isinstance(cve, str):
            cve_strings.append(cve)
    return ", ".join(cve_strings) if cve_strings else ""

def _create_cve_table(elements, styles, data: List[Dict]):
    """Create professional CVE and critical findings table."""
    elements.append(Paragraph("4. Critical & High Severity Findings", styles['SectionHeading']))
    elements.append(Paragraph(
        "Prioritized list of critical and high-risk vulnerabilities requiring immediate attention.",
        ParagraphStyle('SubText', parent=styles['Normal'], fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, spaceAfter=16)
    ))
    
    table_data = [[
        Paragraph("<b>Finding</b>", ParagraphStyle('TableHeader', fontSize=10, fontName="Helvetica-Bold")),
        Paragraph("<b>Risk</b>", ParagraphStyle('TableHeader', fontSize=10, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Security References</b>", ParagraphStyle('TableHeader', fontSize=10, fontName="Helvetica-Bold")),
        Paragraph("<b>Description</b>", ParagraphStyle('TableHeader', fontSize=10, fontName="Helvetica-Bold")),
    ]]
    
    has_items = False
    for item in data:
        if not isinstance(item, dict): 
            continue
        risk = str(item.get("risk", "Low")).upper()
        if risk not in ["CRITICAL", "HIGH"]: 
            continue
        
        has_items = True
        
        # Determine finding identifier
        if "port" in item:
            ident = f"Port {item.get('port')} ({item.get('service', 'Unknown')})"
        else:
            ident = item.get("category", "Unknown")
        
        # Collect CVEs and references
        ref_parts = []
        cve_list = item.get("cves", []) or item.get("nvd", [])
        if cve_list:
            for cve in cve_list[:3]:
                if isinstance(cve, dict):
                    cve_id = cve.get("cve_id", "") or cve.get("id", "")
                    if cve_id:
                        ref_parts.append(cve_id)
                elif isinstance(cve, str):
                    ref_parts.append(cve)
        
        # Add MITRE reference
        mitre = item.get("mitre_attack", {})
        if mitre and mitre.get("technique_id"):
            ref_parts.append(f"MITRE {mitre.get('technique_id')}")
        
        refs = ", ".join(ref_parts) if ref_parts else "None identified"
        
        # Description - safely handle
        desc = ""
        if item.get("scan_type"):
            desc = item.get("issue", "") or ""
        else:
            issue = item.get("issue") or ""
            analysis = item.get("analysis", {}) if isinstance(item.get("analysis"), dict) else {}
            summary = analysis.get("summary") or ""
            desc = issue or summary or "No description available"
        
        # Ensure desc is a string
        desc = str(desc) if desc else "No description available"
        
        if len(desc) > 100:
            desc = desc[:97] + "..."
        
        risk_color = _get_risk_color(risk)
        
        table_data.append([
            Paragraph(ident, ParagraphStyle('CellText', fontSize=9, textColor=EnterpriseTheme.TEXT)),
            Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk}</b></font>", 
                     ParagraphStyle('CellRisk', fontSize=9, alignment=TA_CENTER)),
            Paragraph(refs, ParagraphStyle('CellRefs', fontSize=8.5, textColor=EnterpriseTheme.CRITICAL)),
            Paragraph(desc, ParagraphStyle('CellDesc', fontSize=9, textColor=EnterpriseTheme.TEXT_LIGHT)),
        ])
    
    if not has_items:
        elements.append(Paragraph(
            "No critical or high-severity findings were detected in this scan.",
            ParagraphStyle('NoFindings', fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, italic=True)
        ))
        elements.append(Spacer(1, 0.5*inch))
        return

    # Normalize table data to ensure consistent dimensions
    table_data = safe_table_data(table_data)
    t = Table(table_data, colWidths=[1.6*inch, 0.9*inch, 2.3*inch, 2.2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), EnterpriseTheme.WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ALIGN', (0,0), (0,-1), 'LEFT'),
        ('ALIGN', (1,0), (1,-1), 'CENTER'),
        ('ALIGN', (2,0), (3,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, EnterpriseTheme.BORDER),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,1), (-1,-1), EnterpriseTheme.PANEL_BG),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.3*inch))

def _create_mitre_mapping(elements, styles, data: List[Dict]):
    """Create professional MITRE ATT&CK framework mapping table."""
    elements.append(Paragraph("5. MITRE ATT&CK Framework Mapping", styles['SectionHeading']))
    elements.append(Paragraph(
        "Identified threat vectors mapped to the MITRE ATT&CK framework for contextual threat understanding.",
        ParagraphStyle('SubText', parent=styles['Normal'], fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, spaceAfter=16)
    ))
    
    mitre_items = []
    for item in data:
        if not isinstance(item, dict):
            continue
        m = item.get("mitre_attack")
        if m and m.get("technique_id"):
            ident = f"Port {item.get('port')}" if "port" in item else item.get("category", "")
            mitre_items.append([
                m.get("tactic", "Unknown"),
                m.get("technique_id", ""),
                m.get("technique", "Unknown"),
                ident
            ])
    
    if not mitre_items:
        elements.append(Paragraph(
            "No MITRE ATT&CK mappings were generated for this scan.",
            ParagraphStyle('NoMitre', fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, italic=True)
        ))
        elements.append(Spacer(1, 0.5*inch))
        return
    
    # Deduplicate based on technique_id
    seen = set()
    uniq_mitre = []
    for m in mitre_items:
        # Safety check: ensure m has at least 2 elements before accessing m[1]
        if len(m) >= 2 and m[1] not in seen:
            seen.add(m[1])
            uniq_mitre.append(m)
    
    # Build table with styled header
    t_data = [[
        Paragraph("<b>Tactic</b>", ParagraphStyle('MitreHeader', fontSize=10, fontName="Helvetica-Bold")),
        Paragraph("<b>Technique ID</b>", ParagraphStyle('MitreHeader', fontSize=10, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Technique</b>", ParagraphStyle('MitreHeader', fontSize=10, fontName="Helvetica-Bold")),
        Paragraph("<b>Affected Asset</b>", ParagraphStyle('MitreHeader', fontSize=10, fontName="Helvetica-Bold")),
    ]]
    
    for m in uniq_mitre:
        # Ensure m has all 4 elements - pad if necessary
        while len(m) < 4:
            m.append("")
        t_data.append([
            Paragraph(str(m[0]), ParagraphStyle('MitreCell', fontSize=9, textColor=EnterpriseTheme.TEXT)),
            Paragraph(f"<font color='{EnterpriseTheme.ACCENT.hexval()}'><b>{m[1]}</b></font>",
                     ParagraphStyle('MitreId', fontSize=9, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            Paragraph(str(m[2]), ParagraphStyle('MitreCell', fontSize=9, textColor=EnterpriseTheme.TEXT)),
            Paragraph(str(m[3]), ParagraphStyle('MitreCell', fontSize=9, textColor=EnterpriseTheme.TEXT_MUTED)),
        ])

    # Only create table if we have data rows beyond header
    if len(t_data) < 2:
        elements.append(Paragraph(
            "No valid MITRE ATT&CK mappings were generated for this scan.",
            ParagraphStyle('NoMitre', fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, italic=True)
        ))
        elements.append(Spacer(1, 0.5*inch))
        return

    # Use safe table data to ensure consistent column counts
    t_data = safe_table_data(t_data)
    t = Table(t_data, colWidths=[1.4*inch, 1.1*inch, 3*inch, 1.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), EnterpriseTheme.WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, EnterpriseTheme.BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,1), (-1,-1), EnterpriseTheme.PANEL_BG),
    ]))
    elements.append(t)
    elements.append(PageBreak())

def _create_attack_surface(elements, styles, findings: List[Dict], scan_type: str):
    """Create professional attack surface analysis section."""
    elements.append(Paragraph("6. Attack Surface Analysis", styles['SectionHeading']))
    elements.append(Paragraph(
        "Comprehensive overview of the discovered attack surface and exposure vectors.",
        ParagraphStyle('SubText', parent=styles['Normal'], fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, spaceAfter=16)
    ))

    if not findings:
        elements.append(Paragraph("No attack surface data available.", styles['Normal']))
        return

    # Calculate statistics
    critical_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "HIGH")
    medium_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "MEDIUM")
    low_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "LOW")
    total = len(findings)

    # Create severity summary cards
    severity_cards = [
        ("Critical", critical_count, EnterpriseTheme.CRITICAL, EnterpriseTheme.CRITICAL_BG),
        ("High", high_count, EnterpriseTheme.HIGH, EnterpriseTheme.HIGH_BG),
        ("Medium", medium_count, EnterpriseTheme.MEDIUM, EnterpriseTheme.MEDIUM_BG),
        ("Low", low_count, EnterpriseTheme.LOW, EnterpriseTheme.LOW_BG),
    ]
    
    card_data = []
    card_row = []
    for level, count, color, bg in severity_cards:
        pct = (count / max(total, 1) * 100)
        card_content = [
            Paragraph(str(count), ParagraphStyle(
                'SeverityCount', fontSize=24, textColor=color, fontName="Helvetica-Bold", alignment=TA_CENTER
            )),
            Paragraph(level, ParagraphStyle(
                'SeverityLabel', fontSize=9, textColor=EnterpriseTheme.TEXT_MUTED, alignment=TA_CENTER
            )),
            Paragraph(f"{pct:.1f}%", ParagraphStyle(
                'SeverityPct', fontSize=10, textColor=color, alignment=TA_CENTER
            )),
        ]
        card_row.append(card_content)
    
    # 1 row with 4 columns (horizontal card layout)
    card_table = Table([card_row], colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
    card_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 0.5, EnterpriseTheme.BORDER),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), 4),
        ('BACKGROUND', (0,0), (0,0), EnterpriseTheme.CRITICAL_BG),
        ('BACKGROUND', (1,0), (1,0), EnterpriseTheme.HIGH_BG),
        ('BACKGROUND', (2,0), (2,0), EnterpriseTheme.MEDIUM_BG),
        ('BACKGROUND', (3,0), (3,0), EnterpriseTheme.LOW_BG),
    ]))
    elements.append(card_table)
    elements.append(Spacer(1, 0.25*inch))

    # Scan-type specific details
    if scan_type == "port_scan":
        # Port scan stats
        open_ports = list(set([f.get("port") for f in findings if f.get("port")]))
        services = list(set([f.get("service", "Unknown") for f in findings if f.get("service")]))
        
        stats_data = [
            ["Metric", "Value"],
            ["Total Open Ports", str(len(open_ports))],
            ["Unique Services Detected", str(len(services))],
            ["Total Findings", str(total)],
        ]
        
        # Normalize table data to ensure consistent dimensions
        stats_data = safe_table_data(stats_data)
        stats_table = Table(stats_data, colWidths=[2.5*inch, 3.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.HEADER_BG),
            ('TEXTCOLOR', (0,0), (-1,0), EnterpriseTheme.TEXT),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('ALIGN', (0,0), (0,-1), 'LEFT'),
            ('ALIGN', (1,0), (1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('LINEBELOW', (0,0), (-1,-2), 0.5, EnterpriseTheme.BORDER),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,1), (-1,-1), EnterpriseTheme.PANEL_BG),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.2*inch))

        # Top critical exposures
        critical_findings = [f for f in findings if str(f.get("risk", "")).upper() in ["CRITICAL", "HIGH"]]
        if critical_findings:
            elements.append(Paragraph("<b>Priority Exposures Requiring Immediate Action</b>", 
                         ParagraphStyle('PriorityHeader', fontSize=11, textColor=EnterpriseTheme.TEXT, spaceAfter=8)))
            
            for cf in critical_findings[:8]:
                port = cf.get("port", "N/A")
                service = cf.get("service", "Unknown")
                issue = cf.get("issue", "")
                risk = str(cf.get("risk", "")).upper()
                risk_color = _get_risk_color(risk)
                
                elements.append(Paragraph(
                    f"<font color='{risk_color.hexval()}'>&#9679;</font> <b>Port {port}</b> ({service}): {issue[:80]}{'...' if len(issue) > 80 else ''}",
                    ParagraphStyle('ExposureItem', fontSize=9.5, leading=16, leftIndent=12)
                ))
    else:
        # OS inspection stats
        elements.append(Paragraph(f"<b>Configuration Checks Completed:</b> {total}", 
                     ParagraphStyle('StatsText', fontSize=10, spaceAfter=8)))

        # Categories with issues
        categories = {}
        for f in findings:
            risk = str(f.get("risk", "")).upper()
            cat = f.get("category", "Unknown")
            if risk in ["CRITICAL", "HIGH"]:
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(f)

        if categories:
            elements.append(Paragraph("<b>High-Risk Configuration Categories</b>", 
                         ParagraphStyle('CategoryHeader', fontSize=11, textColor=EnterpriseTheme.TEXT, spaceAfter=8)))
            
            # Sort safely - categories.items() returns (key, value) tuples
            # Ensure value is a list before getting its length
            def _safe_cat_sort(item):
                # item is always a 2-tuple from items()
                key, value = item
                if isinstance(value, (list, tuple)):
                    return len(value)
                return 0
            sorted_cats = sorted(categories.items(), key=_safe_cat_sort, reverse=True)[:8]
            for cat, items in sorted_cats:
                if isinstance(items, (list, tuple)):
                    high_risk_count = sum(1 for i in items if str(i.get("risk", "")).upper() == "CRITICAL")
                    elements.append(Paragraph(
                        f"<font color='{EnterpriseTheme.CRITICAL.hexval()}'>&#9679;</font> <b>{cat}:</b> {len(items)} findings ({high_risk_count} critical)",
                        ParagraphStyle('CategoryItem', fontSize=9.5, leading=16, leftIndent=12)
                    ))

    elements.append(Spacer(1, 0.3*inch))
    elements.append(PageBreak())


def _create_remediation(elements, styles):
    """Create professional remediation roadmap with phased approach."""
    elements.append(Paragraph("7. Remediation Roadmap", styles['SectionHeading']))
    elements.append(Paragraph(
        "Prioritized action plan to address identified security findings and improve security posture.",
        ParagraphStyle('SubText', parent=styles['Normal'], fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, spaceAfter=16)
    ))
    
    # Phase cards with visual distinction
    phases = [
        {
            "phase": "Phase 1",
            "timeline": "0-7 Days",
            "color": EnterpriseTheme.CRITICAL,
            "bg": EnterpriseTheme.CRITICAL_BG,
            "actions": [
                "Patch all critical CVEs immediately",
                "Isolate or restrict high-risk exposed management ports (RDP, SMB, Telnet)",
                "Disable unnecessary services and unused accounts",
                "Review and strengthen access controls"
            ]
        },
        {
            "phase": "Phase 2",
            "timeline": "8-30 Days",
            "color": EnterpriseTheme.HIGH,
            "bg": EnterpriseTheme.HIGH_BG,
            "actions": [
                "Implement strict password policies and MFA where possible",
                "Disable legacy protocols (NetBIOS, LLMNR, SMBv1)",
                "Deploy and configure endpoint protection solutions",
                "Establish security logging and monitoring"
            ]
        },
        {
            "phase": "Phase 3",
            "timeline": "Ongoing",
            "color": EnterpriseTheme.ACCENT,
            "bg": EnterpriseTheme.PANEL_BG,
            "actions": [
                "Implement continuous vulnerability scanning",
                "Deploy network segmentation and zero-trust principles",
                "Establish incident response procedures",
                "Regular security awareness training"
            ]
        }
    ]
    
    for phase in phases:
        # Phase header
        phase_header = Table([[
            Paragraph(f"<b>{phase['phase']}</b>", ParagraphStyle(
                'PhaseTitle', fontSize=12, textColor=phase['color'], fontName="Helvetica-Bold"
            )),
            Paragraph(f"<b>{phase['timeline']}</b>", ParagraphStyle(
                'PhaseTimeline', fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, alignment=TA_RIGHT
            ))
        ]], colWidths=[3*inch, 3*inch])
        phase_header.setStyle(TableStyle([
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('VALIGN', (0,0), (-1,0), 'MIDDLE'),
        ]))
        elements.append(phase_header)
        
        # Action items
        for action in phase['actions']:
            elements.append(Paragraph(
                f"<font color='{phase['color'].hexval()}'>&#9654;</font> {action}",
                ParagraphStyle('ActionItem', fontSize=9.5, leading=16, leftIndent=16, spaceAfter=6)
            ))
        
        elements.append(Spacer(1, 0.15*inch))
    
    # Compliance note
    elements.append(Spacer(1, 0.15*inch))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=EnterpriseTheme.BORDER, spaceBefore=0, spaceAfter=12))
    elements.append(Paragraph(
        "<b>Compliance Alignment:</b> Addressing these findings improves alignment with NIST Cybersecurity Framework, "
        "CIS Controls, ISO 27001, and enterprise security baselines.",
        ParagraphStyle('ComplianceNote', fontSize=10, textColor=EnterpriseTheme.TEXT_LIGHT, leading=16)
    ))

def _create_technical_appendix(elements, styles, findings: List[Dict], scan_type: str):
    """Create professional technical appendix with command outputs."""
    elements.append(Paragraph("8. Technical Appendix", styles['SectionHeading']))
    elements.append(Paragraph(
        "Technical details and raw command outputs for security analysts and remediation teams.",
        ParagraphStyle('SubText', parent=styles['Normal'], fontSize=10, textColor=EnterpriseTheme.TEXT_MUTED, spaceAfter=16)
    ))

    if not findings:
        elements.append(Paragraph("No technical data available.", styles['Normal']))
        return

    # Commands executed (for OS inspection)
    if scan_type != "port_scan":
        elements.append(Paragraph("<b>Inspection Commands Executed</b>", 
                     ParagraphStyle('AppendixHeader', fontSize=11, textColor=EnterpriseTheme.TEXT, spaceAfter=10)))
        
        commands_data = [[
            Paragraph("<b>Category</b>", ParagraphStyle('CmdHeader', fontSize=9, fontName="Helvetica-Bold")),
            Paragraph("<b>Command Executed</b>", ParagraphStyle('CmdHeader', fontSize=9, fontName="Helvetica-Bold")),
        ]]
        
        commands_seen = set()
        for item in findings[:15]:  # Limit to first 15
            cmd_info = item.get("command", {})
            if isinstance(cmd_info, dict):
                cmd = cmd_info.get("executed", "")
                category = item.get("category", "Unknown")
                if cmd and cmd not in commands_seen:
                    commands_seen.add(cmd)
                    # Truncate long commands
                    display_cmd = cmd[:80] + "..." if len(cmd) > 80 else cmd
                    commands_data.append([
                        Paragraph(category, ParagraphStyle('CmdCategory', fontSize=8.5, textColor=EnterpriseTheme.TEXT_MUTED)),
                        Paragraph(f"<code>{display_cmd}</code>", ParagraphStyle('CmdText', fontSize=8, textColor=EnterpriseTheme.TEXT, fontName="Courier")),
                    ])
        
        if len(commands_data) > 1:
            # Normalize table data to ensure consistent dimensions
            commands_data = safe_table_data(commands_data)
            cmd_table = Table(commands_data, colWidths=[1.5*inch, 4.5*inch])
            cmd_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.HEADER_BG),
                ('TEXTCOLOR', (0,0), (-1,0), EnterpriseTheme.TEXT),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,-2), 0.5, EnterpriseTheme.BORDER),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BACKGROUND', (0,1), (-1,-1), EnterpriseTheme.PANEL_BG),
            ]))
            elements.append(cmd_table)
        
        elements.append(Spacer(1, 0.25*inch))

    # Sample outputs section
    elements.append(Paragraph("<b>Sample Command Outputs</b>", 
                 ParagraphStyle('OutputHeader', fontSize=11, textColor=EnterpriseTheme.TEXT, spaceAfter=10)))
    
    for item in findings[:3]:  # Show first 3
        if not isinstance(item, dict):
            continue
        
        category = item.get("category", item.get("port", "Unknown"))
        
        # Create output box
        output_elements = []
        output_elements.append(Paragraph(
            f"<b>{category}</b>",
            ParagraphStyle('OutputCategory', fontSize=10, textColor=EnterpriseTheme.ACCENT)
        ))
        
        cmd_info = item.get("command", {}) if isinstance(item.get("command"), dict) else {}
        output = cmd_info.get("raw_output") if isinstance(cmd_info, dict) else None
        if output:
            # Clean and truncate output
            clean_output = str(output)[:400].replace("<", "&lt;").replace(">", "&gt;")
            lines = clean_output.split('\n')[:10] if clean_output else []  # First 10 lines
            formatted_output = '\n'.join(lines)
            if len(clean_output) > 400:
                formatted_output += "\n[Output truncated...]"
                
                output_elements.append(Spacer(1, 6))
                output_elements.append(Paragraph(
                    f"<font face='Courier' size='8' color='{EnterpriseTheme.TEXT_MUTED.hexval()}'>{formatted_output}</font>",
                    ParagraphStyle('OutputText', fontSize=8, fontName="Courier", leading=12, 
                                 textColor=EnterpriseTheme.TEXT_MUTED)
                ))
        
        # Wrap in styled container
        if len(output_elements) > 1:
            output_box = Table([[e] for e in output_elements], colWidths=[6*inch])
            output_box.setStyle(TableStyle([
                ('LEFTPADDING', (0,0), (-1,-1), 12),
                ('RIGHTPADDING', (0,0), (-1,-1), 12),
                ('TOPPADDING', (0,0), (-1,0), 10),
                ('BOTTOMPADDING', (0,0), (-1,-1), 12),
                ('BOX', (0,0), (-1,-1), 0.5, EnterpriseTheme.BORDER),
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0a0f1a")),
                ('ROUNDEDCORNERS', (0,0), (-1,-1), 4),
            ]))
            elements.append(KeepTogether([
                output_box,
                Spacer(1, 0.15*inch)
            ]))

    elements.append(PageBreak())

def generate_pdf(scan_data: Dict) -> str:
    # Normalize scan data to handle both OS inspection and port scan formats
    normalized = _normalize_scan_data(scan_data)

    scan_id = normalized.get("scan_id", scan_data.get("scan_id", "unknown"))
    scan_type = normalized.get("scan_type", "unknown")
    target = normalized.get("target", "unknown")
    summary = normalized.get("summary", {})
    findings = normalized.get("findings", [])

    print(f"[PDF] Generating report for scan_id={scan_id}, type={scan_type}")
    print(f"[PDF] Summary: {summary}")
    print(f"[PDF] Findings count: {len(findings)}")

    safe_id = str(scan_id).replace(" ", "_").replace(":", "-")[:30]
    filename = f"Security_Report_{scan_type}_{safe_id}.pdf"
    filepath = os.path.join(OUTPUT_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=(8.5*inch, 11*inch), rightMargin=0.75*inch, leftMargin=0.75*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()

    # FIX: getSampleStyleSheet() returns a module-level singleton in ReportLab.
    # If generate_pdf() is called more than once in the same process, the custom
    # styles we added in the first call are still registered, so we must guard
    # against 'already defined' errors with a try/except.
    def _safe_add_style(styles, style):
        try:
            styles.add(style)
        except KeyError:
            pass  # style already registered from a previous call — that's fine

    # Professional document styles
    _safe_add_style(styles, ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=EnterpriseTheme.PRIMARY,
        spaceAfter=16,
        spaceBefore=24,
        fontName='Helvetica-Bold',
        leading=24
    ))
    _safe_add_style(styles, ParagraphStyle(
        'SubSectionHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=EnterpriseTheme.SECONDARY,
        spaceAfter=10,
        spaceBefore=16,
        fontName='Helvetica-Bold'
    ))
    _safe_add_style(styles, ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontSize=10,
        leading=16,
        textColor=EnterpriseTheme.TEXT
    ))

    elements = []

    try:
        _create_cover_page(elements, styles, normalized)
    except Exception as e:
        print(f"[PDF ERROR] _create_cover_page failed: {e}")
        raise
    try:
        _create_executive_summary(elements, styles, summary, scan_type)
    except Exception as e:
        print(f"[PDF ERROR] _create_executive_summary failed: {e}")
        raise
    try:
        _create_heatmap(elements, styles, summary, scan_type)
    except Exception as e:
        print(f"[PDF ERROR] _create_heatmap failed: {e}")
        raise
    try:
        _create_detailed_findings(elements, styles, findings, scan_type)
    except Exception as e:
        print(f"[PDF ERROR] _create_detailed_findings failed: {e}")
        raise
    try:
        _create_cve_table(elements, styles, findings)
    except Exception as e:
        print(f"[PDF ERROR] _create_cve_table failed: {e}")
        raise
    try:
        _create_mitre_mapping(elements, styles, findings)
    except Exception as e:
        print(f"[PDF ERROR] _create_mitre_mapping failed: {e}")
        raise
    try:
        _create_attack_surface(elements, styles, findings, scan_type)
    except Exception as e:
        print(f"[PDF ERROR] _create_attack_surface failed: {e}")
        raise
    try:
        _create_remediation(elements, styles)
    except Exception as e:
        print(f"[PDF ERROR] _create_remediation failed: {e}")
        raise
    try:
        _create_technical_appendix(elements, styles, findings, scan_type)
    except Exception as e:
        print(f"[PDF ERROR] _create_technical_appendix failed: {e}")
        raise

    # Professional footer
    elements.append(Spacer(1, 0.75*inch))
    elements.append(HRFlowable(
        width="100%", thickness=0.5, 
        color=EnterpriseTheme.BORDER, 
        spaceBefore=0, spaceAfter=12
    ))
    footer_text = (
        f"<font color='{EnterpriseTheme.TEXT_MUTED.hexval()}' size='9'>"
        f"Report ID: SEC-{safe_id[:8].upper()} | "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Classification: CONFIDENTIAL"
        f"</font>"
    )
    elements.append(Paragraph(
        footer_text,
        ParagraphStyle('Footer', alignment=TA_CENTER, fontSize=9)
    ))
    elements.append(Paragraph(
        f"<font color='{EnterpriseTheme.TEXT_MUTED.hexval()}' size='8'>Enterprise Security Assessment Platform</font>",
        ParagraphStyle('FooterSub', alignment=TA_CENTER, fontSize=8, spaceBefore=6)
    ))

    # Build the PDF with detailed error handling
    try:
        doc.build(elements)
        print(f"[PDF] Report saved to: {filepath}")
    except IndexError as e:
        print(f"[PDF FATAL ERROR] IndexError during PDF build: {e}")
        import traceback
        traceback.print_exc()
        # Try to identify which table is causing the issue
        print("[PDF DEBUG] Element count:", len(elements))
        for i, elem in enumerate(elements):
            elem_type = type(elem).__name__
            if isinstance(elem, Table):
                print(f"[PDF DEBUG] Element {i}: Table - checking dimensions...")
        raise
    except Exception as e:
        print(f"[PDF FATAL ERROR] Unexpected error during PDF build: {e}")
        import traceback
        traceback.print_exc()
        raise

    return filepath


def _load_findings_for_pdf(scan_id: str, result: Dict) -> List[Dict]:
    """
    Load findings from database for PDF generation.
    Tries DB first, falls back to result.data for legacy support.
    """
    import json
    import traceback

    findings = []

    try:
        # Import inside try block to avoid import errors during PDF generation
        from extensions import db
        from models.finding import Finding

        # Query database for findings
        db_findings = Finding.query.filter_by(scan_id=scan_id).all()
        print(f"[PDF] Loaded {len(db_findings)} findings from database for scan {scan_id}")

        for f in db_findings:
            # Parse raw_data_json to get full finding details
            try:
                raw_data = json.loads(f.raw_data_json) if f.raw_data_json else {}
            except:
                raw_data = {}

            # Safely parse CVEs JSON
            cves = []
            if f.cves_json:
                try:
                    parsed = json.loads(f.cves_json)
                    if isinstance(parsed, list):
                        cves = parsed
                except (json.JSONDecodeError, TypeError):
                    cves = []
            
            # Safely get analysis sub-dict
            analysis = raw_data.get("analysis", {}) if isinstance(raw_data.get("analysis"), dict) else {}
            
            finding_dict = {
                "port": f.port,
                "service": f.service,
                "state": f.state,
                "category": f.category,
                "issue": f.issue or raw_data.get("issue") or analysis.get("summary") or "Unknown finding",
                "risk": f.risk_level or "LOW",
                "note": f.note or raw_data.get("note") or analysis.get("logic") or "",
                "cves": cves,
                "mitre_attack": raw_data.get("mitre_attack", {}) if isinstance(raw_data.get("mitre_attack"), dict) else {}
            }
            findings.append(finding_dict)

    except Exception as e:
        print(f"[PDF] Database query failed: {e}")
        traceback.print_exc()
        # Fallback to result.data if DB query fails
        findings = result.get("data", [])
        print(f"[PDF] Fallback to result.data: {len(findings)} findings")

    return findings
