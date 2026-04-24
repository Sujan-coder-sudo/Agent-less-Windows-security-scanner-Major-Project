"""
pdf_service.py
Enterprise-grade PDF report generation for security scans.
Features Cover Page, Executive Summary, Heatmaps, and MITRE ATT&CK Mapping.
"""

import os
from datetime import datetime
from typing import Dict, Any, List

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, ListFlowable, ListItem
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "backend", "data", "exports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

class EnterpriseTheme:
    PRIMARY = colors.HexColor("#0f172a") # Slate 900
    SECONDARY = colors.HexColor("#334155") # Slate 700
    ACCENT = colors.HexColor("#3b82f6") # Blue 500
    BACKGROUND = colors.HexColor("#f8fafc") # Slate 50
    CRITICAL = colors.HexColor("#dc2626") # Red 600
    HIGH = colors.HexColor("#ea580c") # Orange 600
    MEDIUM = colors.HexColor("#ca8a04") # Yellow 600
    LOW = colors.HexColor("#16a34a") # Green 600
    TEXT = colors.HexColor("#1e293b") # Slate 800
    LIGHT_TEXT = colors.HexColor("#64748b") # Slate 500

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
    return getattr(EnterpriseTheme, level.upper(), EnterpriseTheme.LOW)

def _format_timestamp(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y at %I:%M %p UTC")
    except:
        return ts

def _create_cover_page(elements, styles, scan_data: Dict):
    scan_type = scan_data.get("scan_type", "Unknown")
    target = scan_data.get("target", "Unknown")
    timestamp = _format_timestamp(scan_data.get("timestamp", "Unknown"))
    
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontSize=36,
        textColor=EnterpriseTheme.PRIMARY,
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold"
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontSize=18,
        textColor=EnterpriseTheme.ACCENT,
        alignment=TA_CENTER,
        spaceAfter=100
    )
    
    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontSize=14,
        textColor=EnterpriseTheme.SECONDARY,
        alignment=TA_CENTER,
        spaceAfter=10
    )

    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("SECURITY POSTURE ASSESSMENT", title_style))
    
    scan_label = "Network Exposure Analysis" if scan_type == "port_scan" else "System Configuration Audit"
    elements.append(Paragraph(scan_label, subtitle_style))
    
    elements.append(Paragraph(f"<b>Target Scope:</b> {target}", meta_style))
    elements.append(Paragraph(f"<b>Generated On:</b> {timestamp}", meta_style))
    elements.append(Paragraph(f"<b>Report ID:</b> SEC-{scan_data.get('scan_id', 'Unknown')[:8].upper()}", meta_style))
    
    elements.append(Spacer(1, 3*inch))
    elements.append(Paragraph("<b>CONFIDENTIAL</b>", ParagraphStyle('Conf', alignment=TA_CENTER, textColor=EnterpriseTheme.CRITICAL, fontSize=12)))
    elements.append(PageBreak())

def _create_executive_summary(elements, styles, summary: Dict, scan_type: str):
    elements.append(Paragraph("1. Executive Summary", styles['SectionHeading']))
    
    # Text narrative
    narrative_style = ParagraphStyle('Narrative', parent=styles['Normal'], fontSize=11, leading=16, spaceAfter=20)
    
    if scan_type == "port_scan":
        score = summary.get('risk_score', 0)
        level = _get_risk_level(score)
        color = _get_risk_color(level)
        elements.append(Paragraph(f"The automated network exposure analysis identified <b>{summary.get('open_ports', 0)} open ports</b> out of {summary.get('total_findings', 0)} total findings. The overall calculated risk posture is <b>{score}/10</b>, placing the target asset in the <font color='{color.hexval()}'><b>{level}</b></font> risk tier. Immediate strategic action should be prioritized for critical vulnerabilities.", narrative_style))
    else:
        crit = summary.get('critical', 0)
        high = summary.get('high', 0)
        level = "CRITICAL" if crit > 0 else "HIGH" if high > 0 else "MEDIUM"
        color = _get_risk_color(level)
        elements.append(Paragraph(f"The system configuration audit completed <b>{summary.get('total_checks', 0)} checks</b> across the OS matrix. The environment exhibits a <font color='{color.hexval()}'><b>{level}</b></font> risk posture. {crit} critical and {high} high-severity misconfigurations were detected that require immediate remediation to align with industry compliance standards.", narrative_style))

    # Risk Posture Score Box
    score_data = [[
        Paragraph(f"<font color='white' size=24><b>{level}</b></font>", ParagraphStyle('Score', alignment=TA_CENTER))
    ]]
    t = Table(score_data, colWidths=[6*inch], rowHeights=[1*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 20),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.5*inch))

def _create_heatmap(elements, styles, summary: Dict, scan_type: str):
    elements.append(Paragraph("2. Severity Heatmap", styles['SectionHeading']))
    
    dist = summary.get("risk_distribution", {}) if scan_type == "port_scan" else summary
    
    crit = dist.get("Critical", 0) if scan_type == "port_scan" else dist.get("critical", 0)
    high = dist.get("High", 0) if scan_type == "port_scan" else dist.get("high", 0)
    med = dist.get("Medium", 0) if scan_type == "port_scan" else dist.get("medium", 0)
    low = dist.get("Low", 0) if scan_type == "port_scan" else dist.get("low", 0)
    
    total = sum([crit, high, med, low])
    if total == 0:
        elements.append(Paragraph("No severity data available.", styles['Normal']))
        return

    drawing = Drawing(400, 200)
    pie = Pie()
    pie.x = 100
    pie.y = 20
    pie.width = 150
    pie.height = 150
    pie.data = [x for x in [crit, high, med, low] if x > 0]
    pie.labels = [l for x, l in zip([crit, high, med, low], ['Critical', 'High', 'Medium', 'Low']) if x > 0]
    
    colors_list = []
    if crit > 0: colors_list.append(EnterpriseTheme.CRITICAL)
    if high > 0: colors_list.append(EnterpriseTheme.HIGH)
    if med > 0: colors_list.append(EnterpriseTheme.MEDIUM)
    if low > 0: colors_list.append(EnterpriseTheme.LOW)
    
    for i, c in enumerate(colors_list):
        pie.slices[i].fillColor = c
        
    drawing.add(pie)
    elements.append(drawing)
    elements.append(Spacer(1, 0.5*inch))
    elements.append(PageBreak())

def _create_detailed_findings(elements, styles, findings: List[Dict], scan_type: str):
    elements.append(Paragraph("3. Detailed Findings", styles['SectionHeading']))
    elements.append(Paragraph("Complete list of all identified security findings.", styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))

    if not findings:
        elements.append(Paragraph("No findings were detected.", styles['Normal']))
        return

    for idx, item in enumerate(findings[:50]):  # Limit to first 50 for PDF size
        if not isinstance(item, dict):
            continue

        risk = str(item.get("risk", "Low")).upper()
        risk_color = _get_risk_color(risk)

        # Determine title based on scan type
        if scan_type == "port_scan":
            port = item.get("port", "N/A")
            service = item.get("service", "Unknown")
            title = f"Finding #{idx+1}: Port {port} ({service})"
        else:
            category = item.get("category", "Unknown")
            title = f"Finding #{idx+1}: {category}"

        # Title with risk color
        title_style = ParagraphStyle(
            'FindingTitle',
            parent=styles['Normal'],
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=risk_color,
            spaceAfter=6
        )
        elements.append(Paragraph(title, title_style))

        # Risk badge
        elements.append(Paragraph(f"<b>Risk Level:</b> <font color='{risk_color.hexval()}'>{risk}</font>", styles['Normal']))

        # Description
        if scan_type == "port_scan":
            issue = item.get("issue", "")
            if issue:
                elements.append(Paragraph(f"<b>Issue:</b> {issue}", styles['Normal']))
            note = item.get("note", "")
            if note:
                elements.append(Paragraph(f"<b>Details:</b> {note}", styles['Normal']))
            version = item.get("version", "")
            if version:
                elements.append(Paragraph(f"<b>Version:</b> {version}", styles['Normal']))
        else:
            # OS inspection format
            analysis = item.get("analysis", {})
            if isinstance(analysis, dict):
                summary_text = analysis.get("summary", "")
                if summary_text:
                    elements.append(Paragraph(f"<b>Summary:</b> {summary_text}", styles['Normal']))
                logic_text = analysis.get("logic", "")
                if logic_text:
                    elements.append(Paragraph(f"<b>Logic:</b> {logic_text}", styles['Normal']))

            # Show findings dict for OS inspection
            findings_dict = item.get("findings", {})
            if findings_dict and isinstance(findings_dict, dict):
                for key, value in findings_dict.items():
                    if value:
                        elements.append(Paragraph(f"<b>{key}:</b> {str(value)[:200]}", styles['Normal']))

        # CVEs
        cves = item.get("cves", []) or item.get("nvd", [])
        if cves:
            cve_text = _format_cves(cves)
            if cve_text:
                elements.append(Paragraph(f"<b>CVEs:</b> {cve_text}", styles['Normal']))

        elements.append(Spacer(1, 0.15*inch))

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
    elements.append(Paragraph("4. CVE Table & Critical Findings", styles['SectionHeading']))
    elements.append(Spacer(1, 0.1*inch))
    
    table_data = [["ID / Category", "Risk", "CVE / Mitre", "Description"]]
    
    has_items = False
    for item in data:
        if not isinstance(item, dict): continue
        risk = str(item.get("risk", "Low")).upper()
        if risk not in ["CRITICAL", "HIGH"]: continue
        
        has_items = True
        
        # Determine specific details based on engine
        ident = f"Port {item.get('port')}" if "port" in item else item.get("category", "Unknown")
        
        # Flatten CVEs
        cves = ""
        cve_list = item.get("cves", []) or item.get("nvd", [])
        if cve_list:
            if isinstance(cve_list[0], dict):
                cves = ", ".join([c.get("cve_id", "") for c in cve_list[:3]])
            else:
                cves = ", ".join([str(c) for c in cve_list[:3]])
        
        # Mitre
        mitre = item.get("mitre_attack", {})
        if mitre:
            if cves: cves += "\n"
            cves += f"MITRE: {mitre.get('technique_id', '')}"
            
        desc = item.get("issue") or item.get("analysis", {}).get("summary", "")
        if len(desc) > 80: desc = desc[:77] + "..."
        
        table_data.append([
            Paragraph(ident, styles['Normal']),
            Paragraph(f"<font color='{_get_risk_color(risk).hexval()}'><b>{risk}</b></font>", styles['Normal']),
            Paragraph(cves, styles['Normal']),
            Paragraph(desc, styles['Normal'])
        ])
        
    if not has_items:
        elements.append(Paragraph("No critical or high findings were detected.", styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        return

    t = Table(table_data, colWidths=[1.5*inch, 1*inch, 2*inch, 2.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.SECONDARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.5*inch))

def _create_mitre_mapping(elements, styles, data: List[Dict]):
    elements.append(Paragraph("5. MITRE ATT&CK Mapping", styles['SectionHeading']))
    elements.append(Paragraph("Identified threat vectors mapped to the MITRE ATT&CK framework.", styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    mitre_items = []
    for item in data:
        if not isinstance(item, dict): continue
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
        elements.append(Paragraph("No MITRE ATT&CK mappings generated.", styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        return
        
    # Deduplicate based on technique_id
    seen = set()
    uniq_mitre = []
    for m in mitre_items:
        if m[1] not in seen:
            seen.add(m[1])
            uniq_mitre.append(m)
            
    t_data = [["Tactic", "ID", "Technique", "Affected Asset"]] + uniq_mitre
    
    t = Table(t_data, colWidths=[1.5*inch, 1*inch, 3*inch, 1.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t)
    elements.append(PageBreak())

def _create_attack_surface(elements, styles, findings: List[Dict], scan_type: str):
    elements.append(Paragraph("6. Attack Surface Summary", styles['SectionHeading']))
    elements.append(Spacer(1, 0.1*inch))

    if not findings:
        elements.append(Paragraph("No attack surface data available.", styles['Normal']))
        return

    # Calculate statistics
    critical_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "HIGH")
    medium_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "MEDIUM")
    low_count = sum(1 for f in findings if str(f.get("risk", "")).upper() == "LOW")

    if scan_type == "port_scan":
        # Port scan stats
        open_ports = [f.get("port") for f in findings if f.get("port")]
        services = list(set([f.get("service", "Unknown") for f in findings if f.get("service")]))

        elements.append(Paragraph(f"<b>Total Open Ports:</b> {len(open_ports)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Services Detected:</b> {', '.join(services[:10])}", styles['Normal']))

        # Top critical ports
        critical_findings = [f for f in findings if str(f.get("risk", "")).upper() in ["CRITICAL", "HIGH"]]
        if critical_findings:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph("<b>Critical Exposed Services:</b>", styles['Normal']))
            for cf in critical_findings[:5]:
                port = cf.get("port", "N/A")
                service = cf.get("service", "Unknown")
                issue = cf.get("issue", "")
                elements.append(Paragraph(f"&bull; Port {port} ({service}): {issue[:60]}...", styles['Normal']))
    else:
        # OS inspection stats
        elements.append(Paragraph(f"<b>Total Checks Performed:</b> {len(findings)}", styles['Normal']))

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
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph("<b>High-Risk Categories:</b>", styles['Normal']))
            for cat, items in list(categories.items())[:5]:
                elements.append(Paragraph(f"&bull; {cat}: {len(items)} high-risk findings", styles['Normal']))

    # Severity breakdown box
    elements.append(Spacer(1, 0.2*inch))
    severity_data = [
        ["Severity", "Count"],
        ["Critical", str(critical_count)],
        ["High", str(high_count)],
        ["Medium", str(medium_count)],
        ["Low", str(low_count)]
    ]

    t = Table(severity_data, colWidths=[3*inch, 2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), EnterpriseTheme.SECONDARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t)
    elements.append(PageBreak())


def _create_remediation(elements, styles):
    elements.append(Paragraph("7. Remediation Roadmap & Compliance", styles['SectionHeading']))
    elements.append(Spacer(1, 0.2*inch))
    
    items = [
        "<b>Phase 1 (0-7 Days):</b> Patch critical CVEs and isolate high-risk exposed management ports (e.g., RDP, SMB).",
        "<b>Phase 2 (14-30 Days):</b> Enforce strict password policies, disable legacy protocols (NetBIOS/Telnet), and enable endpoint protection.",
        "<b>Phase 3 (Ongoing):</b> Implement continuous network monitoring, zero-trust segmentation, and regular vulnerability scanning."
    ]
    
    list_items = [ListItem(Paragraph(item, styles['Normal']), leftIndent=15) for item in items]
    elements.append(ListFlowable(list_items, bulletType='bullet'))
    
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph("<b>Compliance Summary:</b> Addressing the issues identified in this report will improve alignment with NIST CSF, CIS Controls, and general enterprise security baselines.", styles['Normal']))

def _create_technical_appendix(elements, styles, findings: List[Dict], scan_type: str):
    elements.append(Paragraph("8. Technical Appendix", styles['SectionHeading']))
    elements.append(Paragraph("Raw technical details for security analysts.", styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))

    if not findings:
        elements.append(Paragraph("No technical data available.", styles['Normal']))
        return

    # Commands executed (for OS inspection)
    if scan_type != "port_scan":
        elements.append(Paragraph("<b>Inspection Commands Executed:</b>", styles['SubSectionHeading']))
        commands_seen = set()
        for item in findings:
            cmd_info = item.get("command", {})
            if isinstance(cmd_info, dict):
                cmd = cmd_info.get("executed", "")
                if cmd and cmd not in commands_seen:
                    commands_seen.add(cmd)
                    elements.append(Paragraph(f"<code>{cmd[:100]}</code>", styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))

    # Raw output samples
    elements.append(Paragraph("<b>Sample Raw Outputs:</b>", styles['SubSectionHeading']))
    for item in findings[:3]:  # Show first 3
        if not isinstance(item, dict):
            continue
        category = item.get("category", item.get("port", "Unknown"))
        elements.append(Paragraph(f"<i>{category}:</i>", styles['Normal']))

        cmd_info = item.get("command", {})
        if isinstance(cmd_info, dict):
            output = cmd_info.get("raw_output", "")
            if output:
                # Truncate and clean output for PDF
                clean_output = str(output)[:300].replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Paragraph(f"<font size='8'>{clean_output}...</font>", styles['Normal']))

        elements.append(Spacer(1, 0.1*inch))

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

    _safe_add_style(styles, ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=EnterpriseTheme.PRIMARY,
        spaceAfter=12,
        fontName='Helvetica-Bold'
    ))
    _safe_add_style(styles, ParagraphStyle(
        'SubSectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=EnterpriseTheme.SECONDARY,
        spaceAfter=10
    ))

    elements = []

    _create_cover_page(elements, styles, normalized)
    _create_executive_summary(elements, styles, summary, scan_type)
    _create_heatmap(elements, styles, summary, scan_type)
    _create_detailed_findings(elements, styles, findings, scan_type)
    _create_cve_table(elements, styles, findings)
    _create_mitre_mapping(elements, styles, findings)
    _create_attack_surface(elements, styles, findings, scan_type)
    _create_remediation(elements, styles)
    _create_technical_appendix(elements, styles, findings, scan_type)

    # Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph("<font color='grey'><i>Report auto-generated by Enterprise Security Platform. Confidential.</i></font>", ParagraphStyle('Footer', alignment=TA_CENTER)))

    doc.build(elements)
    print(f"[PDF] Report saved to: {filepath}")
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

            finding_dict = {
                "port": f.port,
                "service": f.service,
                "state": f.state,
                "category": f.category,
                "issue": f.issue or raw_data.get("issue") or raw_data.get("analysis", {}).get("summary"),
                "risk": f.risk_level or "LOW",
                "note": f.note or raw_data.get("note") or raw_data.get("analysis", {}).get("logic"),
                "cves": json.loads(f.cves_json) if f.cves_json else [],
                "mitre_attack": raw_data.get("mitre_attack", {})
            }
            findings.append(finding_dict)

    except Exception as e:
        print(f"[PDF] Database query failed: {e}")
        traceback.print_exc()
        # Fallback to result.data if DB query fails
        findings = result.get("data", [])
        print(f"[PDF] Fallback to result.data: {len(findings)} findings")

    return findings
