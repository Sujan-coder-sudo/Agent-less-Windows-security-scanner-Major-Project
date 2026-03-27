"""
pdf_service.py
Professional PDF report generation for security scans.
Supports both Port Scan and OS Inspection with clean, readable formatting.
"""

import os
from datetime import datetime
from typing import Dict, Any, List

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib import colors
from reportlab.lib.units import inch

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "backend", "data", "exports")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _get_risk_level(score: float) -> str:
    """Convert numeric risk score to human-readable level."""
    if score >= 7.5:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _get_risk_color(level: str) -> colors.Color:
    """Get color for risk level."""
    color_map = {
        "CRITICAL": colors.HexColor("#DC2626"),
        "HIGH": colors.HexColor("#EA580C"),
        "MEDIUM": colors.HexColor("#CA8A04"),
        "LOW": colors.HexColor("#16A34A"),
    }
    return color_map.get(level.upper(), colors.grey)


def _format_timestamp(ts: str) -> str:
    """Format ISO timestamp to readable date."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y at %I:%M %p")
    except:
        return ts


def _generate_recommendations_port_scan(findings: List[Dict]) -> List[str]:
    """Generate human-readable recommendations for port scan."""
    recs = []
    
    high_risk_ports = [f for f in findings if isinstance(f, dict) and f.get("risk") == "High"]
    open_ports = [f for f in findings if isinstance(f, dict) and f.get("state") == "open"]
    
    if high_risk_ports:
        services = ", ".join(set(f.get("service", "Unknown") for f in high_risk_ports[:3]))
        recs.append(f"• Review high-risk services: {services}. Consider restricting access or disabling if not required.")
    
    if len(open_ports) > 5:
        recs.append(f"• System has {len(open_ports)} open ports. Close unused ports to reduce attack surface.")
    
    risky_services = [f for f in findings if isinstance(f, dict) and 
                      f.get("service") in ["telnet", "ftp", "msrpc", "netbios"]]
    if risky_services:
        recs.append("• Legacy services detected (Telnet, FTP, NetBIOS). These are commonly targeted—migrate to secure alternatives.")
    
    rdp_findings = [f for f in findings if isinstance(f, dict) and f.get("service") == "ms-wbt-server"]
    if rdp_findings:
        recs.append("• Remote Desktop (RDP) is exposed. Ensure strong authentication and network-level protection (VPN/firewall rules).")
    
    if not recs:
        recs.append("• Regularly review open ports and services to maintain security posture.")
    
    return recs


def _generate_recommendations_os_inspection(findings: List[Dict]) -> List[str]:
    """Generate human-readable recommendations for OS inspection."""
    recs = []
    
    critical_high = [f for f in findings if isinstance(f, dict) and 
                     f.get("risk") in ["CRITICAL", "HIGH"]]
    
    failed_checks = [f for f in findings if isinstance(f, dict) and 
                     f.get("status") == "failed"]
    
    if critical_high:
        cats = ", ".join(set(f.get("category", "Unknown") for f in critical_high[:3]))
        recs.append(f"• Address critical/high risk issues in: {cats}. These pose immediate security concerns.")
    
    if failed_checks:
        recs.append(f"• {len(failed_checks)} security checks failed. Investigate and remediate these configuration issues.")
    
    edr_issues = [f for f in findings if isinstance(f, dict) and 
                  "EDR" in f.get("category", "") and f.get("status") == "failed"]
    if edr_issues:
        recs.append("• EDR/AV health check failed. Ensure endpoint protection is active and up-to-date.")
    
    firewall_issues = [f for f in findings if isinstance(f, dict) and 
                       "Firewall" in f.get("category", "")]
    if any(f.get("findings", {}).get("exposed_ports") for f in firewall_issues):
        recs.append("• Review firewall rules—unnecessary ports are exposed to the network.")
    
    if not recs:
        recs.append("• Continue regular security audits and keep systems patched.")
    
    return recs


def _create_header_elements(styles, scan_data: Dict) -> List:
    """Create the header section of the PDF."""
    elements = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6,
        alignment=TA_CENTER
    )
    elements.append(Paragraph("Security Scan Report", title_style))
    elements.append(Spacer(1, 0.1*inch))
    
    # Subtitle with scan type
    scan_type = scan_data.get("scan_type", "Unknown")
    scan_label = "Port Scan Analysis" if scan_type == "port_scan" else "OS Security Inspection"
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER
    )
    elements.append(Paragraph(scan_label, subtitle_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Metadata box
    target = scan_data.get("target", "Unknown")
    timestamp = _format_timestamp(scan_data.get("timestamp", "Unknown"))
    scan_id = scan_data.get("scan_id", "Unknown")[:8]
    
    meta_data = [
        ["Target System:", target],
        ["Scan Date:", timestamp],
        ["Report ID:", f"SCAN-{scan_id.upper()}"],
    ]
    
    meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#334155")),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(meta_table)
    elements.append(Spacer(1, 0.4*inch))
    
    return elements


def _create_executive_summary_port_scan(elements, styles, result: Dict):
    """Create executive summary for port scan."""
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    summary = result.get("summary", {})
    total = summary.get("total_findings", 0)
    open_ports = summary.get("open_ports", 0)
    risk_score = summary.get("risk_score", 0.0)
    risk_level = _get_risk_level(risk_score)
    
    # Risk color
    risk_color = _get_risk_color(risk_level)
    
    # Build narrative
    if risk_level == "HIGH":
        narrative = f"""This system has <b>{open_ports} open ports</b> out of {total} total findings. 
        The overall risk score of <b>{risk_score}/10</b> indicates a <font color="{risk_color.hexval()}"><b>{risk_level}</b></font> risk level. 
        <b>Immediate attention is recommended</b> to address exposed services and reduce attack surface."""
    elif risk_level == "MEDIUM":
        narrative = f"""This system has <b>{open_ports} open ports</b> out of {total} total findings. 
        The overall risk score of <b>{risk_score}/10</b> indicates a <font color="{risk_color.hexval()}"><b>{risk_level}</b></font> risk level. 
        Some services expose potential attack surfaces that should be reviewed."""
    else:
        narrative = f"""This system has <b>{open_ports} open ports</b> out of {total} total findings. 
        The overall risk score of <b>{risk_score}/10</b> indicates a <font color="{risk_color.hexval()}"><b>{risk_level}</b></font> risk level. 
        The system appears to have a reasonable security posture, though regular reviews are recommended."""
    
    elements.append(Paragraph(narrative, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))


def _create_executive_summary_os_inspection(elements, styles, result: Dict):
    """Create executive summary for OS inspection."""
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    summary = result.get("summary", {})
    total = summary.get("total_checks", 0)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    failed = summary.get("failed", 0)
    
    # Determine overall risk
    if critical > 0 or high > 3:
        risk_level = "HIGH"
        narrative = f"""This system underwent <b>{total} security checks</b>. 
        <font color="#DC2626"><b>{critical} critical</b></font> and <b>{high} high-risk</b> vulnerabilities were identified, 
        along with <b>{failed} failed checks</b>. <b>Immediate remediation is strongly advised</b> to prevent potential compromise."""
    elif high > 0 or medium > 3:
        risk_level = "MEDIUM"
        narrative = f"""This system underwent <b>{total} security checks</b>. 
        <b>{high} high-risk</b> and <b>{medium} medium-risk</b> issues were found. 
        Addressing these concerns will improve the overall security posture."""
    else:
        risk_level = "LOW"
        narrative = f"""This system underwent <b>{total} security checks</b>. 
        Most checks passed with only <b>{medium} medium</b> and <b>{summary.get('low', 0)} low</b> risk findings. 
        The system demonstrates good security configuration overall."""
    
    elements.append(Paragraph(narrative, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))


def _create_risk_table_port_scan(elements, styles, result: Dict):
    """Create risk breakdown table for port scan."""
    elements.append(Paragraph("Risk Breakdown", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    summary = result.get("summary", {})
    dist = summary.get("risk_distribution", {})
    
    data = [
        ["Severity", "Count", "Indicator"],
        ["Critical", str(dist.get("Critical", 0)), "🔴"],
        ["High", str(dist.get("High", 0)), "🟠"],
        ["Medium", str(dist.get("Medium", 0)), "🟡"],
        ["Low", str(dist.get("Low", 0)), "🟢"],
    ]
    
    table = Table(data, colWidths=[2*inch, 1.5*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 1), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.3*inch))


def _create_risk_table_os_inspection(elements, styles, result: Dict):
    """Create risk breakdown table for OS inspection."""
    elements.append(Paragraph("Risk Breakdown", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    summary = result.get("summary", {})
    
    data = [
        ["Severity", "Count", "Status"],
        ["Critical", str(summary.get("critical", 0)), "Requires Immediate Action"],
        ["High", str(summary.get("high", 0)), "Should Address Soon"],
        ["Medium", str(summary.get("medium", 0)), "Review Recommended"],
        ["Low", str(summary.get("low", 0)), "Informational"],
        ["Failed Checks", str(summary.get("failed", 0)), "Needs Investigation"],
    ]
    
    table = Table(data, colWidths=[1.5*inch, 1*inch, 2.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (1, -1), 'CENTER'),
        ('ALIGN', (2, 0), (2, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 1), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.3*inch))


def _create_findings_port_scan(elements, styles, data: List[Dict]):
    """Create detailed findings section for port scan."""
    elements.append(Paragraph("Detailed Findings", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    for i, finding in enumerate(data, 1):
        if not isinstance(finding, dict):
            continue
            
        port = finding.get("port", "Unknown")
        service = finding.get("service", "Unknown")
        issue = finding.get("issue", "Unknown issue")
        risk = finding.get("risk", "Low")
        note = finding.get("note", "No additional information")
        state = finding.get("state", "unknown")
        cves = finding.get("cves", [])
        
        # Risk styling
        risk_color = _get_risk_color(risk)
        
        # Finding header
        finding_title = f"Finding #{i} — Port {port} ({service})"
        elements.append(Paragraph(finding_title, styles['Heading3']))
        
        # Status and risk badges
        status_text = f"""<b>Status:</b> {state.upper()} | <b>Risk Level:</b> <font color="{risk_color.hexval()}"><b>{risk.upper()}</b></font>"""
        elements.append(Paragraph(status_text, styles['Normal']))
        elements.append(Spacer(1, 0.05*inch))
        
        # Issue
        elements.append(Paragraph(f"<b>Issue Detected:</b> {issue}", styles['Normal']))
        elements.append(Spacer(1, 0.05*inch))
        
        # Note/Explanation
        elements.append(Paragraph(f"<b>Details:</b> {note}", styles['Normal']))
        
        # CVEs
        if cves:
            cve_text = ", ".join(str(c) for c in cves[:5])
            elements.append(Paragraph(f"<b>Referenced CVEs:</b> {cve_text}", styles['Normal']))
        
        elements.append(Spacer(1, 0.15*inch))


def _create_findings_os_inspection(elements, styles, data: List[Dict]):
    """Create detailed findings section for OS inspection."""
    elements.append(Paragraph("Detailed Findings", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    for i, finding in enumerate(data, 1):
        if not isinstance(finding, dict):
            continue
            
        category = finding.get("category", "Unknown")
        risk = finding.get("risk", "LOW")
        status = finding.get("status", "unknown")
        analysis = finding.get("analysis", {})
        summary = analysis.get("summary", "No summary available")
        logic = analysis.get("logic", "")
        nvd = finding.get("nvd", [])
        
        # Risk styling
        risk_color = _get_risk_color(risk)
        
        # Finding header
        elements.append(Paragraph(f"Finding #{i} — {category}", styles['Heading3']))
        
        # Status and risk
        status_text = f"""<b>Status:</b> {status.upper()} | <b>Risk Level:</b> <font color="{risk_color.hexval()}"><b>{risk.upper()}</b></font>"""
        elements.append(Paragraph(status_text, styles['Normal']))
        elements.append(Spacer(1, 0.05*inch))
        
        # Summary
        elements.append(Paragraph(f"<b>Finding:</b> {summary}", styles['Normal']))
        
        # Logic
        if logic:
            elements.append(Paragraph(f"<b>Assessment Logic:</b> {logic}", styles['Normal']))
        
        # NVD CVEs
        if nvd and isinstance(nvd, list):
            cves = [c for c in nvd if isinstance(c, dict) and c.get("cve_id")]
            if cves:
                elements.append(Spacer(1, 0.05*inch))
                elements.append(Paragraph("<b>Related CVEs:</b>", styles['Normal']))
                for cve in cves[:3]:
                    cve_id = cve.get("cve_id", "Unknown")
                    severity = cve.get("severity", "Unknown")
                    desc = cve.get("description", "")[:100] + "..." if len(cve.get("description", "")) > 100 else cve.get("description", "")
                    elements.append(Paragraph(f"  • <b>{cve_id}</b> ({severity}): {desc}", styles['Normal']))
        
        elements.append(Spacer(1, 0.15*inch))


def _create_recommendations(elements, styles, scan_type: str, data: List[Dict]):
    """Create recommendations section."""
    elements.append(Paragraph("Recommendations", styles['Heading2']))
    elements.append(Spacer(1, 0.1*inch))
    
    # Generate recommendations based on scan type
    if scan_type == "port_scan":
        recs = _generate_recommendations_port_scan(data)
    else:
        recs = _generate_recommendations_os_inspection(data)
    
    for rec in recs:
        elements.append(Paragraph(rec, styles['Normal']))
        elements.append(Spacer(1, 0.08*inch))
    
    # General recommendations
    elements.append(Spacer(1, 0.1*inch))
    elements.append(Paragraph("<b>General Best Practices:</b>", styles['Normal']))
    general = [
        "• Implement network segmentation to limit lateral movement",
        "• Enable comprehensive logging and monitoring",
        "• Apply security patches within 30 days of release",
        "• Conduct regular vulnerability assessments",
    ]
    for g in general:
        elements.append(Paragraph(g, styles['Normal']))
        elements.append(Spacer(1, 0.05*inch))


def generate_pdf(scan_data: Dict) -> str:
    """
    Generate a professional PDF report from scan data.
    
    Args:
        scan_data: Dictionary containing scan results in unified format
        
    Returns:
        Path to generated PDF file
    """
    scan_id = scan_data.get("scan_id", "unknown")
    scan_type = scan_data.get("scan_type", "unknown")
    
    # Generate filename
    safe_id = scan_id.replace(" ", "_").replace(":", "-")[:30]
    filename = f"Security_Report_{scan_type}_{safe_id}.pdf"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    # Create document
    doc = SimpleDocTemplate(
        filepath,
        pagesize=(8.5*inch, 11*inch),
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Build elements
    elements = []
    
    # Header
    elements.extend(_create_header_elements(styles, scan_data))
    
    # Get result data
    result = scan_data.get("result", {})
    data = result.get("data", [])
    
    # Executive Summary (different for each type)
    if scan_type == "port_scan":
        _create_executive_summary_port_scan(elements, styles, result)
        _create_risk_table_port_scan(elements, styles, result)
        _create_findings_port_scan(elements, styles, data)
    else:
        _create_executive_summary_os_inspection(elements, styles, result)
        _create_risk_table_os_inspection(elements, styles, result)
        _create_findings_os_inspection(elements, styles, data)
    
    # Recommendations
    _create_recommendations(elements, styles, scan_type, data)
    
    # Footer note
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph(
        "<i>This report was generated automatically by the Agentless Windows Security Scanner. "
        "For questions or support, consult your security team.</i>",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=colors.grey)
    ))
    
    # Build PDF
    doc.build(elements)
    
    return filepath
