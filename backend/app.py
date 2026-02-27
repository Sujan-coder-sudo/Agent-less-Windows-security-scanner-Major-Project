"""
Backend API for Agentless Windows Security Scanner Dashboard
Production-grade Flask application with secure subprocess execution.
"""

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from datetime import datetime
import logging
import os
import sys
import json
import csv
import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.scanner_service import ScannerService
from utils.validators import validate_ip_address
from utils.exceptions import ValidationError, ExecutionError, FileReadError

# Configure logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/api.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Flask-CORS configuration
# Accept both Live Server origins (127.0.0.1:5500 and localhost:5500)
CORS(
    app,
    resources={r"/api/*": {"origins": [
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5000",
        "http://localhost:5000",
    ]}},
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
    expose_headers=["Content-Disposition"],
)


@app.after_request
def _cors_credentials_safety_net(response):
    ALLOWED_ORIGINS = {
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5000",
        "http://localhost:5000",
    }
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'
        # Preflight OPTIONS — must echo back allow-headers & allow-methods
        if request.method == 'OPTIONS':
            response.headers['Access-Control-Allow-Headers'] = (
                'Content-Type, Authorization, Accept'
            )
            response.headers['Access-Control-Allow-Methods'] = (
                'GET, POST, PUT, DELETE, OPTIONS'
            )
            response.headers['Access-Control-Max-Age'] = '3600'
    return response


@app.route('/api/ping', methods=['GET'])
def ping():
    """Simple connectivity test — no auth required."""
    return jsonify({'status': 'ok', 'message': 'Backend is reachable', 'timestamp': datetime.utcnow().isoformat() + 'Z'})


@app.route('/api/routes', methods=['GET'])
def list_routes():
    routes = sorted({rule.rule for rule in app.url_map.iter_rules() if rule.rule.startswith('/api/')})
    return jsonify(
        _create_api_response(
            status="success",
            authenticated=check_auth_status(),
            data={"routes": routes},
            message="Routes listed",
        )
    ), 200

# Path to scan history database
SCAN_HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'scan_history.json')
AUTH_STATUS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'auth_status.json')

# Ensure data directory exists
os.makedirs(os.path.dirname(SCAN_HISTORY_FILE), exist_ok=True)

# Initialize scanner service
scanner_service = ScannerService()


def load_scan_history():
    """Load scan history from persistent storage."""
    if os.path.exists(SCAN_HISTORY_FILE):
        try:
            with open(SCAN_HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load scan history: {e}")
    return []


def save_scan_history(history):
    """Save scan history to persistent storage."""
    try:
        with open(SCAN_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save scan history: {e}")


def add_scan_to_history(phase, target, status, data=None):
    """Add a new scan entry to history."""
    history = load_scan_history()
    scan_entry = {
        "id": len(history) + 1,
        "phase": phase,
        "target": target,
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "data_summary": _extract_summary(data) if data else None
    }
    history.insert(0, scan_entry)
    save_scan_history(history)
    return scan_entry


def _extract_summary(data):
    """Extract summary from scan data for history storage."""
    if not data:
        return None
    summary = {}
    if 'summary' in data:
        summary.update(data['summary'])
    if 'scan_info' in data:
        summary['scan_info'] = data['scan_info']
    return summary


def check_auth_status():
    """Check if user is currently authenticated."""
    if os.path.exists(AUTH_STATUS_FILE):
        try:
            with open(AUTH_STATUS_FILE, 'r') as f:
                status = json.load(f)
                # Check if auth is still valid (e.g., within last 30 minutes)
                if 'timestamp' in status:
                    auth_time = datetime.fromisoformat(status['timestamp'].replace('Z', '+00:00'))
                    elapsed = (datetime.utcnow() - auth_time.replace(tzinfo=None)).total_seconds()
                    if elapsed < 1800:  # 30 minutes
                        return status.get('authenticated', False)
        except Exception as e:
            logger.error(f"Failed to check auth status: {e}")
    return False


def set_auth_status(authenticated):
    """Set authentication status."""
    try:
        with open(AUTH_STATUS_FILE, 'w') as f:
            json.dump({
                'authenticated': authenticated,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }, f)
    except Exception as e:
        logger.error(f"Failed to set auth status: {e}")


def _create_api_response(*, status: str, authenticated: bool | None = None, data=None, message: str | None = None):
    response = {
        "status": status,
        "authenticated": authenticated,
        "data": data,
        "message": message,
    }
    return response


def _run_coroutine(coro):
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _windows_hello_verify_async(prompt: str) -> bool:
    from winrt.windows.security.credentials.ui import (
        UserConsentVerifier,
        UserConsentVerificationResult,
    )

    result = await UserConsentVerifier.request_verification_async(prompt)
    return result == UserConsentVerificationResult.VERIFIED


def create_response(status="success", message=None, data=None, errors=None):
    """
    Create a standardized API response.
    
    Args:
        status: 'success' or 'error'
        message: Human-readable message
        data: Response payload
        errors: List of error details
    
    Returns:
        JSON response with consistent structure
    """
    response = {
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": message or ("Operation completed successfully" if status == "success" else "An error occurred"),
    }
    if data is not None:
        response["data"] = data
    if errors is not None:
        response["errors"] = errors
    return jsonify(response)


@app.route('/api/auth/status', methods=['GET'])
def get_auth_status():
    """Get current authentication status."""
    is_authenticated = check_auth_status()
    return jsonify(
        _create_api_response(
            status="success",
            authenticated=is_authenticated,
            data={},
            message="Auth status retrieved",
        )
    ), 200


@app.route('/api/auth/verify', methods=['POST'])
def verify_auth():
    """Trigger Windows Hello authentication (Face/Fingerprint/PIN)."""
    try:
        verified = _run_coroutine(
            _windows_hello_verify_async(
                "Authenticate to start the vulnerability scan"
            )
        )
        set_auth_status(bool(verified))

        if verified:
            return jsonify(
                _create_api_response(
                    status="success",
                    authenticated=True,
                    data={},
                    message="Authentication verified",
                )
            ), 200

        return jsonify(
            _create_api_response(
                status="failed",
                authenticated=False,
                data={},
                message="Authentication denied or cancelled",
            )
        ), 401

    except Exception as e:
        logger.exception("Windows Hello authentication error")
        set_auth_status(False)
        return jsonify(
            _create_api_response(
                status="error",
                authenticated=False,
                data={},
                message=str(e),
            )
        ), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Clear authentication status."""
    set_auth_status(False)
    return create_response(
        status="success",
        message="Logged out successfully",
        data={"authenticated": False}
    )


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return create_response(
        status="success",
        message="API is operational",
        data={
            "service": "Agentless Scanner API",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


@app.route('/api/phase2/run', methods=['POST'])
def run_phase2_scan():
    """
    Execute Phase 2 Network Exposure Scan.
    Requires authentication.
    """
    try:
        # Check authentication
        if not check_auth_status():
            return jsonify(
                _create_api_response(
                    status="failed",
                    authenticated=False,
                    data={},
                    message="Authentication required",
                )
            ), 401
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        target = data.get('target', '').strip()
        if not target:
            raise ValidationError("Target IP address is required")
        
        # Validate IP address format
        validate_ip_address(target)
        
        logger.info(f"Starting Phase 2 scan for target: {target}")
        
        # Execute scan
        result = scanner_service.run_phase2_scan(target)
        
        # Add to history
        add_scan_to_history("Phase 2", target, "Success", result)
        
        logger.info(f"Phase 2 scan completed for {target}")
        
        return create_response(
            status="success",
            message="Phase 2 scan completed successfully",
            data=result
        )
        
    except ValidationError as e:
        logger.warning(f"Validation error in Phase 2 scan: {str(e)}")
        add_scan_to_history("Phase 2", target if 'target' in locals() else "unknown", "Failed", None)
        return create_response(
            status="error",
            message="Validation failed",
            errors=[{"field": "target", "message": str(e)}]
        ), 400
        
    except ExecutionError as e:
        logger.error(f"Execution error in Phase 2 scan: {str(e)}")
        add_scan_to_history("Phase 2", target if 'target' in locals() else "unknown", "Failed", None)
        return create_response(
            status="error",
            message="Scan execution failed",
            errors=[{"type": "execution", "message": str(e)}]
        ), 500
        
    except FileReadError as e:
        logger.error(f"File read error in Phase 2 scan: {str(e)}")
        add_scan_to_history("Phase 2", target if 'target' in locals() else "unknown", "Failed", None)
        return create_response(
            status="error",
            message="Failed to read scan results",
            errors=[{"type": "file_read", "message": str(e)}]
        ), 500
        
    except Exception as e:
        logger.exception(f"Unexpected error in Phase 2 scan: {str(e)}")
        add_scan_to_history("Phase 2", target if 'target' in locals() else "unknown", "Error", None)
        return create_response(
            status="error",
            message="An unexpected error occurred",
            errors=[{"type": "internal", "message": "Internal server error"}]
        ), 500


@app.route('/api/phase3/run', methods=['POST'])
def run_phase3_scan():
    """
    Execute Phase 3 System Vulnerability Scan.
    Requires authentication.
    """
    try:
        # Check authentication
        if not check_auth_status():
            return jsonify(
                _create_api_response(
                    status="failed",
                    authenticated=False,
                    data={},
                    message="Authentication required",
                )
            ), 401
        
        logger.info("Starting Phase 3 scan")
        
        # Execute scan
        result = scanner_service.run_phase3_scan()
        
        # Add to history
        add_scan_to_history("Phase 3", "localhost", "Success", result)
        
        logger.info("Phase 3 scan completed")
        
        return create_response(
            status="success",
            message="Phase 3 scan completed successfully",
            data=result
        )
        
    except ExecutionError as e:
        logger.error(f"Execution error in Phase 3 scan: {str(e)}")
        add_scan_to_history("Phase 3", "localhost", "Failed", None)
        return create_response(
            status="error",
            message="Scan execution failed",
            errors=[{"type": "execution", "message": str(e)}]
        ), 500
        
    except FileReadError as e:
        logger.error(f"File read error in Phase 3 scan: {str(e)}")
        add_scan_to_history("Phase 3", "localhost", "Failed", None)
        return create_response(
            status="error",
            message="Failed to read scan results",
            errors=[{"type": "file_read", "message": str(e)}]
        ), 500
        
    except Exception as e:
        logger.exception(f"Unexpected error in Phase 3 scan: {str(e)}")
        add_scan_to_history("Phase 3", "localhost", "Error", None)
        return create_response(
            status="error",
            message="An unexpected error occurred",
            errors=[{"type": "internal", "message": "Internal server error"}]
        ), 500


@app.route('/api/overview', methods=['GET'])
def get_overview():
    """
    Get dashboard overview metrics from latest scan results.
    
    Returns:
        Aggregated metrics from Phase 2 and Phase 3 scans
    """
    try:
        overview = scanner_service.get_overview_metrics()
        
        return jsonify(
            _create_api_response(
                status="success",
                authenticated=check_auth_status(),
                data=overview,
                message="Overview loaded successfully",
            )
        ), 200
        
    except Exception as e:
        logger.exception("Error retrieving overview")
        empty = {
            "totalHosts": 0,
            "openPorts": 0,
            "highRiskServices": 0,
            "missingHotfixes": 0,
            "lastScan": None,
            "vulnData": [],
            "recentHosts": [],
        }
        return jsonify(
            _create_api_response(
                status="success",
                authenticated=check_auth_status(),
                data=empty,
                message="No scan data available",
            )
        ), 200


@app.route('/api/scans', methods=['GET'])
def get_scan_history():
    """
    Get persistent scan history for both Phase 2 and Phase 3.
    """
    try:
        history = load_scan_history()
        
        return create_response(
            status="success",
            message="Scan history retrieved",
            data=history
        )
        
    except Exception as e:
        logger.exception(f"Error retrieving scan history: {str(e)}")
        return create_response(
            status="success",
            message="No scan history available",
            data=[]
        )


@app.route('/api/export/<format>/<int:scan_id>', methods=['GET'])
def export_scan(format, scan_id):
    """
    Export scan results in specified format.
    
    Args:
        format: 'json', 'csv', or 'pdf'
        scan_id: ID of the scan to export
    """
    try:
        # Load scan history
        history = load_scan_history()
        scan = next((s for s in history if s['id'] == scan_id), None)
        
        if not scan:
            return create_response(
                status="error",
                message="Scan not found",
                errors=[{"type": "not_found", "message": f"Scan {scan_id} does not exist"}]
            ), 404
        
        if format == 'json':
            return _export_json(scan)
        elif format == 'csv':
            return _export_csv(scan)
        elif format == 'pdf':
            return _export_pdf(scan)
        else:
            return create_response(
                status="error",
                message="Invalid export format",
                errors=[{"type": "validation", "message": "Supported formats: json, csv, pdf"}]
            ), 400
            
    except Exception as e:
        logger.exception(f"Export error: {e}")
        return create_response(
            status="error",
            message="Export failed",
            errors=[{"type": "export", "message": str(e)}]
        ), 500


def _export_json(scan):
    """Export scan as JSON file."""
    output = io.BytesIO()
    output.write(json.dumps(scan, indent=2, default=str).encode('utf-8'))
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/json',
        as_attachment=True,
        download_name=f"scan_{scan['id']}_{scan['phase'].lower().replace(' ', '_')}.json"
    )


def _export_csv(scan):
    """Export scan as CSV file."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Phase', 'Target', 'Status', 'Timestamp'])
    
    # Write scan data
    writer.writerow([
        scan['id'],
        scan['phase'],
        scan['target'],
        scan['status'],
        scan['timestamp']
    ])
    
    # Write summary if available
    if scan.get('data_summary'):
        writer.writerow([])
        writer.writerow(['Summary'])
        for key, value in scan['data_summary'].items():
            if key != 'scan_info':
                writer.writerow([key, value])
    
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"scan_{scan['id']}_{scan['phase'].lower().replace(' ', '_')}.csv"
    )


def _export_pdf(scan):
    """Export scan as PDF file."""
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#2c3e50')
    )
    
    # Title
    elements.append(Paragraph(f"Scan Report - {scan['phase']}", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Scan details table
    data = [
        ['Field', 'Value'],
        ['Scan ID', str(scan['id'])],
        ['Phase', scan['phase']],
        ['Target', scan['target']],
        ['Status', scan['status']],
        ['Timestamp', scan['timestamp']]
    ]
    
    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Summary section
    if scan.get('data_summary'):
        elements.append(Paragraph("Summary", styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        summary_data = [['Metric', 'Value']]
        for key, value in scan['data_summary'].items():
            if isinstance(value, (str, int, float, bool)):
                summary_data.append([key.replace('_', ' ').title(), str(value)])
        
        if len(summary_data) > 1:
            summary_table = Table(summary_data, colWidths=[2.5*inch, 3.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            elements.append(summary_table)
    
    # Build PDF
    doc.build(elements)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"scan_{scan['id']}_{scan['phase'].lower().replace(' ', '_')}.pdf"
    )


@app.route('/api/export/all/<format>', methods=['GET'])
def export_all_scans(format):
    """
    Export all scan history in specified format.
    """
    try:
        history = load_scan_history()
        
        if format == 'json':
            output = io.BytesIO()
            output.write(json.dumps(history, indent=2, default=str).encode('utf-8'))
            output.seek(0)
            return send_file(
                output,
                mimetype='application/json',
                as_attachment=True,
                download_name=f"all_scans_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
        elif format == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Phase', 'Target', 'Status', 'Timestamp'])
            for scan in history:
                writer.writerow([
                    scan['id'],
                    scan['phase'],
                    scan['target'],
                    scan['status'],
                    scan['timestamp']
                ])
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f"all_scans_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
        else:
            return create_response(
                status="error",
                message="Invalid format for bulk export",
                errors=[{"type": "validation", "message": "Bulk export supports: json, csv"}]
            ), 400
            
    except Exception as e:
        logger.exception(f"Bulk export error: {e}")
        return create_response(
            status="error",
            message="Export failed",
            errors=[{"type": "export", "message": str(e)}]
        ), 500


@app.route('/api/scans/clear', methods=['POST'])
def clear_scan_history():
    """Clear all scan history."""
    try:
        save_scan_history([])
        return create_response(
            status="success",
            message="Scan history cleared"
        )
    except Exception as e:
        logger.error(f"Failed to clear history: {e}")
        return create_response(
            status="error",
            message="Failed to clear history",
            errors=[{"type": "clear", "message": str(e)}]
        ), 500


# ─────────────────────────────────────────────────────────────
# NEW SPEC ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.route('/api/scan/phase2', methods=['POST'])
def new_run_phase2_scan():
    """
    POST /api/scan/phase2
    Body: { "target": "<ip>" }
    Execute Phase 2 network exposure scan and return structured JSON.
    """
    target = 'unknown'
    try:
        body = request.get_json(silent=True) or {}
        target = (body.get('target') or '').strip()

        if not target:
            return create_response(
                status='error',
                message='target IP address is required',
                errors=[{'field': 'target', 'message': 'target is required'}]
            ), 400

        # Basic IP / CIDR validation
        validate_ip_address(target)

        logger.info(f'[/api/scan/phase2] Starting scan for: {target}')
        result = scanner_service.run_phase2_scan(target)

        scan_record = add_scan_to_history('Phase 2', target, 'Success', result)

        return create_response(
            status='success',
            message='Phase 2 scan completed successfully',
            data={
                'scan_id': scan_record['id'],
                'phase': 2,
                'target': target,
                'timestamp': scan_record['timestamp'],
                'status': 'Success',
                'result': result
            }
        )

    except ValidationError as e:
        add_scan_to_history('Phase 2', target, 'Failed', None)
        return create_response(
            status='error',
            message='Validation failed',
            errors=[{'field': 'target', 'message': str(e)}]
        ), 400

    except (ExecutionError, FileReadError) as e:
        add_scan_to_history('Phase 2', target, 'Failed', None)
        logger.error(f'[/api/scan/phase2] {e}')
        return create_response(
            status='error',
            message=str(e),
            errors=[{'type': 'execution', 'message': str(e)}]
        ), 500

    except Exception as e:
        add_scan_to_history('Phase 2', target, 'Error', None)
        logger.exception(f'[/api/scan/phase2] Unexpected error: {e}')
        return create_response(
            status='error',
            message='An unexpected error occurred',
            errors=[{'type': 'internal', 'message': 'Internal server error'}]
        ), 500


@app.route('/api/scan/phase3', methods=['POST'])
def new_run_phase3_scan():
    """
    POST /api/scan/phase3
    Execute Phase 3 system vulnerability scan and return structured JSON.
    """
    try:
        logger.info('[/api/scan/phase3] Starting scan')
        result = scanner_service.run_phase3_scan()

        scan_record = add_scan_to_history('Phase 3', 'localhost', 'Success', result)

        return create_response(
            status='success',
            message='Phase 3 scan completed successfully',
            data={
                'scan_id': scan_record['id'],
                'phase': 3,
                'target': 'localhost',
                'timestamp': scan_record['timestamp'],
                'status': 'Success',
                'result': result
            }
        )

    except (ExecutionError, FileReadError) as e:
        add_scan_to_history('Phase 3', 'localhost', 'Failed', None)
        logger.error(f'[/api/scan/phase3] {e}')
        return create_response(
            status='error',
            message=str(e),
            errors=[{'type': 'execution', 'message': str(e)}]
        ), 500

    except Exception as e:
        add_scan_to_history('Phase 3', 'localhost', 'Error', None)
        logger.exception(f'[/api/scan/phase3] Unexpected error: {e}')
        return create_response(
            status='error',
            message='An unexpected error occurred',
            errors=[{'type': 'internal', 'message': 'Internal server error'}]
        ), 500


@app.route('/api/history', methods=['GET'])
def get_history_list():
    """
    GET /api/history
    Returns list of all scan metadata records.
    """
    try:
        history = load_scan_history()
        payload = [
            {
                'scan_id': s.get('id'),
                'phase': s.get('phase'),
                'target': s.get('target'),
                'timestamp': s.get('timestamp'),
                'status': s.get('status')
            }
            for s in history
        ]
        return create_response(
            status='success',
            message='History retrieved',
            data=payload
        )
    except Exception as e:
        logger.exception(f'[/api/history] {e}')
        return create_response(
            status='success',
            message='No history available',
            data=[]
        )


@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_history_detail(scan_id):
    """
    GET /api/history/<scan_id>
    Returns full scan record including data_summary.
    """
    try:
        history = load_scan_history()
        record = next((s for s in history if s.get('id') == scan_id), None)
        if not record:
            return create_response(
                status='error',
                message=f'Scan {scan_id} not found',
                errors=[{'type': 'not_found', 'message': f'No scan with id {scan_id}'}]
            ), 404
        return create_response(
            status='success',
            message='Scan record retrieved',
            data=record
        )
    except Exception as e:
        logger.exception(f'[/api/history/{scan_id}] {e}')
        return create_response(
            status='error',
            message='Failed to retrieve scan record',
            errors=[{'type': 'internal', 'message': str(e)}]
        ), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return create_response(
        status="error",
        message="Endpoint not found",
        errors=[{"type": "not_found", "message": "The requested resource does not exist"}]
    ), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return create_response(
        status="error",
        message="Method not allowed",
        errors=[{"type": "method_not_allowed", "message": "The HTTP method is not supported for this endpoint"}]
    ), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.exception("Internal server error")
    return create_response(
        status="error",
        message="Internal server error",
        errors=[{"type": "internal", "message": "An unexpected error occurred"}]
    ), 500


if __name__ == '__main__':
    # Production: use proper WSGI server
    # Development: use Flask's built-in server
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    
    logger.info(f"Starting Agentless Scanner API on port {port}")
    try:
        api_routes = sorted({rule.rule for rule in app.url_map.iter_rules() if rule.rule.startswith('/api/')})
        logger.info("Registered /api routes: %s", api_routes)
        logger.info("CORS: origins=%s supports_credentials=%s", ["http://127.0.0.1:5500"], True)
    except Exception:
        logger.exception("Failed to log startup diagnostics")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
