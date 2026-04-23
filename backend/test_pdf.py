import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from services.pdf_service import generate_pdf

payload = {
    'scan_id': 'test_id_from_python_test',
    'scan_type': 'port_scan',
    'target': '192.168.1.100',
    'timestamp': '2026-04-23T12:00:00Z',
    'result': {
        'summary': {
            'total_findings': 15,
            'open_ports': 4,
            'risk_score': 8.2,
            'risk_distribution': {'Critical': 1, 'High': 2, 'Medium': 8, 'Low': 4}
        },
        'data': [
            {'port': 80, 'service': 'http', 'issue': 'Cleartext transport', 'risk': 'Medium', 'state': 'open'},
            {'port': 445, 'service': 'smb', 'issue': 'SMB exposed to internet', 'risk': 'Critical', 'state': 'open'}
        ]
    }
}

print(f"Generated PDF at: {generate_pdf(payload)}")
