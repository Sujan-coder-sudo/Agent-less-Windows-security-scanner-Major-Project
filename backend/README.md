# Agentless Windows Security Scanner - Backend API

Production-grade Flask backend for the Agentless Windows Security Scanner Dashboard.

## Features

- **Secure subprocess execution** without shell injection
- **IP address validation** with regex and ipaddress module
- **Timeout handling** for long-running scans
- **Comprehensive error handling** with structured responses
- **CORS enabled** for frontend communication
- **Structured logging** to console and file

## Architecture

```
backend/
├── app.py                     # Main Flask application
├── requirements.txt           # Python dependencies
├── services/
│   └── scanner_service.py    # Business logic layer
└── utils/
    ├── exceptions.py         # Custom exceptions
    ├── validators.py         # Input validation
    ├── execution.py          # Subprocess execution manager
    └── json_parser.py        # JSON parsing and normalization
```

## API Endpoints

### Health Check
```
GET /api/health
```

### Phase 2 - Network Exposure Scan
```
POST /api/phase2/run
Body: { "target": "192.168.1.0/24" }
```

### Phase 3 - System Vulnerability Scan
```
POST /api/phase3/run
Body: {}
```

### Dashboard Overview
```
GET /api/overview
```

### Scan History
```
GET /api/scans
```

## Installation

1. Install dependencies:
```bash
cd backend
pip install -r requirements.txt
```

2. Run the server:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## Security Features

- **No shell execution**: All subprocess calls use `shell=False`
- **Input validation**: IP addresses validated with regex and ipaddress module
- **Path traversal protection**: Script paths validated to be within allowed directories
- **Command injection prevention**: Dangerous characters blocked in input validation
- **Timeout handling**: Prevents indefinite hanging on subprocess calls

## Response Format

All API responses follow a consistent structure:

```json
{
  "status": "success|error",
  "timestamp": "2024-01-01T00:00:00Z",
  "message": "Operation completed successfully",
  "data": { ... },
  "errors": [ ... ]
}
```

## Environment Variables

- `FLASK_DEBUG`: Set to `true` for debug mode (default: false)
- `PORT`: Server port (default: 5000)
- `NVD_API_KEY`: Optional NVD API key for Phase 3 CVE lookups
