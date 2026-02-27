"""
Minimal CORS test for Flask backend
"""
from flask import Flask, jsonify, request, make_response
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# CORS - applied to every response
@app.after_request
def after_request(response):
    """Add CORS headers to every response."""
    origin = request.headers.get('Origin', '*')
    
    logger.info(f"CORS: origin={origin}, path={request.path}, method={request.method}")
    
    # Must set specific origin when credentials are used
    if origin in ["http://127.0.0.1:5500", "http://localhost:5500", "http://localhost:5000"]:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = '*'
    
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    logger.info(f"CORS headers added: {dict(response.headers)}")
    
    return response


# Global OPTIONS handler
@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    """Handle CORS preflight."""
    logger.info(f"OPTIONS preflight for: {path}")
    response = make_response()
    return response, 200


# Simple auth status endpoint
@app.route('/api/auth/status', methods=['GET'])
def get_auth_status():
    """Get auth status."""
    logger.info(f"Auth status request from {request.remote_addr}")
    return jsonify({
        "status": "success",
        "authenticated": False,
        "message": "Auth status retrieved"
    })


# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check."""
    return jsonify({
        "status": "success",
        "message": "API is operational"
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting test server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
