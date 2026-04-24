"""
app.py
Flask application factory and entry point.
"""

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

# ── Logging Setup ──────────────────────────────────────────────────────────────
# Configure root logger so scan_service.py / scan_tasks.py debug output is visible.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("services.scan_service").setLevel(logging.INFO)
logging.getLogger("tasks.scan_tasks").setLevel(logging.INFO)

from config import config_by_name
from extensions import db
from routes.scan_routes import scan_bp
from models import User, Scan, Finding

def create_app(config_name="default"):
    """Application factory pattern."""
    app = Flask(__name__)
    
    # ── Configuration ──────────────────────────────────────────────────────────────
    # Safely retrieve configuration, fallback to 'default' if the provided config_name is invalid
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)
    
    # ── Extensions ─────────────────────────────────────────────────────────────────
    db.init_app(app)

    # ── CORS ───────────────────────────────────────────────────────────────────────
    CORS(
        app,
        resources={r"/api/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500"]}},
        supports_credentials=True,
    )

    # ── Blueprints ─────────────────────────────────────────────────────────────────
    app.register_blueprint(scan_bp, url_prefix="/api")

    # ── Health / Ping ──────────────────────────────────────────────────────────────
    @app.route("/api/ping", methods=["GET"])
    def ping():
        return jsonify({"status": "ok", "message": "Backend is running."}), 200

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    # ── Error Handlers ─────────────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Endpoint not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"status": "error", "message": "Method not allowed."}), 405

    # ── Database Initialization ────────────────────────────────────────────────────
    with app.app_context():
        # Ensure database tables are created. 
        # In a real production setup, use Flask-Migrate instead.
        db.create_all()
        
    return app

# Provide a default app instance for simple local execution
app = create_app(os.getenv("FLASK_ENV") or "default")

if __name__ == "__main__":
    print("=" * 50)
    print(" Agentless Scanner — Enterprise Backend (Phase 2)")
    print(" http://localhost:5000")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
