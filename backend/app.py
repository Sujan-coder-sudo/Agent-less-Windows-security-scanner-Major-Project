"""
app.py
Flask application entry point.
"""

from flask import Flask, jsonify
from flask_cors import CORS
from routes.scan_routes import scan_bp

app = Flask(__name__)

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


# ── 404 / 405 handlers ────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Endpoint not found."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"status": "error", "message": "Method not allowed."}), 405


# ── Entry ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print(" Agentless Scanner — Clean Backend")
    print(" http://localhost:5000")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
