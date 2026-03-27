"""
scan_routes.py
Blueprint containing all /api/scan* routes.
"""

from flask import Blueprint, request, jsonify
from services.scan_service import (
    run_scan,
    get_scan_history,
    get_scan_by_id,
    get_latest_scan,
)
from utils.validator import validate_target

scan_bp = Blueprint("scan", __name__)


# ── POST /api/scan ─────────────────────────────────────────────────────────────

@scan_bp.route("/scan", methods=["POST"])
def start_scan():
    body = request.get_json(silent=True) or {}
    target    = str(body.get("target", "")).strip()
    scan_type = str(body.get("scan_type", "")).strip()

    # Validate target
    valid, reason = validate_target(target)
    if not valid:
        return jsonify({"status": "error", "message": reason}), 400

    # Validate scan_type
    if scan_type not in ("port_scan", "os_inspection"):
        return jsonify({
            "status":  "error",
            "message": "scan_type must be 'port_scan' or 'os_inspection'."
        }), 400

    try:
        payload = run_scan(target, scan_type)
        return jsonify({
            "status":  "success",
            "scan_id": payload["scan_id"],
            "message": f"{scan_type} completed successfully.",
            "data":    payload,
        }), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    except RuntimeError as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"Unexpected error: {str(e)}"}), 500


# ── GET /api/scans ─────────────────────────────────────────────────────────────

@scan_bp.route("/scans", methods=["GET"])
def list_scans():
    try:
        history = get_scan_history()
        return jsonify({"status": "success", "data": history}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/scans/latest ──────────────────────────────────────────────────────

@scan_bp.route("/scans/latest", methods=["GET"])
def latest_scan():
    try:
        scan = get_latest_scan()
        if scan is None:
            return jsonify({"status": "error", "message": "No scans found."}), 404
        return jsonify({"status": "success", "data": scan}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/scans/<scan_id> ───────────────────────────────────────────────────

@scan_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    try:
        scan = get_scan_by_id(scan_id)
        if scan is None:
            return jsonify({"status": "error", "message": f"Scan '{scan_id}' not found."}), 404
        return jsonify({"status": "success", "data": scan}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
