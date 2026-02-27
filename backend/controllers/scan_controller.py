from __future__ import annotations

import logging
from flask import Blueprint, jsonify, request

from services.scan_service import ScanService
from utils.validators import validate_ipv4_or_cidr_strict
from utils.exceptions import ValidationError, ExecutionError, FileReadError, JSONParseError

logger = logging.getLogger(__name__)

scan_bp = Blueprint("scan", __name__, url_prefix="/api")

scan_service = ScanService()


def _response(*, status: str, message: str, data=None):
    return jsonify({"status": status, "message": message, "data": data})


@scan_bp.route("/phase2/run", methods=["POST"])
def run_phase2():
    try:
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        if not target:
            raise ValidationError("Target IP address is required")

        validate_ipv4_or_cidr_strict(target)

        result = scan_service.run_phase2(target)
        return _response(status="success", message="Phase 2 scan completed successfully", data=result), 200

    except ValidationError as e:
        return _response(status="error", message=str(e), data={}), 400
    except (ExecutionError, FileReadError, JSONParseError) as e:
        logger.exception("Phase 2 failed")
        return _response(status="error", message=str(e), data={}), 500
    except Exception:
        logger.exception("Unexpected error in Phase 2")
        return _response(status="error", message="Internal server error", data={}), 500


@scan_bp.route("/phase3/run", methods=["POST"])
def run_phase3():
    try:
        result = scan_service.run_phase3()
        return _response(status="success", message="Phase 3 scan completed successfully", data=result), 200

    except (ExecutionError, FileReadError, JSONParseError) as e:
        logger.exception("Phase 3 failed")
        return _response(status="error", message=str(e), data={}), 500
    except Exception:
        logger.exception("Unexpected error in Phase 3")
        return _response(status="error", message="Internal server error", data={}), 500


@scan_bp.route("/scans", methods=["GET"])
def list_scans():
    try:
        scans = scan_service.list_scans()
        return _response(status="success", message="Scan history retrieved", data=scans), 200
    except Exception:
        logger.exception("Failed to list scans")
        return _response(status="error", message="Internal server error", data=[]), 500


@scan_bp.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    try:
        scan = scan_service.get_scan(scan_id)
        if scan is None:
            return _response(status="error", message="Scan not found", data={}), 404
        return _response(status="success", message="Scan retrieved", data=scan), 200
    except Exception:
        logger.exception("Failed to get scan")
        return _response(status="error", message="Internal server error", data={}), 500
