"""
celery_worker.py
DEPRECATED: Celery has been removed from this project.

This file is kept for reference only. The application now uses
threading.Thread for background scan execution instead of Celery.
No separate worker process is required.

To run scans:
1. Start the Flask backend: python app.py
2. POST to /api/scan - scans execute in background threads automatically
"""
print("WARNING: Celery has been removed from this project.")
print("Scans now run in background threads within the Flask process.")
print("No separate worker is required.")
