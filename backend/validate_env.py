import sys
try:
    from app import create_app
    from extensions import db
    app = create_app('default')
    with app.app_context():
        db.create_all()
    print('SUCCESS: Flask and SQLAlchemy initialized successfully!')
    print('SUCCESS: SQLite database created/verified.')
    sys.exit(0)
except Exception as e:
    print(f'CRITICAL FAILURE: {e}')
    sys.exit(1)
