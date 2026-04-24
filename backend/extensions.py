from flask_sqlalchemy import SQLAlchemy

# Initialize extensions without binding to an app to avoid circular imports.
db = SQLAlchemy()
