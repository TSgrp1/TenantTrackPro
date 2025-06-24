from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1) # needed for url_for to generate with https

# Force Supabase database configuration
database_url = "postgresql://postgres.mtttdnwhvkkxqfiaqiam:fE3YVKimALq8ycar@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres"
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
logging.info("Using Supabase PostgreSQL database")

# Remove the problematic lines

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    'pool_pre_ping': True,
    "pool_recycle": 300,
}

# Set maximum content length to 50MB to handle multiple compressed photos
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# Initialize database
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Create tables immediately since we're using SQLite
with app.app_context():
    try:
        import models  # noqa: F401
        from app.models import models_house_acknowledge  # noqa: F401
        from app.models import models_meter_reading  # noqa: F401
        from app.models import models_room_inspection  # noqa: F401
        from app.models import models_asset  # noqa: F401
        from app.models import models_msrf  # noqa: F401
        from app.models import models_food_locker  # noqa: F401
        from app.models import models_bedding  # noqa: F401
        from app.models import models_resident_checkout  # noqa: F401
        from app.models import models_key_management  # noqa: F401
        # Skip models_compliance to avoid table conflicts - ComplianceRecord is already in models.py
        db.create_all()
        logging.info("Database tables created successfully")
    except Exception as e:
        logging.error(f"Error creating database tables: {e}")
        raise

# Add custom Jinja2 filters
import json
@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string to Python object"""
    try:
        return json.loads(value) if value else {}
    except (json.JSONDecodeError, TypeError):
        return {}

@app.template_filter('nl2br')
def nl2br_filter(value):
    """Convert newlines to HTML line breaks"""
    if not value:
        return ''
    return value.replace('\n', '<br>\n')
