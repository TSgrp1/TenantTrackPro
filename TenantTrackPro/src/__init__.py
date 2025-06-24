"""Application factory and initialization"""
import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from src.config.database import configure_database, Base
from src.config.settings import get_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

def create_app(config_name=None):
    """Create and configure Flask application"""
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    
    # Load configuration
    config_class = get_config()
    app.config.from_object(config_class)
    
    # Configure proxy for production deployment
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Initialize database
    db = configure_database(app)
    db.init_app(app)
    
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Register custom template filters
    register_template_filters(app)
    
    # Import and register models
    with app.app_context():
        register_models()
        db.create_all()
        logging.info("Database tables created successfully")
    
    # Import and register blueprints/routes
    register_routes(app)
    
    # Import authentication setup
    register_auth(app)
    
    return app, db

def register_template_filters(app):
    """Register custom Jinja2 template filters"""
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

def register_models():
    """Import all model modules to register with SQLAlchemy"""
    try:
        from src.models import user, organization, system_log, news
        from src.models import house_acknowledge, meter_reading, room_inspection
        from src.models import asset, msrf, food_locker, bedding
        from src.models import resident_checkout, key_management, compliance
        from src.models import purchase  # New purchase models
        logging.info("All models registered successfully")
    except ImportError as e:
        logging.error(f"Error importing models: {e}")
        # Fall back to old model imports for compatibility
        import models
        import models_house_acknowledge
        import models_meter_reading
        import models_room_inspection
        import models_asset
        import models_msrf
        import models_food_locker
        import models_bedding
        import models_resident_checkout
        import models_key_management
        import models_compliance
        logging.info("Fallback model imports successful")

def register_routes(app):
    """Register application routes"""
    try:
        from src.routes import auth_routes, main_routes, purchase_routes
        # Register route modules when they exist
        logging.info("New route structure registered")
    except ImportError:
        # Fall back to old route structure
        import routes
        logging.info("Fallback routes imported")

def register_auth(app):
    """Register authentication configuration"""
    try:
        from src.auth import setup_auth
        setup_auth(app)
    except ImportError:
        # Fall back to old auth
        import auth
        logging.info("Fallback auth imported")

# Global database instance (for backward compatibility)
db = None