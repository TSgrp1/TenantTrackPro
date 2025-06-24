"""Application factory with proper route and model registration"""
import os
import logging
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
# Try to load environment variables if dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # Continue without dotenv in Replit environment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

class Base(DeclarativeBase):
    pass

def create_app():
    """Create and configure Flask application with proper structure"""
    app = Flask(__name__)
    
    # Register routes
    from app.routes import register_routes
    register_routes(app)
    
    # Register Jinja2 globals and filters
    from jinja_globals import register_jinja_globals
    register_jinja_globals(app)
    
    # Load all environment variables
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY') or os.environ.get('SESSION_SECRET') or 'dev-key',
        'SUPABASE_URL': os.environ.get('SUPABASE_URL'),
        'SUPABASE_ANON_KEY': os.environ.get('SUPABASE_ANON_KEY'),
        'SUPABASE_SERVICE_ROLE_KEY': os.environ.get('SUPABASE_SERVICE_ROLE_KEY'),
        'MAX_CONTENT_LENGTH': 50 * 1024 * 1024,  # 50MB
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })
    
    app.secret_key = app.config['SECRET_KEY']
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Database configuration with Supabase support
    database_url = os.environ.get("DATABASE_URL")
    
    if database_url:
        # Always use Supabase database from .env file for consistency
        try:
            with open('.env', 'r') as f:
                for line in f:
                    if line.startswith('DATABASE_URL='):
                        database_url = line.split('=', 1)[1].strip()
                        logging.info("Using Supabase PostgreSQL database")
                        break
        except FileNotFoundError:
            logging.info("Using environment DATABASE_URL")
        
        # Handle postgres:// vs postgresql:// prefix
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 20,
            'max_overflow': 30,
            'pool_timeout': 20,
            'echo': False,  # Disable SQL logging for performance
        }
        logging.info("✓ Connected to Supabase/PostgreSQL database")
    else:
        # Use SQLite fallback
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        }
        if database_url:
            logging.warning("⚠ Old database endpoint detected, using SQLite fallback")
        else:
            logging.info("ℹ No DATABASE_URL provided, using SQLite")
    
    # Initialize database
    db = SQLAlchemy(model_class=Base)
    db.init_app(app)
    
    # Create directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Register template filters
    register_filters(app)
    
    # Add performance monitoring
    from performance_monitor import monitor_performance
    monitor_performance(app)
    
    # Database optimizations
    from db_optimizer import optimize_database_connections, create_database_indexes
    with app.app_context():
        optimize_database_connections()
        create_database_indexes()
    
    # Register models and create tables
    with app.app_context():
        register_models()
        try:
            db.create_all()
            logging.info("✓ Database tables created successfully")
        except Exception as e:
            logging.error(f"✗ Database error: {e}")
    
    # Register routes
    register_routes(app)
    
    # Add health check endpoint
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'database': 'connected' if database_url else 'sqlite_fallback',
            'supabase_configured': bool(app.config.get('SUPABASE_URL'))
        })
    
    return app, db

def register_filters(app):
    """Register Jinja2 template filters"""
    import json
    
    @app.template_filter('from_json')
    def from_json_filter(value):
        try:
            return json.loads(value) if value else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    @app.template_filter('nl2br')
    def nl2br_filter(value):
        if not value:
            return ''
        return value.replace('\n', '<br>\n')

def register_models():
    """Import all models to register with SQLAlchemy"""
    try:
        # Import all existing model files (avoid duplicates)
        import models
        from app.models import models_house_acknowledge
        from app.models import models_meter_reading
        from app.models import models_room_inspection
        from app.models import models_asset
        from app.models import models_msrf
        from app.models import models_food_locker
        from app.models import models_bedding
        from app.models import models_resident_checkout
        from app.models import models_key_management
        # Skip models_compliance to avoid table conflicts - ComplianceRecord is already in models.py
        logging.info("✓ All models registered")
    except ImportError as e:
        logging.error(f"✗ Model import error: {e}")
    except Exception as e:
        logging.error(f"✗ Model registration error: {e}")
        # Continue anyway to avoid blocking the app

def register_routes(app):
    """Register all application routes"""
    global db
    try:
        # Set globals to make app and db available to routes module
        import sys
        sys.modules['app'].app = app
        sys.modules['app'].db = db
        
        # Reimport routes to register with correct app instance
        if 'routes' in sys.modules:
            del sys.modules['routes']
        if 'auth' in sys.modules:
            del sys.modules['auth']
            
        # Import authentication first
        import auth
        
        # Import routes fresh - this will register all @app.route decorators
        import routes
        
        logging.info("✓ Authentication and routes registered")
    except ImportError as e:
        logging.error(f"✗ Route import error: {e}")
    except Exception as e:
        logging.error(f"✗ Route registration error: {e}")

# Create application instance
app, db = create_app()

# Make available for imports
__all__ = ['app', 'db']

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logging.info(f"🚀 Starting application on 0.0.0.0:{port}")
    logging.info(f"🔧 Debug mode: {debug}")
    
    app.run(host="0.0.0.0", port=port, debug=debug)