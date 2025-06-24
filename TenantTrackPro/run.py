#!/usr/bin/env python3
"""
Main application runner with proper error handling and Supabase support
"""
import os
import sys
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

class Base(DeclarativeBase):
    pass

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Load environment variables if available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    
    # Basic configuration with all required env vars
    app.secret_key = os.environ.get("SESSION_SECRET") or os.environ.get("SECRET_KEY") or "dev-key-change-in-production"
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Supabase configuration
    app.config['SUPABASE_URL'] = os.environ.get('SUPABASE_URL')
    app.config['SUPABASE_ANON_KEY'] = os.environ.get('SUPABASE_ANON_KEY')
    app.config['SUPABASE_SERVICE_ROLE_KEY'] = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')
    
    # Database configuration with proper Supabase support
    database_url = os.environ.get("DATABASE_URL")
    
    if database_url and "ep-holy-rice-adpl2v47.c-2.us-east-1.aws.neon.tech" not in database_url:
        # Handle Supabase and other PostgreSQL URLs
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 10,
            'max_overflow': 20
        }
        logging.info("Connected to PostgreSQL/Supabase database")
    else:
        # Use SQLite fallback
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        }
        if database_url:
            logging.warning("Old database endpoint detected, using SQLite fallback")
        else:
            logging.info("No DATABASE_URL provided, using SQLite")
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
    
    # Initialize database
    db = SQLAlchemy(model_class=Base)
    db.init_app(app)
    
    # Create upload directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    
    # Add custom Jinja2 filters
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
    
    # Import and register models
    with app.app_context():
        try:
            # Import all model files to register them
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
            
            # Create all tables
            db.create_all()
            logging.info("Database tables created successfully")
        except Exception as e:
            logging.error(f"Error setting up database: {e}")
            # Don't fail completely, let the app start
    
    # Import authentication and routes
    try:
        import auth
        import routes
        logging.info("Authentication and routes loaded successfully")
    except Exception as e:
        logging.error(f"Error loading auth/routes: {e}")
        return None
    
    return app

def main():
    """Main application entry point"""
    app = create_app()
    
    if app is None:
        logging.error("Failed to create application")
        sys.exit(1)
    
    # Get configuration from environment
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    host = '0.0.0.0'
    
    logging.info(f"Starting application on {host}:{port}")
    logging.info(f"Debug mode: {debug}")
    
    try:
        app.run(host=host, port=port, debug=debug)
    except Exception as e:
        logging.error(f"Failed to start application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()