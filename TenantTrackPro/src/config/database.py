"""Database configuration for Supabase integration"""
import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase
from flask_sqlalchemy import SQLAlchemy

class Base(DeclarativeBase):
    pass

def get_database_url():
    """Get Supabase database URL"""
    database_url = os.environ.get("DATABASE_URL")
    
    if not database_url:
        # Try to read from .env file
        try:
            with open('.env', 'r') as f:
                for line in f:
                    if line.startswith('DATABASE_URL='):
                        database_url = line.split('=', 1)[1].strip()
                        break
        except FileNotFoundError:
            pass
    
    if not database_url:
        logging.error("No DATABASE_URL found")
        return None
    
    # Handle postgres:// vs postgresql:// prefix for Supabase
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    return database_url

def configure_database(app):
    """Configure database for Flask app"""
    database_url = get_database_url()
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Configure engine options based on database type
    if "postgresql" in database_url:
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 10,
            'max_overflow': 20
        }
        logging.info("Configured PostgreSQL/Supabase database")
    else:
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        }
        logging.info("Configured SQLite database")
    
    return SQLAlchemy(model_class=Base)