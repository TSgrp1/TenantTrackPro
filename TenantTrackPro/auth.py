from flask import request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from app_main import app, db
from models import User
import logging

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def create_pioneer_lodge_user():
    """Create the Pioneer Lodge admin user if it doesn't exist"""
    username = "pioneerlodge@tsgrp.sg"
    password = "PLOPS@123&"
    
    existing_user = User.query.filter_by(email=username).first()
    if not existing_user:
        # Create Pioneer Lodge user with admin role
        user = User()
        user.id = "pioneer_lodge_admin"
        user.email = username
        user.first_name = "Pioneer Lodge"
        user.last_name = "Admin"
        user.password_hash = generate_password_hash(password)
        user.organization_id = 1  # Pioneer Lodge organization
        user.role = 'admin'  # Set admin role in database
        user.is_admin = True  # Set admin flag
        
        db.session.add(user)
        db.session.commit()
        logging.info(f"Created Pioneer Lodge admin user: {username} with admin role")
        return user
    else:
        # Update existing user to ensure admin role
        if existing_user.role != 'admin':
            existing_user.role = 'admin'
            existing_user.is_admin = True
            db.session.commit()
            logging.info(f"Updated Pioneer Lodge user role to admin: {username}")
    return existing_user

def authenticate_user(username, password):
    """Authenticate user with username and password"""
    logging.info(f"Authentication attempt for username: {username}")
    
    # Check if user exists in database (case-insensitive email comparison)
    if username:
        user = User.query.filter(User.email.ilike(username)).first()
    else:
        user = None
    
    if user:
        logging.info(f"User found: {user.email}, has password hash: {bool(user.password_hash)}")
        # Check if user has a password hash (for password-based login)
        if user.password_hash and check_password_hash(user.password_hash, password):
            logging.info(f"Password verification successful for user: {user.email}")
            return user
        # Fallback for Pioneer Lodge admin (maintaining compatibility)
        elif username == "pioneerlodge@tsgrp.sg" and password == "PLOPS@123&":
            # Ensure user has admin role in database
            if user.role != 'admin':
                user.role = 'admin'
                user.is_admin = True
                db.session.commit()
            # Update password hash if not set
            if not user.password_hash:
                user.password_hash = generate_password_hash(password)
                db.session.commit()
            logging.info(f"Pioneer Lodge admin authenticated: {user.email}")
            return user
        else:
            logging.warning(f"Password verification failed for user: {user.email}")
    else:
        logging.warning(f"User not found for username: {username}")
    
    # Create Pioneer Lodge admin if it doesn't exist and credentials match
    if username == "pioneerlodge@tsgrp.sg" and password == "PLOPS@123&":
        user = create_pioneer_lodge_user()
        logging.info(f"Created Pioneer Lodge admin user: {user.email}")
        return user
    
    logging.warning(f"Authentication failed for username: {username}")
    return None