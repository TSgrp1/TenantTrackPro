"""Role-Based Access Control Utilities"""
from functools import wraps
from flask import session, redirect, url_for, flash
from flask_login import current_user

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session first
        if session.get('role') != 'admin':
            # Fallback to user object check
            if not current_user.is_authenticated:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('other.login'))
            
            # Check if user has admin role in database
            if not (hasattr(current_user, 'role') and current_user.role == 'admin'):
                flash('Admin access required', 'error')
                return redirect(url_for('dashboard.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def session_admin_check():
    """Check if current session has admin privileges"""
    return session.get('role') == 'admin'

def user_has_admin_role():
    """Check if current user has admin role - Dynamic database-driven"""
    # Check session first
    if session.get('role') == 'admin':
        return True
    
    # Fallback to user object role
    if current_user.is_authenticated:
        if hasattr(current_user, 'role') and current_user.role == 'admin':
            return True
    
    return False