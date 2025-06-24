"""Authentication and miscellaneous routes"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from auth import authenticate_user
from functools import wraps

# Create Blueprint
other_bp = Blueprint('other', __name__)

def is_admin_user(user):
    """Check if user is an admin - Dynamic role-based"""
    from flask import session
    # Check session first (for performance)
    if session.get('role') == 'admin':
        return True
    # Fallback to user object role check
    if user and hasattr(user, 'role') and user.role == 'admin':
        return True
    return False

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('other.login'))
        if not is_admin_user(current_user):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@other_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login form submission"""
    from urllib.parse import unquote
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = authenticate_user(username, password)
        if user:
            login_user(user)
            
            # Store user role in session for RBAC - Dynamic database-driven
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['role'] = user.role or 'user'  # Use database role directly
            
            flash('Successfully logged in!', 'success')
            
            # Handle next parameter properly
            next_page = request.args.get('next')
            if next_page:
                # Decode URL-encoded parameters
                next_page = unquote(next_page)
                # Ensure it's a safe redirect
                if next_page.startswith('/'):
                    return redirect(next_page)
            
            return redirect(url_for('dashboard.dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('auth/login.html')
    
    # Show professional login page for GET requests
    return render_template('auth/login.html')

@other_bp.route('/logout')
@login_required
def logout():
    """Handle logout"""
    logout_user()
    session.clear()  # Clear all session data including role
    flash('You have been logged out.', 'info')
    return redirect(url_for('dashboard.index'))

@other_bp.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'ok', 'message': 'Application is running'}, 200

@other_bp.route('/login%3Fnext=%2Fadmin')
@other_bp.route('/login%3Fnext=%2F<path:next_path>')
def handle_encoded_login(next_path=None):
    """Handle URL-encoded login redirects from new tabs"""
    from urllib.parse import unquote
    
    if current_user.is_authenticated:
        if next_path:
            decoded_path = '/' + unquote(next_path)
            return redirect(decoded_path)
        return redirect(url_for('dashboard.dashboard'))
    
    # Redirect to proper login with decoded next parameter
    if next_path:
        decoded_next = '/' + unquote(next_path)
        return redirect(url_for('other.login', next=decoded_next))
    else:
        return redirect(url_for('other.login', next='/admin'))

@other_bp.route('/api/get_user_password/<int:user_id>')
@admin_required
def get_user_password(user_id):
    """API endpoint for admin to get user's actual password"""
    from models import User
    try:
        user = User.query.get_or_404(user_id)
        # Only return password if current user is admin
        if not is_admin_user(current_user):
            return jsonify({'error': 'Access denied'}), 403
        
        # Return the actual password hash (in real implementation, this would be decrypted)
        # For security demo, we'll show a portion of the hash
        password_display = user.password_hash[:20] + "..." if user.password_hash else "No password set"
        
        return jsonify({
            'success': True,
            'password_display': password_display,
            'username': user.username
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500