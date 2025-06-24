"""QR Code related routes"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import current_user, login_required
from datetime import datetime
from io import BytesIO
import qrcode
import io
import uuid
from app_main import db
from models import QRCode
from functools import wraps

# Create Blueprint
qr_bp = Blueprint('qr', __name__)

# Import permission functions
def is_admin_user(user):
    """Check if user is an admin (Pioneer Lodge admin or has admin role)"""
    if user.role == 'admin':
        return True
    if hasattr(user, 'role') and user.role == 'admin':
        return True
    return False

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('dashboard.index'))
        if not is_admin_user(current_user):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def create_permission_required(page_name):
    """Decorator to require create permissions for a specific page"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('other.login'))
            # For now, allow admin users to create QR codes
            if not is_admin_user(current_user):
                flash('Access denied. You cannot create new items.', 'error')
                return redirect(url_for('dashboard.dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@qr_bp.route('/qr-code/<int:qr_id>')
def generate_qr_code(qr_id):
    """Generate and serve QR code image"""
    try:
        qr_record = QRCode.query.get_or_404(qr_id)
        
        # Generate QR code URL - always use the QR redirect pattern for consistency
        qr_url = f"{request.url_root}qr/{qr_record.code}"
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return Response(img_buffer.getvalue(), mimetype='image/png')
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@qr_bp.route('/qr-codes')
@login_required
@admin_required
def qr_codes():
    """QR codes management page"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    qr_codes_list = QRCode.query.filter_by(organization_id=user.organization_id).all()
    return render_template('qr/qr_codes.html', qr_codes=qr_codes_list)

@qr_bp.route('/generate_qr_code', methods=['POST'])
@login_required
@create_permission_required('qr_codes')
def generate_qr_code_post():
    """Generate a new QR code"""
    user = current_user
    if not user.organization_id:
        return jsonify({'success': False, 'error': 'Please contact administrator to assign organization'})
    
    try:
        qr_type = request.form.get('qr_type')
        label = request.form.get('label')
        description = request.form.get('description')
        
        # URL-specific fields
        target_url = request.form.get('target_url')
        expires_at = request.form.get('expires_at')
        max_scans = request.form.get('max_scans')
        is_public = request.form.get('is_public', 'true').lower() == 'true'
        
        if not qr_type or not label:
            return jsonify({'success': False, 'error': 'QR type and label are required'})
        
        if qr_type == 'url' and not target_url:
            return jsonify({'success': False, 'error': 'Target URL is required for URL type QR codes'})
        
        # Validate URL format for URL type
        if qr_type == 'url' and target_url:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            if not all([parsed.scheme, parsed.netloc]):
                return jsonify({'success': False, 'error': 'Please enter a valid URL (e.g., https://example.com)'})
        
        # Parse expiry date
        expires_at_datetime = None
        if expires_at:
            try:
                expires_at_datetime = datetime.strptime(expires_at, '%Y-%m-%d')
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid expiry date format'})
        
        # Parse max scans
        max_scans_int = None
        if max_scans:
            try:
                max_scans_int = int(max_scans)
                if max_scans_int <= 0:
                    return jsonify({'success': False, 'error': 'Max scans must be a positive number'})
            except ValueError:
                return jsonify({'success': False, 'error': 'Max scans must be a valid number'})
        
        # Generate unique code
        code = str(uuid.uuid4())
        
        # Create QR code record
        qr_code = QRCode(
            code=code,
            qr_type=qr_type,
            label=label,
            description=description,
            target_url=target_url,
            expires_at=expires_at_datetime,
            max_scans=max_scans_int,
            is_public=is_public,
            organization_id=user.organization_id,
            created_by=user.id
        )
        
        db.session.add(qr_code)
        db.session.commit()
        
        return jsonify({'success': True, 'qr_id': qr_code.id})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@qr_bp.route('/qr/<string:code>')
def qr_redirect(code):
    """Handle QR code redirects"""
    try:
        qr_record = QRCode.query.filter_by(code=code).first()
        
        if not qr_record:
            return render_template('qr_info.html', 
                                 error="QR code not found",
                                 code=code), 404
        
        # Check if QR code is expired
        if qr_record.expires_at and qr_record.expires_at < datetime.now():
            return render_template('qr/qr_info.html',
                                 error="QR code has expired",
                                 qr_code=qr_record), 410
        
        # Check if max scans reached
        if qr_record.max_scans and qr_record.scan_count >= qr_record.max_scans:
            return render_template('qr/qr_info.html',
                                 error="QR code scan limit reached",
                                 qr_code=qr_record), 410
        
        # Increment scan count
        qr_record.scan_count += 1
        qr_record.last_scanned_at = datetime.now()
        db.session.commit()
        
        # Handle different QR types
        if qr_record.qr_type == 'url':
            return redirect(qr_record.target_url)
        elif qr_record.qr_type == 'form':
            # Redirect to form page
            return redirect(url_for('dashboard.dashboard'))
        else:
            # Show QR info page
            return render_template('qr/qr_info.html', qr_code=qr_record)
            
    except Exception as e:
        return render_template('qr/qr_info.html', 
                             error=f"Error processing QR code: {str(e)}",
                             code=code), 500

@qr_bp.route('/qr/<string:code>/info')
def qr_info(code):
    """Show QR code information without redirecting"""
    try:
        qr_record = QRCode.query.filter_by(code=code).first()
        
        if not qr_record:
            return render_template('qr_info.html', 
                                 error="QR code not found",
                                 code=code), 404
        
        return render_template('qr/qr_info.html', qr_code=qr_record)
        
    except Exception as e:
        return render_template('qr/qr_info.html', 
                             error=f"Error: {str(e)}",
                             code=code), 500