"""Form management routes for templates and submissions"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from app_main import db
from models import FormTemplate, FormSubmission, User, Organization
from app.models.models_house_acknowledge import HouseAcknowledge, HouseAcknowledgment

# Create Blueprint
form_bp = Blueprint('form', __name__)

def is_admin_user(user):
    """Check if user is an admin"""
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
            return redirect(url_for('other.login'))
        if not is_admin_user(current_user):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@form_bp.route('/form-management')
@login_required
@admin_required
def form_management():
    """Form management dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    forms = FormTemplate.query.filter_by(organization_id=user.organization_id).all()
    submissions = FormSubmission.query.filter_by(organization_id=user.organization_id).order_by(FormSubmission.created_at.desc()).limit(10).all()
    
    return render_template('forms/form_management.html',
                         forms=forms,
                         submissions=submissions,
                         user=user)

@form_bp.route('/submissions')
@login_required
def submissions():
    """View form submissions"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    submissions = FormSubmission.query.filter_by(organization_id=user.organization_id).order_by(FormSubmission.created_at.desc()).all()
    return render_template('forms/form_submissions.html', submissions=submissions, user=user)

@form_bp.route('/house-acknowledge')
@login_required
def house_acknowledge():
    """House acknowledgment forms dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    acknowledgments = HouseAcknowledgment.query.filter_by(organization_id=user.organization_id).order_by(HouseAcknowledgment.created_at.desc()).all()
    return render_template('forms/house_acknowledge_storage.html', acknowledgments=acknowledgments, user=user)

@form_bp.route('/house-acknowledge/create', methods=['GET', 'POST'])
@login_required
def create_house_acknowledge():
    """Create house acknowledgment form"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content = request.form.get('content')
            language = request.form.get('language', 'english')
            
            if not title or not content:
                flash('Title and content are required', 'error')
                return render_template('forms/house_acknowledge_create.html', user=user)
            
            acknowledgment = HouseAcknowledgment(
                title=title,
                content=content,
                language=language,
                organization_id=user.organization_id,
                created_by=user.id,
                created_at=datetime.now()
            )
            
            db.session.add(acknowledgment)
            db.session.commit()
            
            flash('House acknowledgment created successfully!', 'success')
            return redirect(url_for('form.house_acknowledge'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating acknowledgment: {str(e)}', 'error')
    
    return render_template('forms/house_acknowledge_create.html', user=user)

@form_bp.route('/house-acknowledge/<int:ack_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_house_acknowledge(ack_id):
    """Edit house acknowledgment form"""
    user = current_user
    acknowledgment = HouseAcknowledgment.query.filter_by(id=ack_id, organization_id=user.organization_id).first()
    
    if not acknowledgment:
        flash('Acknowledgment not found', 'error')
        return redirect(url_for('form.house_acknowledge'))
    
    if request.method == 'POST':
        try:
            acknowledgment.title = request.form.get('title')
            acknowledgment.content = request.form.get('content')
            acknowledgment.language = request.form.get('language')
            
            db.session.commit()
            flash('Acknowledgment updated successfully!', 'success')
            return redirect(url_for('form.house_acknowledge'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating acknowledgment: {str(e)}', 'error')
    
    return render_template('forms/house_acknowledge_edit.html', acknowledgment=acknowledgment, user=user)

@form_bp.route('/public/house-acknowledge/<int:ack_id>')
def public_house_acknowledge(ack_id):
    """Public house acknowledgment form"""
    acknowledgment = HouseAcknowledgment.query.get_or_404(ack_id)
    return render_template('forms/house_acknowledge_form.html', acknowledgment=acknowledgment)

@form_bp.route('/public/house-acknowledge/<int:ack_id>/submit', methods=['POST'])
def submit_house_acknowledge(ack_id):
    """Submit house acknowledgment form"""
    acknowledgment = HouseAcknowledgment.query.get_or_404(ack_id)
    
    try:
        # Process form submission
        resident_name = request.form.get('resident_name')
        room_number = request.form.get('room_number')
        signature_data = request.form.get('signature_data')
        
        if not resident_name or not room_number:
            flash('Resident name and room number are required', 'error')
            return render_template('forms/house_acknowledge_form.html', acknowledgment=acknowledgment)
        
        # Create submission record
        submission = FormSubmission(
            form_type='house_acknowledge',
            reference_id=acknowledgment.id,
            organization_id=acknowledgment.organization_id,
            data=request.form.to_dict(),
            created_at=datetime.now()
        )
        
        db.session.add(submission)
        db.session.commit()
        
        return render_template('forms/house_acknowledge_success.html', acknowledgment=acknowledgment)
        
    except Exception as e:
        db.session.rollback()
        return render_template('forms/form_error.html', error=str(e))

@form_bp.route('/public/offense-report')
def public_offense_report():
    """Public offense report form"""
    return render_template('forms/public_offense_report.html')

@form_bp.route('/public/offense-report/submit', methods=['POST'])
def submit_offense_report():
    """Submit offense report"""
    try:
        # Process offense report submission
        report_data = request.form.to_dict()
        
        # Create submission record
        submission = FormSubmission(
            form_type='offense_report',
            data=report_data,
            created_at=datetime.now()
        )
        
        db.session.add(submission)
        db.session.commit()
        
        flash('Offense report submitted successfully', 'success')
        return render_template('forms/form_submitted.html')
        
    except Exception as e:
        db.session.rollback()
        return render_template('forms/form_error.html', error=str(e))