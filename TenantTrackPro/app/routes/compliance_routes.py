"""Compliance management routes for records and acknowledgments"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from app_main import db
from models import User, Organization, ComplianceRecord, ComplianceAcknowledgment

# Create Blueprint
compliance_bp = Blueprint('compliance', __name__)

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

@compliance_bp.route('/compliance-management')
@login_required
def compliance_management():
    """Compliance management dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Get compliance records
    compliance_records = ComplianceRecord.query.filter_by(organization_id=user.organization_id).order_by(ComplianceRecord.created_at.desc()).all()
    
    # Get acknowledgments
    acknowledgments = ComplianceAcknowledgment.query.filter_by(organization_id=user.organization_id).order_by(ComplianceAcknowledgment.created_at.desc()).limit(10).all()
    
    # Get statistics
    total_records = len(compliance_records)
    pending_records = len([r for r in compliance_records if r.status == 'pending'])
    acknowledged_records = len([r for r in compliance_records if r.status == 'acknowledged'])
    
    return render_template('compliance/compliance_management.html',
                         compliance_records=compliance_records,
                         acknowledgments=acknowledgments,
                         total_records=total_records,
                         pending_records=pending_records,
                         acknowledged_records=acknowledged_records,
                         user=user)

@compliance_bp.route('/create-compliance-record', methods=['POST'])
@login_required
@admin_required
def create_compliance_record():
    """Create new compliance record"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority', 'medium')
        language = request.form.get('language', 'english')
        
        if not title or not description:
            flash('Title and description are required', 'error')
            return redirect(url_for('compliance.compliance_management'))
        
        record = ComplianceRecord(
            title=title,
            description=description,
            category=category,
            priority=priority,
            language=language,
            status='pending',
            organization_id=user.organization_id,
            created_by=user.id,
            created_at=datetime.now()
        )
        
        db.session.add(record)
        db.session.commit()
        
        flash('Compliance record created successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating compliance record: {str(e)}', 'error')
    
    return redirect(url_for('compliance.compliance_management'))

@compliance_bp.route('/compliance-records/filter/<language_code>')
@login_required
def filter_compliance_records(language_code):
    """Filter compliance records by language"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Get filtered records
    if language_code == 'all':
        records = ComplianceRecord.query.filter_by(organization_id=user.organization_id).order_by(ComplianceRecord.created_at.desc()).all()
    else:
        records = ComplianceRecord.query.filter_by(organization_id=user.organization_id, language=language_code).order_by(ComplianceRecord.created_at.desc()).all()
    
    return render_template('compliance/compliance_records_filtered.html',
                         records=records,
                         language_filter=language_code,
                         user=user)

@compliance_bp.route('/compliance-records/<int:record_id>')
@login_required
def compliance_record_detail(record_id):
    """View compliance record details"""
    user = current_user
    record = ComplianceRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Compliance record not found', 'error')
        return redirect(url_for('compliance.compliance_management'))
    
    # Get acknowledgments for this record
    acknowledgments = ComplianceAcknowledgment.query.filter_by(compliance_record_id=record_id).order_by(ComplianceAcknowledgment.created_at.desc()).all()
    
    return render_template('compliance/compliance_record_detail.html',
                         record=record,
                         acknowledgments=acknowledgments,
                         user=user)

@compliance_bp.route('/compliance-records/<int:record_id>/acknowledgments')
@login_required
def compliance_record_acknowledgments(record_id):
    """View acknowledgments for compliance record"""
    user = current_user
    record = ComplianceRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Compliance record not found', 'error')
        return redirect(url_for('compliance.compliance_management'))
    
    acknowledgments = ComplianceAcknowledgment.query.filter_by(compliance_record_id=record_id).order_by(ComplianceAcknowledgment.created_at.desc()).all()
    
    return render_template('compliance/compliance_acknowledgments.html',
                         record=record,
                         acknowledgments=acknowledgments,
                         user=user)

@compliance_bp.route('/acknowledge-compliance/<int:record_id>', methods=['POST'])
@login_required
def acknowledge_compliance(record_id):
    """Acknowledge compliance record"""
    user = current_user
    record = ComplianceRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Compliance record not found', 'error')
        return redirect(url_for('compliance.compliance_management'))
    
    try:
        # Check if user already acknowledged this record
        existing_ack = ComplianceAcknowledgment.query.filter_by(
            compliance_record_id=record_id,
            user_id=user.id
        ).first()
        
        if existing_ack:
            flash('You have already acknowledged this compliance record', 'warning')
            return redirect(url_for('compliance.compliance_record_detail', record_id=record_id))
        
        # Create acknowledgment
        acknowledgment = ComplianceAcknowledgment(
            compliance_record_id=record_id,
            user_id=user.id,
            user_name=user.username,
            user_email=user.email,
            acknowledgment_text=request.form.get('acknowledgment_text'),
            signature_data=request.form.get('signature_data'),
            organization_id=user.organization_id,
            created_at=datetime.now()
        )
        
        db.session.add(acknowledgment)
        
        # Update record status if needed
        total_acknowledgments = ComplianceAcknowledgment.query.filter_by(compliance_record_id=record_id).count() + 1
        if total_acknowledgments >= 1:  # Can be configured based on requirements
            record.status = 'acknowledged'
            record.acknowledged_at = datetime.now()
        
        db.session.commit()
        
        flash('Compliance record acknowledged successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error acknowledging compliance record: {str(e)}', 'error')
    
    return redirect(url_for('compliance.compliance_record_detail', record_id=record_id))

@compliance_bp.route('/compliance-storage')
@login_required
def compliance_storage():
    """Compliance storage and archived records"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Get all compliance records with acknowledgments
    records = ComplianceRecord.query.filter_by(organization_id=user.organization_id).order_by(ComplianceRecord.created_at.desc()).all()
    
    # Get acknowledgment counts for each record
    record_stats = {}
    for record in records:
        ack_count = ComplianceAcknowledgment.query.filter_by(compliance_record_id=record.id).count()
        record_stats[record.id] = {
            'acknowledgment_count': ack_count,
            'last_acknowledged': ComplianceAcknowledgment.query.filter_by(compliance_record_id=record.id).order_by(ComplianceAcknowledgment.created_at.desc()).first()
        }
    
    return render_template('compliance/compliance_storage.html',
                         records=records,
                         record_stats=record_stats,
                         user=user)

@compliance_bp.route('/update-compliance-record/<int:record_id>', methods=['POST'])
@login_required
@admin_required
def update_compliance_record(record_id):
    """Update compliance record"""
    user = current_user
    record = ComplianceRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Compliance record not found', 'error')
        return redirect(url_for('compliance.compliance_management'))
    
    try:
        record.title = request.form.get('title')
        record.description = request.form.get('description')
        record.category = request.form.get('category')
        record.priority = request.form.get('priority')
        record.status = request.form.get('status')
        record.updated_at = datetime.now()
        record.updated_by = user.id
        
        db.session.commit()
        flash('Compliance record updated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating compliance record: {str(e)}', 'error')
    
    return redirect(url_for('compliance.compliance_record_detail', record_id=record_id))