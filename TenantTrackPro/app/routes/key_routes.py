"""Key management routes for key tracking and QR codes"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from io import BytesIO
import openpyxl
from app_main import db
from models import User, Organization
from app.models.models_key_management import KeyRecord
import qrcode

# Create Blueprint
key_bp = Blueprint('key', __name__)

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

@key_bp.route('/key-management')
@login_required
def key_management():
    """Key management dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Get key records for the user's organization
    key_records = KeyRecord.query.filter_by(organization_id=user.organization_id).order_by(KeyRecord.created_at.desc()).all()
    
    # Get statistics
    total_keys = len(key_records)
    checked_out_keys = len([k for k in key_records if k.status == 'checked_out'])
    available_keys = len([k for k in key_records if k.status == 'available'])
    
    return render_template('forms/key_management_dashboard.html',
                         key_records=key_records,
                         total_keys=total_keys,
                         checked_out_keys=checked_out_keys,
                         available_keys=available_keys,
                         user=user)

@key_bp.route('/key-management/qr-codes')
@login_required
def key_management_qr_codes():
    """Generate QR codes for key management"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Generate QR code for key scanning
    qr_url = url_for('key.key_scan_form', scan_type='checkout', _external=True)
    
    return render_template('forms/key_management_qr_codes.html',
                         qr_url=qr_url,
                         user=user)

@key_bp.route('/key-management/scan/<scan_type>')
@login_required
def key_scan_form(scan_type):
    """Key scan form for checkout/checkin"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if scan_type not in ['checkout', 'checkin']:
        flash('Invalid scan type', 'error')
        return redirect(url_for('key.key_management'))
    
    return render_template('forms/key_scan_form.html',
                         scan_type=scan_type,
                         user=user)

@key_bp.route('/key-management/scan/<scan_type>', methods=['POST'])
@login_required
def process_key_scan(scan_type):
    """Process key scan for checkout/checkin"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        key_number = request.form.get('key_number')
        person_name = request.form.get('person_name')
        room_number = request.form.get('room_number')
        notes = request.form.get('notes')
        
        if not key_number or not person_name:
            flash('Key number and person name are required', 'error')
            return redirect(url_for('key.key_scan_form', scan_type=scan_type))
        
        # Create or update key record
        key_record = KeyRecord.query.filter_by(
            key_number=key_number,
            organization_id=user.organization_id
        ).first()
        
        if not key_record:
            key_record = KeyRecord(
                key_number=key_number,
                organization_id=user.organization_id
            )
            db.session.add(key_record)
        
        # Update record based on scan type
        if scan_type == 'checkout':
            key_record.status = 'checked_out'
            key_record.checked_out_to = person_name
            key_record.checkout_time = datetime.now()
            key_record.room_number = room_number
        else:  # checkin
            key_record.status = 'available'
            key_record.checkin_time = datetime.now()
            key_record.last_checked_out_to = key_record.checked_out_to
            key_record.checked_out_to = None
        
        key_record.notes = notes
        key_record.last_updated = datetime.now()
        key_record.updated_by = user.id
        
        db.session.commit()
        
        flash(f'Key {key_number} {scan_type} processed successfully!', 'success')
        return render_template('forms/key_scan_success.html',
                             scan_type=scan_type,
                             key_number=key_number,
                             person_name=person_name,
                             user=user)
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing key {scan_type}: {str(e)}', 'error')
        return redirect(url_for('key.key_scan_form', scan_type=scan_type))

@key_bp.route('/key-management/records')
@login_required
def key_records():
    """View key management records"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    records = KeyRecord.query.filter_by(organization_id=user.organization_id).order_by(KeyRecord.last_updated.desc()).all()
    return render_template('forms/key_management_records.html', records=records, user=user)

@key_bp.route('/key-management/edit/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_key_record(record_id):
    """Edit key management record"""
    user = current_user
    record = KeyRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Key record not found', 'error')
        return redirect(url_for('key.key_records'))
    
    if request.method == 'POST':
        try:
            record.key_number = request.form.get('key_number')
            record.checked_out_to = request.form.get('checked_out_to')
            record.room_number = request.form.get('room_number')
            record.status = request.form.get('status')
            record.notes = request.form.get('notes')
            record.last_updated = datetime.now()
            record.updated_by = user.id
            
            db.session.commit()
            flash('Key record updated successfully!', 'success')
            return redirect(url_for('key.key_records'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating record: {str(e)}', 'error')
    
    return render_template('forms/edit_key_record.html', record=record, user=user)

@key_bp.route('/key-management/delete', methods=['POST'])
@login_required
@admin_required
def delete_key_record():
    """Delete key management record"""
    user = current_user
    record_id = request.form.get('record_id')
    
    if not record_id:
        flash('Record ID is required', 'error')
        return redirect(url_for('key.key_records'))
    
    record = KeyRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Key record not found', 'error')
        return redirect(url_for('key.key_records'))
    
    try:
        db.session.delete(record)
        db.session.commit()
        flash('Key record deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting record: {str(e)}', 'error')
    
    return redirect(url_for('key.key_records'))

@key_bp.route('/key-management/export/<export_type>')
@login_required
def export_key_records(export_type):
    """Export key management records"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if export_type == 'excel':
        try:
            # Create workbook
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Key Records"
            
            # Headers
            headers = ['Key Number', 'Status', 'Checked Out To', 'Room Number', 'Checkout Time', 'Checkin Time', 'Notes']
            ws.append(headers)
            
            # Get records
            records = KeyRecord.query.filter_by(organization_id=user.organization_id).all()
            
            for record in records:
                ws.append([
                    record.key_number,
                    record.status,
                    record.checked_out_to or '',
                    record.room_number or '',
                    record.checkout_time.strftime('%Y-%m-%d %H:%M:%S') if record.checkout_time else '',
                    record.checkin_time.strftime('%Y-%m-%d %H:%M:%S') if record.checkin_time else '',
                    record.notes or ''
                ])
            
            # Save to BytesIO
            output = BytesIO()
            wb.save(output)
            output.seek(0)
            
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'key_records_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
            )
            
        except Exception as e:
            flash(f'Error exporting records: {str(e)}', 'error')
            return redirect(url_for('key.key_records'))
    
    flash('Invalid export type', 'error')
    return redirect(url_for('key.key_records'))