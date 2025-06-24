"""Offense records routes for violation tracking and management"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from io import BytesIO
import openpyxl
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors
from app_main import db
from models import User, Organization, OffenseRecord

# Create Blueprint
offense_bp = Blueprint('offense', __name__)

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

@offense_bp.route('/offense-records', methods=['GET', 'POST'])
@login_required
def offense_records():
    """Offense records management"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if request.method == 'POST':
        try:
            # Create new offense record
            resident_name = request.form.get('resident_name')
            room_number = request.form.get('room_number')
            offense_type = request.form.get('offense_type')
            description = request.form.get('description')
            fine_amount = request.form.get('fine_amount')
            officer_name = request.form.get('officer_name')
            
            if not resident_name or not offense_type:
                flash('Resident name and offense type are required', 'error')
                return redirect(url_for('offense.offense_records'))
            
            offense = OffenseRecord(
                resident_name=resident_name,
                room_number=room_number,
                offense_type=offense_type,
                description=description,
                fine_amount=float(fine_amount) if fine_amount else 0.0,
                officer_name=officer_name,
                status='pending',
                organization_id=user.organization_id,
                created_by=user.id,
                created_at=datetime.now()
            )
            
            db.session.add(offense)
            db.session.commit()
            
            flash('Offense record created successfully!', 'success')
            return redirect(url_for('offense.offense_records'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating offense record: {str(e)}', 'error')
    
    # Get offense records
    offenses = OffenseRecord.query.filter_by(organization_id=user.organization_id).order_by(OffenseRecord.created_at.desc()).all()
    
    return render_template('compliance/offense_records.html', offenses=offenses, user=user)

@offense_bp.route('/update-offense-status/<int:offense_id>', methods=['POST'])
@login_required
def update_offense_status(offense_id):
    """Update offense record status"""
    user = current_user
    offense = OffenseRecord.query.filter_by(id=offense_id, organization_id=user.organization_id).first()
    
    if not offense:
        flash('Offense record not found', 'error')
        return redirect(url_for('offense.offense_records'))
    
    try:
        new_status = request.form.get('status')
        if new_status in ['pending', 'resolved', 'dismissed']:
            offense.status = new_status
            offense.updated_at = datetime.now()
            offense.updated_by = user.id
            
            db.session.commit()
            flash('Status updated successfully!', 'success')
        else:
            flash('Invalid status', 'error')
            
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating status: {str(e)}', 'error')
    
    return redirect(url_for('offense.offense_records'))

@offense_bp.route('/update-offense-payment/<int:offense_id>', methods=['POST'])
@login_required
def update_offense_payment(offense_id):
    """Update offense payment status"""
    user = current_user
    offense = OffenseRecord.query.filter_by(id=offense_id, organization_id=user.organization_id).first()
    
    if not offense:
        flash('Offense record not found', 'error')
        return redirect(url_for('offense.offense_records'))
    
    try:
        payment_status = request.form.get('payment_status')
        payment_date = request.form.get('payment_date')
        
        if payment_status in ['paid', 'unpaid', 'waived']:
            offense.payment_status = payment_status
            if payment_date:
                offense.payment_date = datetime.strptime(payment_date, '%Y-%m-%d')
            offense.updated_at = datetime.now()
            offense.updated_by = user.id
            
            db.session.commit()
            flash('Payment status updated successfully!', 'success')
        else:
            flash('Invalid payment status', 'error')
            
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating payment: {str(e)}', 'error')
    
    return redirect(url_for('offense.offense_records'))

@offense_bp.route('/update-offense-record/<int:offense_id>', methods=['POST'])
@login_required
def update_offense_record(offense_id):
    """Update offense record details"""
    user = current_user
    offense = OffenseRecord.query.filter_by(id=offense_id, organization_id=user.organization_id).first()
    
    if not offense:
        flash('Offense record not found', 'error')
        return redirect(url_for('offense.offense_records'))
    
    try:
        offense.resident_name = request.form.get('resident_name')
        offense.room_number = request.form.get('room_number')
        offense.offense_type = request.form.get('offense_type')
        offense.description = request.form.get('description')
        
        fine_amount = request.form.get('fine_amount')
        if fine_amount:
            offense.fine_amount = float(fine_amount)
        
        offense.officer_name = request.form.get('officer_name')
        offense.updated_at = datetime.now()
        offense.updated_by = user.id
        
        db.session.commit()
        flash('Offense record updated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating record: {str(e)}', 'error')
    
    return redirect(url_for('offense.offense_records'))

@offense_bp.route('/download-offense-pdf/<int:offense_id>')
@login_required
def download_offense_pdf(offense_id):
    """Generate and download PDF for offense record"""
    user = current_user
    offense = OffenseRecord.query.filter_by(id=offense_id, organization_id=user.organization_id).first()
    
    if not offense:
        flash('Offense record not found', 'error')
        return redirect(url_for('offense.offense_records'))
    
    try:
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph("OFFENSE RECORD", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 0.2*inch))
        
        # Record details
        details = [
            ['Record ID:', str(offense.id)],
            ['Resident Name:', offense.resident_name],
            ['Room Number:', offense.room_number or 'N/A'],
            ['Offense Type:', offense.offense_type],
            ['Description:', offense.description or 'N/A'],
            ['Fine Amount:', f'${offense.fine_amount:.2f}' if offense.fine_amount else 'N/A'],
            ['Officer:', offense.officer_name or 'N/A'],
            ['Status:', offense.status],
            ['Payment Status:', getattr(offense, 'payment_status', 'N/A')],
            ['Date Created:', offense.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        table = Table(details, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(table)
        doc.build(story)
        
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'offense_record_{offense.id}.pdf'
        )
        
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('offense.offense_records'))

@offense_bp.route('/bulk-update-offense-status', methods=['POST'])
@login_required
@admin_required
def bulk_update_offense_status():
    """Bulk update offense record statuses"""
    user = current_user
    
    try:
        offense_ids = request.form.getlist('offense_ids')
        new_status = request.form.get('bulk_status')
        
        if not offense_ids or not new_status:
            flash('Please select records and status', 'error')
            return redirect(url_for('offense.offense_records'))
        
        updated_count = 0
        for offense_id in offense_ids:
            offense = OffenseRecord.query.filter_by(id=offense_id, organization_id=user.organization_id).first()
            if offense:
                offense.status = new_status
                offense.updated_at = datetime.now()
                offense.updated_by = user.id
                updated_count += 1
        
        db.session.commit()
        flash(f'Updated {updated_count} offense records!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating records: {str(e)}', 'error')
    
    return redirect(url_for('offense.offense_records'))

@offense_bp.route('/export-offense-table-excel')
@login_required
def export_offense_table_excel():
    """Export offense records to Excel"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        # Create workbook
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Offense Records"
        
        # Headers
        headers = ['ID', 'Resident Name', 'Room Number', 'Offense Type', 'Description', 'Fine Amount', 'Officer', 'Status', 'Payment Status', 'Date Created']
        ws.append(headers)
        
        # Get records
        offenses = OffenseRecord.query.filter_by(organization_id=user.organization_id).all()
        
        for offense in offenses:
            ws.append([
                offense.id,
                offense.resident_name,
                offense.room_number or '',
                offense.offense_type,
                offense.description or '',
                offense.fine_amount or 0,
                offense.officer_name or '',
                offense.status,
                getattr(offense, 'payment_status', ''),
                offense.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # Save to BytesIO
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'offense_records_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )
        
    except Exception as e:
        flash(f'Error exporting records: {str(e)}', 'error')
        return redirect(url_for('offense.offense_records'))

@offense_bp.route('/offense-record/<int:record_id>/details')
@login_required
def offense_record_details(record_id):
    """View detailed offense record"""
    user = current_user
    offense = OffenseRecord.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not offense:
        flash('Offense record not found', 'error')
        return redirect(url_for('offense.offense_records'))
    
    return render_template('compliance/offense_record_detail.html', offense=offense, user=user)