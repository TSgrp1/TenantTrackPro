"""Resident management routes for checkout and visitor tracking"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from io import BytesIO
import openpyxl
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors
from app_main import db
from models import User, Organization, Visitor
from app.models.models_resident_checkout import ResidentCheckout

# Create Blueprint
resident_bp = Blueprint('resident', __name__)

def is_admin_user(user):
    """Check if user is an admin"""
    if user.email == "pioneerlodge@tsgrp.sg":
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

@resident_bp.route('/resident-checkin-checkout-dashboard')
@login_required
def resident_checkin_checkout_dashboard():
    """Resident check-in/checkout dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Get recent checkout records
    recent_checkouts = ResidentCheckout.query.filter_by(organization_id=user.organization_id).order_by(ResidentCheckout.created_at.desc()).limit(10).all()
    
    # Get statistics
    total_checkouts = ResidentCheckout.query.filter_by(organization_id=user.organization_id).count()
    active_checkouts = ResidentCheckout.query.filter_by(organization_id=user.organization_id, status='checked_out').count()
    
    return render_template('residents/resident_checkin_checkout_dashboard.html',
                         recent_checkouts=recent_checkouts,
                         total_checkouts=total_checkouts,
                         active_checkouts=active_checkouts,
                         user=user)

@resident_bp.route('/resident-checkout-qr')
@login_required
def resident_checkout_qr():
    """Generate QR code for resident checkout"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Generate QR code URL
    qr_url = url_for('resident.resident_checkout_scan', _external=True)
    
    return render_template('residents/resident_checkout_qr.html',
                         qr_url=qr_url,
                         user=user)

@resident_bp.route('/resident-checkout-scan')
@login_required
def resident_checkout_scan():
    """Resident checkout scan form"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    return render_template('residents/resident_checkout_scan.html', user=user)

@resident_bp.route('/resident-checkout-submit', methods=['POST'])
@login_required
def resident_checkout_submit():
    """Process resident checkout submission"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        resident_name = request.form.get('resident_name')
        room_number = request.form.get('room_number')
        contact_number = request.form.get('contact_number')
        checkout_reason = request.form.get('checkout_reason')
        expected_return = request.form.get('expected_return')
        emergency_contact = request.form.get('emergency_contact')
        notes = request.form.get('notes')
        
        if not resident_name or not room_number:
            flash('Resident name and room number are required', 'error')
            return redirect(url_for('resident.resident_checkout_scan'))
        
        # Parse expected return date if provided
        expected_return_dt = None
        if expected_return:
            try:
                expected_return_dt = datetime.strptime(expected_return, '%Y-%m-%d')
            except ValueError:
                flash('Invalid expected return date format', 'error')
                return redirect(url_for('resident.resident_checkout_scan'))
        
        # Create checkout record
        checkout = ResidentCheckout(
            resident_name=resident_name,
            room_number=room_number,
            contact_number=contact_number,
            checkout_reason=checkout_reason,
            expected_return_date=expected_return_dt,
            emergency_contact=emergency_contact,
            notes=notes,
            status='checked_out',
            checkout_time=datetime.now(),
            organization_id=user.organization_id,
            created_by=user.id,
            created_at=datetime.now()
        )
        
        db.session.add(checkout)
        db.session.commit()
        
        flash('Resident checkout recorded successfully!', 'success')
        return render_template('residents/resident_checkout_success.html',
                             checkout=checkout,
                             user=user)
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing checkout: {str(e)}', 'error')
        return redirect(url_for('resident.resident_checkout_scan'))

@resident_bp.route('/resident-checkout-records')
@login_required
def resident_checkout_records():
    """View resident checkout records"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    records = ResidentCheckout.query.filter_by(organization_id=user.organization_id).order_by(ResidentCheckout.created_at.desc()).all()
    return render_template('residents/resident_checkout_records.html', records=records, user=user)

@resident_bp.route('/resident-checkout-delete', methods=['POST'])
@login_required
@admin_required
def resident_checkout_delete():
    """Delete resident checkout record"""
    user = current_user
    record_id = request.form.get('record_id')
    
    if not record_id:
        flash('Record ID is required', 'error')
        return redirect(url_for('resident.resident_checkout_records'))
    
    record = ResidentCheckout.query.filter_by(id=record_id, organization_id=user.organization_id).first()
    
    if not record:
        flash('Checkout record not found', 'error')
        return redirect(url_for('resident.resident_checkout_records'))
    
    try:
        db.session.delete(record)
        db.session.commit()
        flash('Checkout record deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting record: {str(e)}', 'error')
    
    return redirect(url_for('resident.resident_checkout_records'))

@resident_bp.route('/resident-checkout-export-excel', methods=['POST'])
@login_required
def resident_checkout_export_excel():
    """Export resident checkout records to Excel"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        # Create workbook
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Resident Checkouts"
        
        # Headers
        headers = ['ID', 'Resident Name', 'Room Number', 'Contact Number', 'Checkout Reason', 'Checkout Time', 'Expected Return', 'Status', 'Notes']
        ws.append(headers)
        
        # Get records
        records = ResidentCheckout.query.filter_by(organization_id=user.organization_id).all()
        
        for record in records:
            ws.append([
                record.id,
                record.resident_name,
                record.room_number,
                record.contact_number or '',
                record.checkout_reason or '',
                record.checkout_time.strftime('%Y-%m-%d %H:%M:%S') if record.checkout_time else '',
                record.expected_return_date.strftime('%Y-%m-%d') if record.expected_return_date else '',
                record.status,
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
            download_name=f'resident_checkouts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )
        
    except Exception as e:
        flash(f'Error exporting records: {str(e)}', 'error')
        return redirect(url_for('resident.resident_checkout_records'))

@resident_bp.route('/resident-checkout-export-pdf', methods=['GET', 'POST'])
@login_required
def resident_checkout_export_pdf():
    """Export resident checkout records to PDF"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph("RESIDENT CHECKOUT RECORDS", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 0.2*inch))
        
        # Get records
        records = ResidentCheckout.query.filter_by(organization_id=user.organization_id).order_by(ResidentCheckout.created_at.desc()).all()
        
        if records:
            # Create table data
            table_data = [['Resident', 'Room', 'Checkout Time', 'Status', 'Expected Return']]
            
            for record in records:
                table_data.append([
                    record.resident_name,
                    record.room_number,
                    record.checkout_time.strftime('%Y-%m-%d %H:%M') if record.checkout_time else '',
                    record.status,
                    record.expected_return_date.strftime('%Y-%m-%d') if record.expected_return_date else 'N/A'
                ])
            
            # Create table
            table = Table(table_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
        else:
            story.append(Paragraph("No checkout records found.", styles['Normal']))
        
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'resident_checkouts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('resident.resident_checkout_records'))

@resident_bp.route('/visitors')
@login_required
def visitors():
    """Visitor management dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    visitors = Visitor.query.filter_by(organization_id=user.organization_id).order_by(Visitor.created_at.desc()).all()
    
    return render_template('residents/visitors.html', visitors=visitors, user=user)

@resident_bp.route('/visitors-qr-codes')
@login_required
def visitors_qr_codes():
    """Generate QR codes for visitor management"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Generate QR code URL
    qr_url = url_for('resident.visitors_scan', _external=True)
    
    return render_template('residents/visitors_qr_codes.html',
                         qr_url=qr_url,
                         user=user)

@resident_bp.route('/visitors-scan')
def visitors_scan():
    """Visitor registration scan form (public access)"""
    return render_template('residents/visitors_scan.html')

@resident_bp.route('/visitors-scan', methods=['POST'])
def visitors_scan_submit():
    """Process visitor registration"""
    try:
        visitor_name = request.form.get('visitor_name')
        contact_number = request.form.get('contact_number')
        visiting_resident = request.form.get('visiting_resident')
        room_number = request.form.get('room_number')
        purpose = request.form.get('purpose')
        id_number = request.form.get('id_number')
        
        if not visitor_name or not visiting_resident:
            flash('Visitor name and visiting resident are required', 'error')
            return redirect(url_for('resident.visitors_scan'))
        
        # Default organization for visitor registration (can be configured)
        organization_id = 1  # This should be configurable
        
        visitor = Visitor(
            visitor_name=visitor_name,
            contact_number=contact_number,
            visiting_resident=visiting_resident,
            room_number=room_number,
            purpose=purpose,
            id_number=id_number,
            visit_time=datetime.now(),
            status='checked_in',
            organization_id=organization_id,
            created_at=datetime.now()
        )
        
        db.session.add(visitor)
        db.session.commit()
        
        return render_template('residents/visitors_success.html', visitor=visitor)
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error registering visitor: {str(e)}', 'error')
        return redirect(url_for('resident.visitors_scan'))

@resident_bp.route('/visitors-records')
@login_required
def visitors_records():
    """View visitor records"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    records = Visitor.query.filter_by(organization_id=user.organization_id).order_by(Visitor.created_at.desc()).all()
    return render_template('residents/visitors_records.html', records=records, user=user)