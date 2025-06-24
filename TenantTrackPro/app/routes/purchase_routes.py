"""Purchase form related routes"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response
from flask_login import current_user, login_required
from datetime import datetime, date
from io import BytesIO
import json
from app_main import db
from models import PurchaseRequest, PurchaseRequestItem, User, Organization
from timezone_utils import singapore_now, format_singapore_datetime
from functools import wraps

# Create Blueprint
purchase_bp = Blueprint('purchase', __name__)

# Permission functions
def is_admin_user(user):
    """Check if user is an admin"""
    if user.role == 'admin':
        return True
    if hasattr(user, 'role') and user.role == 'admin':
        return True
    return False

def edit_permission_required(page_name):
    """Decorator to require edit permissions for a specific page"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('other.login'))
            # For now, allow authenticated users to access purchase forms
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@purchase_bp.route('/purchase-form')
@login_required
def purchase_form():
    """Display purchase request form"""
    user = current_user
    
    # Get or assign organization if needed
    if not user.organization_id:
        org = Organization.query.filter_by(name="Pioneer Lodge").first()
        if not org:
            org = Organization(name="Pioneer Lodge")
            db.session.add(org)
            db.session.commit()
        user.organization_id = org.id
        db.session.commit()
    
    return render_template('purchase/form.html', user=user)

@purchase_bp.route('/download-purchase-form-pdf', methods=['POST'])
@login_required
def download_purchase_form_pdf():
    """Generate and download purchase form PDF"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        # Get form data
        form_data = request.get_json() or {}
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, 
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        # Build PDF content
        story = []
        
        # Title
        story.append(Paragraph("Purchase Request Form", title_style))
        story.append(Spacer(1, 20))
        
        # Basic info table
        basic_data = [
            ['Requested By:', form_data.get('requestedBy', '')],
            ['Department:', form_data.get('department', '')],
            ['Date:', form_data.get('date', '')],
            ['Priority:', form_data.get('priority', 'Normal')]
        ]
        
        basic_table = Table(basic_data, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(basic_table)
        story.append(Spacer(1, 20))
        
        # Items table
        items = form_data.get('items', [])
        if items:
            story.append(Paragraph("Requested Items:", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            item_data = [['#', 'Description', 'Quantity', 'Unit Price', 'Total']]
            
            total_amount = 0
            for i, item in enumerate(items, 1):
                qty = float(item.get('quantity', 0))
                price = float(item.get('unitPrice', 0))
                item_total = qty * price
                total_amount += item_total
                
                item_data.append([
                    str(i),
                    item.get('description', ''),
                    str(qty),
                    f"${price:.2f}",
                    f"${item_total:.2f}"
                ])
            
            # Add total row
            item_data.append(['', '', '', 'TOTAL:', f"${total_amount:.2f}"])
            
            items_table = Table(item_data, colWidths=[0.5*inch, 3*inch, 1*inch, 1*inch, 1*inch])
            items_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('ALIGN', (1, 1), (1, -2), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey)
            ]))
            
            story.append(items_table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"purchase_request_{timestamp}.pdf"
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('purchase.purchase_form'))

@purchase_bp.route('/purchase-form-storage')
@login_required
def purchase_form_storage():
    """Display stored purchase requests"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    # Get all purchase requests for this organization
    requests = PurchaseRequest.query.filter_by(
        organization_id=user.organization_id
    ).order_by(PurchaseRequest.created_at.desc()).all()
    
    return render_template('purchase/storage.html', requests=requests)

@purchase_bp.route('/submit-purchase-form', methods=['POST'])
@login_required
def submit_purchase_form():
    """Submit a new purchase request"""
    user = current_user
    if not user.organization_id:
        return jsonify({'success': False, 'error': 'Organization not assigned'})
    
    try:
        # Get form data
        data = request.get_json()
        
        # Create purchase request
        purchase_request = PurchaseRequest(
            requested_by=data.get('requestedBy', ''),
            department=data.get('department', ''),
            priority=data.get('priority', 'Normal'),
            notes=data.get('notes', ''),
            organization_id=user.organization_id,
            user_id=user.id,
            status='Pending'
        )
        
        db.session.add(purchase_request)
        db.session.flush()  # Get the ID
        
        # Add items
        items = data.get('items', [])
        total_amount = 0
        
        for item_data in items:
            quantity = float(item_data.get('quantity', 0))
            unit_price = float(item_data.get('unitPrice', 0))
            
            item = PurchaseRequestItem(
                purchase_request_id=purchase_request.id,
                description=item_data.get('description', ''),
                quantity=quantity,
                unit_price=unit_price,
                total_price=quantity * unit_price
            )
            
            total_amount += item.total_price
            db.session.add(item)
        
        # Update total amount
        purchase_request.total_amount = total_amount
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Purchase request submitted successfully',
            'request_id': purchase_request.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@purchase_bp.route('/download-purchase-pdf/<int:request_id>')
@login_required
def download_purchase_pdf(request_id):
    """Download PDF for a specific purchase request"""
    user = current_user
    
    purchase_request = PurchaseRequest.query.filter_by(
        id=request_id,
        organization_id=user.organization_id
    ).first_or_404()
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        story = []
        
        # Title
        story.append(Paragraph("Purchase Request", title_style))
        story.append(Spacer(1, 20))
        
        # Request details
        details_data = [
            ['Request ID:', str(purchase_request.id)],
            ['Requested By:', purchase_request.requested_by],
            ['Department:', purchase_request.department],
            ['Date:', purchase_request.created_at.strftime('%Y-%m-%d')],
            ['Priority:', purchase_request.priority],
            ['Status:', purchase_request.status]
        ]
        
        details_table = Table(details_data, colWidths=[2*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(details_table)
        story.append(Spacer(1, 20))
        
        # Items
        if purchase_request.items:
            story.append(Paragraph("Items:", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            item_data = [['Description', 'Quantity', 'Unit Price', 'Total']]
            
            for item in purchase_request.items:
                item_data.append([
                    item.description,
                    str(item.quantity),
                    f"${item.unit_price:.2f}",
                    f"${item.total_price:.2f}"
                ])
            
            # Total row
            item_data.append(['TOTAL', '', '', f"${purchase_request.total_amount:.2f}"])
            
            items_table = Table(item_data, colWidths=[3*inch, 1*inch, 1*inch, 1*inch])
            items_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey)
            ]))
            
            story.append(items_table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        filename = f"purchase_request_{purchase_request.id}.pdf"
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('purchase.purchase_form_storage'))