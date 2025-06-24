"""Organization management routes for settings and configuration"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from app_main import db
from models import User, Organization

# Create Blueprint
org_bp = Blueprint('org', __name__)

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

@org_bp.route('/select-organization')
@login_required
def select_organization():
    """Allow user to select organization"""
    organizations = Organization.query.all()
    return render_template('admin/select_organization.html', organizations=organizations)

@org_bp.route('/assign-organization', methods=['POST'])
@login_required
@admin_required
def assign_organization():
    """Assign organization to user"""
    user = current_user
    org_id = int(request.form['organization_id'])
    
    organization = Organization.query.get(org_id)
    if organization:
        user.organization_id = org_id
        db.session.commit()
        flash(f'Successfully assigned to {organization.name}', 'success')
    else:
        flash('Invalid organization selected', 'error')
    
    return redirect(url_for('dashboard.dashboard'))

@org_bp.route('/admin/organizations/<int:org_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_organization_admin(org_id):
    """Admin edit organization (detailed)"""
    organization = Organization.query.get_or_404(org_id)
    
    if request.method == 'POST':
        try:
            organization.name = request.form.get('name')
            organization.description = request.form.get('description')
            organization.address = request.form.get('address')
            organization.contact_email = request.form.get('contact_email')
            organization.contact_phone = request.form.get('contact_phone')
            organization.settings = request.form.get('settings', '{}')
            organization.updated_at = datetime.now()
            
            db.session.commit()
            flash(f'Organization "{organization.name}" updated successfully!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating organization: {str(e)}', 'error')
    
    return render_template('admin/admin_edit_org.html', organization=organization)

@org_bp.route('/admin/organizations/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_organization_admin():
    """Admin add new organization"""
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            address = request.form.get('address')
            contact_email = request.form.get('contact_email')
            contact_phone = request.form.get('contact_phone')
            
            if not name:
                flash('Organization name is required', 'error')
                return render_template('admin/admin_add_org.html')
            
            # Check if organization already exists
            if Organization.query.filter_by(name=name).first():
                flash('Organization with this name already exists', 'error')
                return render_template('admin/admin_add_org.html')
            
            new_org = Organization(
                name=name,
                description=description,
                address=address,
                contact_email=contact_email,
                contact_phone=contact_phone,
                settings='{}',
                created_at=datetime.now()
            )
            
            db.session.add(new_org)
            db.session.commit()
            
            flash(f'Organization "{name}" created successfully!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating organization: {str(e)}', 'error')
    
    return render_template('admin/admin_add_org.html')

@org_bp.route('/admin/organizations/<int:org_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_organization_admin(org_id):
    """Admin delete organization"""
    organization = Organization.query.get_or_404(org_id)
    
    # Check if organization has users
    user_count = User.query.filter_by(organization_id=org_id).count()
    if user_count > 0:
        flash(f'Cannot delete organization. It has {user_count} users assigned.', 'error')
        return redirect(url_for('admin.admin_dashboard'))
    
    try:
        org_name = organization.name
        db.session.delete(organization)
        db.session.commit()
        
        flash(f'Organization "{org_name}" deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting organization: {str(e)}', 'error')
    
    return redirect(url_for('admin.admin_dashboard'))

@org_bp.route('/organization-settings')
@login_required
def organization_settings():
    """Organization settings for current user's organization"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    organization = Organization.query.get(user.organization_id)
    if not organization:
        flash('Organization not found', 'error')
        return redirect(url_for('dashboard.dashboard'))
    
    return render_template('admin/organization_settings.html', organization=organization, user=user)

@org_bp.route('/organization-settings/update', methods=['POST'])
@login_required
@admin_required
def update_organization_settings():
    """Update organization settings"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    organization = Organization.query.get(user.organization_id)
    if not organization:
        flash('Organization not found', 'error')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        # Update basic info if admin
        if is_admin_user(user):
            organization.name = request.form.get('name')
            organization.description = request.form.get('description')
            organization.address = request.form.get('address')
            organization.contact_email = request.form.get('contact_email')
            organization.contact_phone = request.form.get('contact_phone')
        
        # Update settings
        import json
        settings = {}
        try:
            if organization.settings:
                settings = json.loads(organization.settings)
        except:
            settings = {}
        
        # Update specific settings from form
        settings.update({
            'timezone': request.form.get('timezone', 'UTC'),
            'language': request.form.get('language', 'english'),
            'currency': request.form.get('currency', 'SGD'),
            'date_format': request.form.get('date_format', 'YYYY-MM-DD'),
        })
        
        organization.settings = json.dumps(settings)
        organization.updated_at = datetime.now()
        
        db.session.commit()
        flash('Organization settings updated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating settings: {str(e)}', 'error')
    
    return redirect(url_for('org.organization_settings'))

@org_bp.route('/api/organizations/<int:org_id>/info')
@login_required
@admin_required
def get_organization_info(org_id):
    """Get organization info via API"""
    organization = Organization.query.get_or_404(org_id)
    
    return jsonify({
        'id': organization.id,
        'name': organization.name,
        'description': organization.description,
        'address': organization.address,
        'contact_email': organization.contact_email,
        'contact_phone': organization.contact_phone,
        'created_at': organization.created_at.isoformat() if organization.created_at else None,
        'user_count': User.query.filter_by(organization_id=org_id).count()
    })