"""Administrative routes for user and organization management"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from app_main import db
from models import User, Organization, ImportantNews
from werkzeug.security import generate_password_hash

# Create Blueprint
admin_bp = Blueprint('admin', __name__)

def is_admin_user(user):
    """Check if user is an admin"""
    if user.email == "pioneerlodge@tsgrp.sg":
        return True
    if hasattr(user, 'role') and user.role == 'admin':
        return True
    return False

# admin_required decorator is now imported from rbac_utils

@admin_bp.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard with system overview"""
    user = current_user
    
    # Get system statistics
    total_users = User.query.count()
    total_organizations = Organization.query.count()
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    # Get system news
    news_items = ImportantNews.query.order_by(ImportantNews.created_at.desc()).limit(5).all()
    
    return render_template('admin/admin.html',
                         user=user,
                         total_users=total_users,
                         total_organizations=total_organizations,
                         recent_users=recent_users,
                         news_items=news_items)

@admin_bp.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    """Add new user"""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            organization_id = request.form.get('organization_id')
            role = request.form.get('role', 'user')
            
            # Validation
            if not username or not email or not password:
                flash('Username, email, and password are required', 'error')
                return render_template('admin/admin_add_user.html',
                                     organizations=Organization.query.all())
            
            # Check if user already exists
            if User.query.filter_by(email=email).first():
                flash('User with this email already exists', 'error')
                return render_template('admin/admin_add_user.html',
                                     organizations=Organization.query.all())
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                organization_id=int(organization_id) if organization_id else None,
                role=role,
                created_at=datetime.now()
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'User "{username}" created successfully!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
    
    organizations = Organization.query.all()
    return render_template('admin/admin_add_user.html', organizations=organizations)

@admin_bp.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit existing user"""
    user_to_edit = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            user_to_edit.username = request.form.get('username')
            user_to_edit.email = request.form.get('email')
            
            # Update password if provided
            new_password = request.form.get('password')
            if new_password:
                user_to_edit.password_hash = generate_password_hash(new_password)
            
            # Update organization
            organization_id = request.form.get('organization_id')
            user_to_edit.organization_id = int(organization_id) if organization_id else None
            
            # Update role
            user_to_edit.role = request.form.get('role', 'user')
            
            db.session.commit()
            flash(f'User "{user_to_edit.username}" updated successfully!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')
    
    organizations = Organization.query.all()
    return render_template('admin/admin_edit_user.html',
                         user_to_edit=user_to_edit,
                         organizations=organizations)

@admin_bp.route('/admin/add-organization', methods=['GET', 'POST'])
@login_required
@admin_required
def add_organization():
    """Add new organization"""
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            
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

@admin_bp.route('/admin/edit-organization/<int:org_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_organization(org_id):
    """Edit existing organization"""
    organization = Organization.query.get_or_404(org_id)
    
    if request.method == 'POST':
        try:
            organization.name = request.form.get('name')
            organization.description = request.form.get('description')
            
            db.session.commit()
            flash(f'Organization "{organization.name}" updated successfully!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating organization: {str(e)}', 'error')
    
    return render_template('admin/admin_edit_org.html', organization=organization)

@admin_bp.route('/admin/important-news', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_important_news():
    """Manage important news items"""
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content = request.form.get('content')
            is_active = 'is_active' in request.form
            
            if not title or not content:
                flash('Title and content are required', 'error')
                return render_template('admin/admin_important_news.html',
                                     news_items=ImportantNews.query.order_by(ImportantNews.created_at.desc()).all())
            
            news_item = ImportantNews(
                title=title,
                content=content,
                is_active=is_active,
                created_by=current_user.id,
                created_at=datetime.now()
            )
            
            db.session.add(news_item)
            db.session.commit()
            
            flash('News item created successfully!', 'success')
            return redirect(url_for('admin.manage_important_news'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating news item: {str(e)}', 'error')
    
    news_items = ImportantNews.query.order_by(ImportantNews.created_at.desc()).all()
    return render_template('admin/admin_important_news.html', news_items=news_items)

@admin_bp.route('/admin/password-manager')
@login_required
@admin_required
def password_manager():
    """Password management interface"""
    users = User.query.all()
    return render_template('admin/admin_password_manager.html', users=users)