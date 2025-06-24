"""Jinja2 global functions and template utilities"""
from flask import current_app
from models import User, Organization, Asset, AssetCategory, RoomHandover, OffenseRecord, QRCode, FormSubmission

def is_admin_user(user):
    """Check if user is an admin (Pioneer Lodge admin or has admin role)"""
    if not user:
        return False
    if user.email == "pioneerlodge@tsgrp.sg":
        return True
    if hasattr(user, 'role') and user.role == 'admin':
        return True
    return False

def get_user_dashboard_permissions(user):
    """Get dashboard-specific permissions for a user"""
    if not user:
        return {}
        
    if is_admin_user(user):
        return {
            'can_view_admin_section': True,
            'can_manage_users': True,
            'can_manage_organizations': True,
            'can_view_all_data': True,
            'can_create_qr_codes': True,
            'can_manage_forms': True,
            'can_view_reports': True,
            'can_manage_assets': True,
            'can_manage_rooms': True,
            'can_view_offense_records': True,
            'can_manage_staff_attendance': True,
            'can_view_resident_data': True,
            'can_manage_purchase_requests': True,
            'can_view_submissions': True,
            'can_manage_meter_readings': True,
            'can_view_analytics': True
        }
    
    # Default permissions for regular users
    return {
        'can_view_admin_section': False,
        'can_manage_users': False,
        'can_manage_organizations': False,
        'can_view_all_data': False,
        'can_create_qr_codes': False,
        'can_manage_forms': False,
        'can_view_reports': False,
        'can_manage_assets': False,
        'can_manage_rooms': False,
        'can_view_offense_records': False,
        'can_manage_staff_attendance': False,
        'can_view_resident_data': False,
        'can_manage_purchase_requests': False,
        'can_view_submissions': False,
        'can_manage_meter_readings': False,
        'can_view_analytics': False
    }

def get_user_page_permissions(user, page_name):
    """Get specific page permissions for a user"""
    if not user:
        return {'can_view': False, 'can_create': False, 'can_edit': False, 'can_delete': False}
        
    if is_admin_user(user):
        return {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': True}
    
    # Default permissions for specific pages
    page_permissions = {
        'dashboard': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'staff_attendance': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'pioneer_lodge_visitors': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'resident_checkin': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'house_acknowledge': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'submissions': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'purchase': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'asset_management': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'stock_report': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'food_locker': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'room_checklist': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'resident_checkout': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'offense_records': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'fin_search': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'qr_codes': {'can_view': True, 'can_create': False, 'can_edit': False, 'can_delete': False},
        'msrf_management': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'bedding_management': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'key_management': {'can_view': True, 'can_create': True, 'can_edit': True, 'can_delete': False},
        'settings': {'can_view': True, 'can_create': False, 'can_edit': True, 'can_delete': False}
    }
    
    return page_permissions.get(page_name, {'can_view': False, 'can_create': False, 'can_edit': False, 'can_delete': False})

def get_available_pages():
    """Get all available pages in the system"""
    return {
        'dashboard': {'name': 'Dashboard', 'icon': 'fas fa-tachometer-alt', 'description': 'Main dashboard and overview'},
        'staff_attendance': {'name': 'Staff Attendance', 'icon': 'fas fa-user-clock', 'description': 'Staff attendance tracking'},
        'pioneer_lodge_visitors': {'name': 'Pioneer Lodge Visitors', 'icon': 'fas fa-users', 'description': 'Visitor management system'},
        'resident_checkin': {'name': 'Resident Check-in', 'icon': 'fas fa-user-check', 'description': 'Resident check-in management'},
        'house_acknowledge': {'name': 'House Acknowledge', 'icon': 'fas fa-home', 'description': 'House acknowledgment forms'},
        'submissions': {'name': 'Submissions', 'icon': 'fas fa-file-alt', 'description': 'Form submissions and data'},
        'purchase': {'name': 'Purchase', 'icon': 'fas fa-shopping-cart', 'description': 'Purchase forms, stock storage, and form management'},
        'asset_management': {'name': 'Asset Management', 'icon': 'fas fa-boxes', 'description': 'Inventory and asset tracking'},
        'stock_report': {'name': 'Stock Report', 'icon': 'fas fa-warehouse', 'description': 'Stock and inventory reports'},
        'food_locker': {'name': 'Food Locker Management', 'icon': 'fas fa-utensils', 'description': 'Food locker rental management'},
        'room_checklist': {'name': 'Room Checklist', 'icon': 'fas fa-clipboard-check', 'description': 'Room inspection and maintenance'},
        'key_management': {'name': 'Key Management', 'icon': 'fas fa-key', 'description': 'Key tracking and checkout management'},
        'resident_checkout': {'name': 'Resident Check-Out', 'icon': 'fas fa-sign-out-alt', 'description': 'Resident check-out scanning and management'},
        'offense_records': {'name': 'Offense Records', 'icon': 'fas fa-exclamation-triangle', 'description': 'Disciplinary record management'},
        'fin_search': {'name': 'FIN Search', 'icon': 'fas fa-search', 'description': 'FIN number search functionality'},
        'qr_codes': {'name': 'QR Codes', 'icon': 'fas fa-qrcode', 'description': 'QR code management and generation'},
        'msrf_management': {'name': 'MSRF Management', 'icon': 'fas fa-clipboard-list', 'description': 'MSRF request management'},
        'bedding_management': {'name': 'Bedding Management', 'icon': 'fas fa-bed', 'description': 'Bedding items and inventory'},
        'key_management': {'name': 'Key Management', 'icon': 'fas fa-key', 'description': 'Key tracking and QR code management'},
        'settings': {'name': 'Settings', 'icon': 'fas fa-cog', 'description': 'System settings and configuration'},
        'admin': {'name': 'Admin Dashboard', 'icon': 'fas fa-user-shield', 'description': 'Complete system administration'}
    }

def can_user_create(user, page_name):
    """Check if user can create items on a specific page"""
    if not user:
        return False
    
    # Admin always has full permissions
    if is_admin_user(user):
        return True
    
    permissions = get_user_page_permissions(user, page_name)
    return permissions.get('can_create', False)

def can_user_edit(user, page_name):
    """Check if user can edit items on a specific page"""
    if not user:
        return False
    
    # Admin always has full permissions
    if is_admin_user(user):
        return True
    
    permissions = get_user_page_permissions(user, page_name)
    return permissions.get('can_edit', False)

def can_user_view(user, page_name):
    """Check if user can view a specific page"""
    if not user:
        return False
    
    # Admin always has full permissions
    if is_admin_user(user):
        return True
    
    permissions = get_user_page_permissions(user, page_name)
    return permissions.get('can_view', False)

def from_json_filter(value):
    """Parse JSON string to Python object"""
    import json
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value

def nl2br_filter(value):
    """Convert newlines to HTML line breaks"""
    import re
    if value:
        return re.sub(r'\n', '<br>', str(value))
    return value

def register_jinja_globals(app):
    """Register all Jinja2 global functions and filters"""
    # Global functions
    app.jinja_env.globals.update(
        is_admin_user=is_admin_user,
        get_user_dashboard_permissions=get_user_dashboard_permissions,
        get_user_page_permissions=get_user_page_permissions,
        get_available_pages=get_available_pages,
        can_user_create=can_user_create,
        can_user_edit=can_user_edit,
        can_user_view=can_user_view
    )
    
    # Custom filters
    app.jinja_env.filters['from_json'] = from_json_filter
    app.jinja_env.filters['nl2br'] = nl2br_filter