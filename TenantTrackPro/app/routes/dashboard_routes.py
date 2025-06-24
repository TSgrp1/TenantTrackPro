"""Dashboard and main page routes"""
from flask import Blueprint, render_template, redirect, url_for, session
from flask_login import current_user, login_required
from app_main import db
from models import User, Organization, Asset, AssetCategory, RoomHandover, OffenseRecord, QRCode, FormSubmission, SystemLog, ImportantNews
from app.models.models_house_acknowledge import HouseAcknowledgment

# Create Blueprint
dashboard_bp = Blueprint('dashboard', __name__)

# Permission checking functions (copied from routes.py)
def is_admin_user(user):
    """Check if user is an admin (Pioneer Lodge admin or has admin role)"""
    if user.role == 'admin':
        return True
    
    # Check if user has admin role
    if hasattr(user, 'role') and user.role == 'admin':
        return True
    
    return False

def get_user_dashboard_permissions(user):
    """Get dashboard-specific permissions for a user"""
    if is_admin_user(user):
        return {
            'can_view_admin_section': True,
            'can_manage_users': True,
            'can_manage_organizations': True,
            'can_view_all_data': True,
            'can_view_assets': True,
            'can_view_room_checklist': True,
            'can_view_offense_records': True,
            'can_view_qr_codes': True,
            'can_view_submissions': True,
            'can_view_purchase': True,
            'can_view_asset_management': True,
            'can_view_stock_report': True,
            'can_view_food_locker': True,
            'can_view_house_acknowledge': True,
            'can_view_staff_attendance': True,
            'can_view_pioneer_lodge_visitors': True,
            'can_view_resident_checkin': True,
            'can_view_resident_checkout': True,
            'can_view_fin_search': True,
            'can_view_msrf': True,
            'can_view_bedding': True,
            'can_view_key_management': True,
            'allowed_form_types': ['handover', 'offense', 'stock', 'purchase', 'house_acknowledge', 'staff_attendance', 'visitors', 'resident_checkin', 'resident_checkout', 'msrf', 'bedding', 'key_management']
        }
    
    # Default permissions for non-admin users
    return {
        'can_view_admin_section': False,
        'can_manage_users': False,
        'can_manage_organizations': False,
        'can_view_all_data': False,
        'can_view_assets': True,
        'can_view_room_checklist': True,
        'can_view_offense_records': True,
        'can_view_qr_codes': True,
        'can_view_submissions': True,
        'can_view_purchase': True,
        'can_view_asset_management': True,
        'can_view_stock_report': True,
        'can_view_food_locker': True,
        'can_view_house_acknowledge': True,
        'can_view_staff_attendance': False,
        'can_view_pioneer_lodge_visitors': False,
        'can_view_resident_checkin': False,
        'can_view_resident_checkout': False,
        'can_view_fin_search': False,
        'can_view_msrf': False,
        'can_view_bedding': False,
        'can_view_key_management': False,
        'allowed_form_types': ['handover', 'offense', 'stock', 'purchase', 'house_acknowledge']
    }

def get_user_page_permissions(user):
    """Get detailed page permissions for a user"""
    if is_admin_user(user):
        # Admin users have full access to all pages
        return {
            'dashboard': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'staff_attendance': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'pioneer_lodge_visitors': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'resident_checkin': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'house_acknowledge': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'submissions': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'purchase': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'asset_management': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'stock_report': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'food_locker': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'room_checklist': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'resident_checkout': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'offense_records': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'fin_search': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'qr_codes': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'msrf_management': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'bedding_management': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'key_management': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'settings': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
            'admin': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True}
        }
    
    # Default permissions for regular users
    return {
        'dashboard': {'can_access': True, 'can_view': True, 'can_edit': False, 'can_create': False},
        'house_acknowledge': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
        'submissions': {'can_access': True, 'can_view': True, 'can_edit': False, 'can_create': False},
        'purchase': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
        'asset_management': {'can_access': True, 'can_view': True, 'can_edit': False, 'can_create': False},
        'stock_report': {'can_access': True, 'can_view': True, 'can_edit': False, 'can_create': False},
        'food_locker': {'can_access': True, 'can_view': True, 'can_edit': False, 'can_create': False},
        'room_checklist': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
        'offense_records': {'can_access': True, 'can_view': True, 'can_edit': True, 'can_create': True},
        'qr_codes': {'can_access': True, 'can_view': True, 'can_edit': False, 'can_create': False}
    }

@dashboard_bp.route('/')
@login_required
def index():
    """Redirect to dashboard"""
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with statistics"""
    user = current_user
    
    # Redirect limited users directly to their allowed page
    if not is_admin_user(user):
        user_permissions = get_user_dashboard_permissions(user)
        if 'handover' in user_permissions['allowed_form_types'] and len(user_permissions['allowed_form_types']) == 1:
            return redirect(url_for('room_checklist'))
    
    # Get or assign organization
    if not user.organization_id:
        # For demo purposes, assign based on email domain or ask user to choose
        if user.email and 'pioneerlodge' in user.email.lower():
            org = Organization.query.filter_by(name="Pioneer Lodge").first()
            if org:
                user.organization_id = org.id
        elif user.email and 'tuasview' in user.email.lower():
            org = Organization.query.filter_by(name="Tuas View Dormitory").first()
            if org:
                user.organization_id = org.id
        else:
            # Default to Pioneer Lodge or create one if it doesn't exist
            org = Organization.query.filter_by(name="Pioneer Lodge").first()
            if not org:
                org = Organization(name="Pioneer Lodge")
                db.session.add(org)
                db.session.commit()
            user.organization_id = org.id
        db.session.commit()

    # Get dashboard statistics
    total_assets = Asset.query.filter_by(organization_id=user.organization_id).count()
    active_assets = Asset.query.filter_by(organization_id=user.organization_id, status='Active').count()
    
    total_handovers = RoomHandover.query.filter_by(organization_id=user.organization_id).count()
    pending_handovers = RoomHandover.query.filter_by(organization_id=user.organization_id, status='Pending').count()
    
    total_offenses = OffenseRecord.query.filter_by(organization_id=user.organization_id).count()
    open_offenses = OffenseRecord.query.filter_by(organization_id=user.organization_id, status='Open').count()
    
    total_forms = FormSubmission.query.filter_by(organization_id=user.organization_id).count()
    house_acknowledgment_count = HouseAcknowledgment.query.filter_by(organization_id=user.organization_id).count()
    
    total_qr_codes = QRCode.query.filter_by(organization_id=user.organization_id).count()
    active_qr_codes = QRCode.query.filter_by(organization_id=user.organization_id, is_active=True).count()
    
    # Get asset status distribution
    status_counts = {}
    for status in ['Active', 'Inactive', 'Room', 'Store', 'Clear', 'Other']:
        count = Asset.query.filter_by(organization_id=user.organization_id, status=status).count()
        status_counts[status] = count
    
    # Get recent activities
    recent_assets = Asset.query.filter_by(organization_id=user.organization_id).order_by(Asset.created_at.desc()).limit(5).all()
    recent_handovers = RoomHandover.query.filter_by(organization_id=user.organization_id).order_by(RoomHandover.created_at.desc()).limit(5).all()
    recent_offenses = OffenseRecord.query.filter_by(organization_id=user.organization_id).order_by(OffenseRecord.created_at.desc()).limit(5).all()
    
    # Get important news
    important_news = ImportantNews.query.filter_by(organization_id=user.organization_id, is_published=True).order_by(ImportantNews.created_at.desc()).limit(3).all()
    
    # Get user permissions for dashboard display
    user_permissions = get_user_dashboard_permissions(user)
    
    # Get page permissions for navigation
    page_permissions = get_user_page_permissions(user)
    
    return render_template('dashboard/index.html', 
                         user=user,
                         user_permissions=user_permissions,
                         page_permissions=page_permissions,
                         total_assets=total_assets,
                         active_assets=active_assets,
                         total_handovers=total_handovers,
                         pending_handovers=pending_handovers,
                         total_offenses=total_offenses,
                         open_offenses=open_offenses,
                         total_forms=total_forms,
                         house_acknowledgment_count=house_acknowledgment_count,
                         total_qr_codes=total_qr_codes,
                         active_qr_codes=active_qr_codes,
                         status_counts=status_counts,
                         recent_assets=recent_assets,
                         recent_handovers=recent_handovers,
                         recent_offenses=recent_offenses,
                         important_news=important_news)