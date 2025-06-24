"""Room management routes for inspections and handovers"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_required
from datetime import datetime
from functools import wraps
from app_main import db
from models import RoomHandover, RoomInventoryChecklist, User, Organization
from app.models.models_house_acknowledge import RoomNumber

# Create Blueprint
room_bp = Blueprint('room', __name__)

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

@room_bp.route('/room-checklist')
@login_required
def room_checklist():
    """Room checklist dashboard"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    checklists = RoomInventoryChecklist.query.filter_by(organization_id=user.organization_id).order_by(RoomInventoryChecklist.created_at.desc()).all()
    return render_template('rooms/room_checklist.html', checklists=checklists, user=user)

@room_bp.route('/room-handovers')
@login_required
def room_handovers():
    """Room handover management"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    handovers = RoomHandover.query.filter_by(organization_id=user.organization_id).order_by(RoomHandover.created_at.desc()).all()
    return render_template('rooms/room_handovers.html', handovers=handovers, user=user)

@room_bp.route('/room-inventory')
@login_required
def room_inventory():
    """Room inventory management"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    inventory_records = RoomInventoryChecklist.query.filter_by(organization_id=user.organization_id).order_by(RoomInventoryChecklist.created_at.desc()).all()
    return render_template('rooms/room_inventory_records.html', inventory_records=inventory_records, user=user)

@room_bp.route('/room-numbers')
@login_required
@admin_required
def room_numbers():
    """Room number management"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    room_numbers = RoomNumber.query.filter_by(organization_id=user.organization_id).all()
    return render_template('rooms/room_numbers.html', room_numbers=room_numbers, user=user)

@room_bp.route('/create-room-inspection', methods=['GET', 'POST'])
@login_required
def create_room_inspection():
    """Create room inspection"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if request.method == 'POST':
        try:
            room_number = request.form.get('room_number')
            inspector_name = request.form.get('inspector_name')
            inspection_date = request.form.get('inspection_date')
            notes = request.form.get('notes')
            
            if not room_number or not inspector_name:
                flash('Room number and inspector name are required', 'error')
                return render_template('rooms/create_room_inspection.html', user=user)
            
            # Parse inspection date
            inspection_dt = datetime.strptime(inspection_date, '%Y-%m-%d') if inspection_date else datetime.now()
            
            checklist = RoomInventoryChecklist(
                room_number=room_number,
                inspector_name=inspector_name,
                inspection_date=inspection_dt,
                notes=notes,
                organization_id=user.organization_id,
                created_by=user.id,
                created_at=datetime.now()
            )
            
            db.session.add(checklist)
            db.session.commit()
            
            flash('Room inspection created successfully!', 'success')
            return redirect(url_for('room.room_checklist'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating inspection: {str(e)}', 'error')
    
    return render_template('rooms/create_room_inspection.html', user=user)

@room_bp.route('/edit-room-inspection/<int:inspection_id>', methods=['GET', 'POST'])
@login_required
def edit_room_inspection(inspection_id):
    """Edit room inspection"""
    user = current_user
    inspection = RoomInventoryChecklist.query.filter_by(id=inspection_id, organization_id=user.organization_id).first()
    
    if not inspection:
        flash('Inspection not found', 'error')
        return redirect(url_for('room.room_checklist'))
    
    if request.method == 'POST':
        try:
            inspection.room_number = request.form.get('room_number')
            inspection.inspector_name = request.form.get('inspector_name')
            
            inspection_date = request.form.get('inspection_date')
            if inspection_date:
                inspection.inspection_date = datetime.strptime(inspection_date, '%Y-%m-%d')
            
            inspection.notes = request.form.get('notes')
            
            db.session.commit()
            flash('Inspection updated successfully!', 'success')
            return redirect(url_for('room.room_checklist'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating inspection: {str(e)}', 'error')
    
    return render_template('rooms/edit_room_inspection.html', inspection=inspection, user=user)

@room_bp.route('/room-handover/<int:handover_id>')
@login_required
def view_room_handover(handover_id):
    """View room handover details"""
    user = current_user
    handover = RoomHandover.query.filter_by(id=handover_id, organization_id=user.organization_id).first()
    
    if not handover:
        flash('Handover not found', 'error')
        return redirect(url_for('room.room_handovers'))
    
    return render_template('rooms/room_handover_detail.html', handover=handover, user=user)

@room_bp.route('/create-room-handover', methods=['GET', 'POST'])
@login_required
def create_room_handover():
    """Create room handover"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if request.method == 'POST':
        try:
            room_number = request.form.get('room_number')
            outgoing_resident = request.form.get('outgoing_resident')
            incoming_resident = request.form.get('incoming_resident')
            handover_date = request.form.get('handover_date')
            notes = request.form.get('notes')
            
            if not room_number:
                flash('Room number is required', 'error')
                return render_template('rooms/create_room_handover.html', user=user)
            
            # Parse handover date
            handover_dt = datetime.strptime(handover_date, '%Y-%m-%d') if handover_date else datetime.now()
            
            handover = RoomHandover(
                room_number=room_number,
                outgoing_resident=outgoing_resident,
                incoming_resident=incoming_resident,
                handover_date=handover_dt,
                notes=notes,
                status='pending',
                organization_id=user.organization_id,
                created_by=user.id,
                created_at=datetime.now()
            )
            
            db.session.add(handover)
            db.session.commit()
            
            flash('Room handover created successfully!', 'success')
            return redirect(url_for('room.room_handovers'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating handover: {str(e)}', 'error')
    
    return render_template('rooms/create_room_handover.html', user=user)

@room_bp.route('/add-room-number', methods=['GET', 'POST'])
@login_required
@admin_required
def add_room_number():
    """Add new room number"""
    user = current_user
    if not user.organization_id:
        flash('Please contact administrator to assign organization', 'warning')
        return redirect(url_for('dashboard.dashboard'))
    
    if request.method == 'POST':
        try:
            room_number = request.form.get('room_number')
            building = request.form.get('building')
            floor = request.form.get('floor')
            capacity = request.form.get('capacity')
            
            if not room_number:
                flash('Room number is required', 'error')
                return render_template('rooms/add_room_number.html', user=user)
            
            # Check if room number already exists
            existing_room = RoomNumber.query.filter_by(
                room_number=room_number,
                organization_id=user.organization_id
            ).first()
            
            if existing_room:
                flash('Room number already exists', 'error')
                return render_template('rooms/add_room_number.html', user=user)
            
            room = RoomNumber(
                room_number=room_number,
                building=building,
                floor=int(floor) if floor else None,
                capacity=int(capacity) if capacity else None,
                organization_id=user.organization_id,
                created_at=datetime.now()
            )
            
            db.session.add(room)
            db.session.commit()
            
            flash(f'Room {room_number} added successfully!', 'success')
            return redirect(url_for('room.room_numbers'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding room: {str(e)}', 'error')
    
    return render_template('rooms/add_room_number.html', user=user)