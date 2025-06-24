from datetime import datetime
from timezone_utils import singapore_now
from app_main import db
from timezone_utils import singapore_now

class FoodLocker(db.Model):
    __tablename__ = 'food_lockers'
    id = db.Column(db.Integer, primary_key=True)
    
    # Company and Rental Information
    company_name = db.Column(db.String(100), nullable=False)
    rental_price = db.Column(db.Float, nullable=False)
    rental_start_date = db.Column(db.Date, nullable=False)
    rental_end_date = db.Column(db.Date)
    
    # Caterer Information
    caterer_name = db.Column(db.String(100), nullable=False)
    driver_name = db.Column(db.String(100), nullable=False)
    driver_phone = db.Column(db.String(20))  # Not compulsory
    vehicle_plate = db.Column(db.String(20), nullable=False)
    
    # Person in Charge (Tenant)
    person_in_charge_name = db.Column(db.String(100), nullable=False)
    person_in_charge_fin = db.Column(db.String(20), nullable=False)
    person_in_charge_phone = db.Column(db.String(20))
    person_in_charge_company = db.Column(db.String(100))
    
    # Signatures
    tenant_signature = db.Column(db.Text)  # E-Sign data for tenant
    tenant_signature_date = db.Column(db.DateTime)
    oe_dc_signature = db.Column(db.Text)  # E-Sign data for OE/DC
    oe_dc_signature_date = db.Column(db.DateTime)
    oe_dc_name = db.Column(db.String(100))
    
    # System Fields
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    status = db.Column(db.String(20), default='Active')  # Active, Inactive, Expired
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=datetime.now)
    
    # Relationships
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')
    room_assignments = db.relationship('FoodLockerRoomAssignment', back_populates='food_locker', cascade='all, delete-orphan')

class FoodLockerRoomAssignment(db.Model):
    __tablename__ = 'food_locker_room_assignments'
    id = db.Column(db.Integer, primary_key=True)
    
    food_locker_id = db.Column(db.Integer, db.ForeignKey('food_lockers.id'), nullable=False)
    room_number_id = db.Column(db.Integer, db.ForeignKey('room_numbers.id'), nullable=False)
    
    assigned_date = db.Column(db.Date, default=singapore_now().date)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    food_locker = db.relationship('FoodLocker', back_populates='room_assignments')
    room_number = db.relationship('RoomNumber')