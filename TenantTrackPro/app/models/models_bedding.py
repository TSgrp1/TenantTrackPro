from datetime import datetime
from timezone_utils import singapore_now
from app_main import db
from timezone_utils import singapore_now

class BeddingCategory(db.Model):
    __tablename__ = 'bedding_categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Bed, Pillow, Mattress, Blanket, etc.
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=datetime.now)
    
    # Relationships
    organization = db.relationship('Organization')
    items = db.relationship('BeddingItem', back_populates='category', cascade='all, delete-orphan')

class BeddingItem(db.Model):
    __tablename__ = 'bedding_items'
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), nullable=False, unique=True)
    item_name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('bedding_categories.id'), nullable=False)
    
    # Location and Assignment
    status = db.Column(db.String(20), nullable=False, default='In Store')  # In Store, In Room, Damaged, Others
    room_number = db.Column(db.String(20))  # Current room assignment
    resident_name = db.Column(db.String(100))  # Current resident
    company_name = db.Column(db.String(100))  # Resident's company
    
    # Item Details
    brand = db.Column(db.String(100))
    model = db.Column(db.String(100))
    purchase_date = db.Column(db.Date)
    purchase_price = db.Column(db.Float)
    condition = db.Column(db.String(20), default='Good')  # Excellent, Good, Fair, Poor
    warranty_expiry = db.Column(db.Date)
    
    # Status Details
    description = db.Column(db.Text)  # Additional details, especially for 'Others' status
    last_maintenance_date = db.Column(db.Date)
    next_maintenance_date = db.Column(db.Date)
    
    # System Fields
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=datetime.now)
    
    # Relationships
    category = db.relationship('BeddingCategory', back_populates='items')
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')
    movements = db.relationship('BeddingMovement', back_populates='item', cascade='all, delete-orphan')

class BeddingMovement(db.Model):
    __tablename__ = 'bedding_movements'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('bedding_items.id'), nullable=False)
    
    # Movement Details
    movement_type = db.Column(db.String(50), nullable=False)  # Assignment, Return, Transfer, Maintenance, Disposal
    from_status = db.Column(db.String(20))  # Previous status
    to_status = db.Column(db.String(20), nullable=False)  # New status
    from_room = db.Column(db.String(20))  # Previous room
    to_room = db.Column(db.String(20))  # New room
    from_resident = db.Column(db.String(100))  # Previous resident
    to_resident = db.Column(db.String(100))  # New resident
    
    # Documentation
    reason = db.Column(db.String(200))  # Reason for movement
    notes = db.Column(db.Text)  # Additional notes
    movement_date = db.Column(db.DateTime, nullable=False, default=singapore_now)
    
    # System Fields
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    processed_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    item = db.relationship('BeddingItem', back_populates='movements')
    organization = db.relationship('Organization')
    processed_by_user = db.relationship('User')