from datetime import datetime
from app_main import db
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint, Index
from timezone_utils import singapore_now
from timezone_utils import singapore_now

# (IMPORTANT) This table is mandatory for Replit Auth, don't drop it.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=True)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    profile_image_url = db.Column(db.String, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)  # Add password hash field
    admin_viewable_password = db.Column(db.String(256), nullable=True)  # Admin-accessible password storage
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    
    # Additional fields for better user management
    username = db.Column(db.String(50), nullable=True)  # For login and display
    full_name = db.Column(db.String(100), nullable=True)  # Display name for header
    role = db.Column(db.String(20), default='user')  # 'admin', 'user', 'manager'
    is_user_active = db.Column(db.Boolean, default=True)  # Renamed to avoid UserMixin conflict
    is_admin = db.Column(db.Boolean, default=False)  # Admin access flag
    
    # Page access permissions - JSON field to store accessible pages
    page_permissions = db.Column(db.Text, nullable=True)  # JSON string of accessible pages
    access_level = db.Column(db.String(20), default='full')  # 'full', 'view_only', 'restricted'

    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)

    # Relationship
    organization = db.relationship('Organization', back_populates='users')
    assets = db.relationship('Asset', back_populates='created_by_user')
    form_permissions = db.relationship('UserFormPermission', back_populates='user', cascade='all, delete-orphan')

# (IMPORTANT) This table is mandatory for Replit Auth, don't drop it.
class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.String, db.ForeignKey(User.id))
    browser_session_key = db.Column(db.String, nullable=False)
    user = db.relationship(User)

    __table_args__ = (UniqueConstraint(
        'user_id',
        'browser_session_key',
        'provider',
        name='uq_user_browser_session_key_provider',
    ),)

class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=True, unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    users = db.relationship('User', back_populates='organization')
    assets = db.relationship('Asset', back_populates='organization')

class AssetCategory(db.Model):
    __tablename__ = 'asset_categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    assets = db.relationship('Asset', back_populates='category')

class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('asset_categories.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='Active')  # Active, Inactive, Room, Store, Clear, Other
    location = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    purchase_date = db.Column(db.Date)
    purchase_cost = db.Column(db.Float)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    category = db.relationship('AssetCategory', back_populates='assets')
    organization = db.relationship('Organization', back_populates='assets')
    created_by_user = db.relationship('User', back_populates='assets')

class FormTemplate(db.Model):
    __tablename__ = 'form_templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    form_type = db.Column(db.String(50), nullable=False)  # regulations, handover, offense, inspection, etc.
    
    # Multilingual content
    regulations_text = db.Column(db.Text)  # Main regulations/instructions text
    language_code = db.Column(db.String(10), default='en')  # Language code (en, bn, my, ta, zh)
    
    # Form fields configuration
    fields_json = db.Column(db.Text)  # JSON string of form fields
    
    # Reference photos (stored as base64)
    ref_photo_1 = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_2 = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_3 = db.Column(db.Text)  # Base64 encoded image data
    
    # Language-specific reference photos (15 total: 3 per language for 5 languages)
    # English reference photos
    ref_photo_1_en = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_2_en = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_3_en = db.Column(db.Text)  # Base64 encoded image data
    
    # Bengali reference photos
    ref_photo_1_bn = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_2_bn = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_3_bn = db.Column(db.Text)  # Base64 encoded image data
    
    # Myanmar reference photos
    ref_photo_1_my = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_2_my = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_3_my = db.Column(db.Text)  # Base64 encoded image data
    
    # Tamil reference photos
    ref_photo_1_ta = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_2_ta = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_3_ta = db.Column(db.Text)  # Base64 encoded image data
    
    # Chinese reference photos
    ref_photo_1_zh = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_2_zh = db.Column(db.Text)  # Base64 encoded image data
    ref_photo_3_zh = db.Column(db.Text)  # Base64 encoded image data
    
    # QR Code integration
    qr_code_id = db.Column(db.Integer, db.ForeignKey('qr_codes.id'))
    public_access = db.Column(db.Boolean, default=True)  # Allow access via QR without login
    
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')
    qr_code = db.relationship('QRCode')
    form_submissions = db.relationship('FormSubmission', back_populates='form_template')
    user_permissions = db.relationship('UserFormPermission', back_populates='form_template', cascade='all, delete-orphan')

class RoomHandover(db.Model):
    __tablename__ = 'room_handovers'
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(20), nullable=False)
    block = db.Column(db.String(10))
    floor = db.Column(db.String(5))
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    previous_occupant = db.Column(db.String(100))
    new_occupant = db.Column(db.String(100))
    handover_date = db.Column(db.Date, nullable=False)
    handover_time = db.Column(db.Time)
    condition_before = db.Column(db.Text)
    condition_after = db.Column(db.Text)
    damages_noted = db.Column(db.Text)
    repairs_needed = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')  # Pending, Completed, Inspection Required
    conducted_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    conducted_by_user = db.relationship('User')

class OffenseRecord(db.Model):
    __tablename__ = 'offense_records'
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50))  # Case No field
    offense_type = db.Column(db.String(50), nullable=False)  # Disciplinary, Safety, Cleanliness, etc.
    severity = db.Column(db.String(20), nullable=False)  # Minor, Major, Critical
    
    # Resident Details
    offender_name = db.Column(db.String(100), nullable=False)
    fin_number = db.Column(db.String(20))  # FIN no
    nationality = db.Column(db.String(50))  # Nationality
    offender_room = db.Column(db.String(20))  # Room no
    sector = db.Column(db.String(50))  # Sector
    contact_number = db.Column(db.String(20))  # Contact no
    offender_company = db.Column(db.String(100))  # Company Name
    
    # Incident Details
    description = db.Column(db.Text, nullable=False)  # Description of Contravention
    location = db.Column(db.String(100))
    incident_date = db.Column(db.Date, nullable=False)
    incident_time = db.Column(db.Time)
    
    # Documentary Evidence
    documentary_proof = db.Column(db.Boolean, default=False)  # Documentary proof: YES/NO
    proof_description = db.Column(db.Text)  # Description of proof (e.g., photographs, CCTV footage)
    
    # Incident Photos (Base64 encoded image data, up to 10 photos)
    incident_photo_1 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_2 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_3 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_4 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_5 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_6 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_7 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_8 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_9 = db.Column(db.Text)  # Base64 encoded image data
    incident_photo_10 = db.Column(db.Text)  # Base64 encoded image data
    
    # Financial Penalty
    financial_penalty_imposed = db.Column(db.Boolean, default=False)  # Financial Penalty Imposed: YES/NO
    penalty_amount = db.Column(db.Float)  # AMOUNT S$
    penalty_status = db.Column(db.String(20), default='Pending')  # Pending, Paid, Partially Paid
    amount_paid = db.Column(db.Float, default=0.0)  # Amount already paid
    payment_date = db.Column(db.DateTime)  # Date when payment was made
    
    # Signatures and Management
    resident_signature = db.Column(db.Text)  # E-Sign data for resident
    resident_signature_date = db.Column(db.DateTime)
    duty_manager_signature = db.Column(db.Text)  # E-Sign data for OE/DC
    duty_manager_signature_date = db.Column(db.DateTime)
    duty_manager_name = db.Column(db.String(100))  # Name of duty manager
    
    # System Fields
    reported_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    witness_names = db.Column(db.Text)
    action_taken = db.Column(db.Text)  # Immediate Action Taken
    status = db.Column(db.String(20), default='Open')  # Open, Under Investigation, Resolved, Closed
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    reported_by_user = db.relationship('User')

class QRCode(db.Model):
    __tablename__ = 'qr_codes'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(100), unique=True, nullable=False)
    qr_type = db.Column(db.String(30), nullable=False)  # asset, room, location, form, url
    reference_id = db.Column(db.String(50))  # ID of the related item
    reference_table = db.Column(db.String(50))  # Table name for the reference
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    label = db.Column(db.String(100))
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    scan_count = db.Column(db.Integer, default=0)
    last_scanned = db.Column(db.DateTime)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # URL and expiry functionality
    target_url = db.Column(db.Text)  # Custom URL for direct linking
    expires_at = db.Column(db.DateTime)  # Expiry date for the QR code
    max_scans = db.Column(db.Integer)  # Maximum number of scans allowed
    is_public = db.Column(db.Boolean, default=True)  # Public access without login
    
    # Relationships
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')
    
    @property
    def is_expired(self):
        """Check if QR code has expired"""
        if self.expires_at:
            return singapore_now() > self.expires_at
        return False
    
    @property
    def is_scan_limit_reached(self):
        """Check if scan limit has been reached"""
        if self.max_scans:
            return self.scan_count >= self.max_scans
        return False
    
    @property
    def is_accessible(self):
        """Check if QR code is currently accessible"""
        return self.is_active and not self.is_expired and not self.is_scan_limit_reached

class FormSubmission(db.Model):
    __tablename__ = 'form_submissions'
    id = db.Column(db.Integer, primary_key=True)
    form_template_id = db.Column(db.Integer, db.ForeignKey('form_templates.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    submitted_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    form_data_json = db.Column(db.Text, nullable=False)  # JSON string of submitted data
    status = db.Column(db.String(20), default='Submitted')  # Submitted, Under Review, Approved, Rejected
    reviewed_by = db.Column(db.String, db.ForeignKey('users.id'))
    review_notes = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=singapore_now)
    reviewed_at = db.Column(db.DateTime)
    
    # Relationships
    form_template = db.relationship('FormTemplate', back_populates='form_submissions')
    organization = db.relationship('Organization')
    submitted_by_user = db.relationship('User', foreign_keys=[submitted_by])
    reviewed_by_user = db.relationship('User', foreign_keys=[reviewed_by])

class RoomInventoryChecklist(db.Model):
    __tablename__ = 'room_inventory_checklists'
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(20), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    checklist_date = db.Column(db.Date, nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    
    # Meter readings
    water_meter_reading = db.Column(db.String(50))
    water_meter_signature = db.Column(db.Text)
    water_meter_datetime = db.Column(db.DateTime)
    electricity_meter_reading = db.Column(db.String(50))
    electricity_meter_signature = db.Column(db.Text)
    electricity_meter_datetime = db.Column(db.DateTime)
    
    # Handover signatures data (JSON)
    handover_signature_data = db.Column(db.Text)  # JSON string with signature info
    takeover_signature_data = db.Column(db.Text)  # JSON string with signature info
    
    # Checklist items data (JSON)
    checklist_items_data = db.Column(db.Text)  # JSON string of all checklist items
    
    status = db.Column(db.String(20), default='Completed')  # Completed, Under Review, Approved
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)

    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')

class Submission(db.Model):
    __tablename__ = 'submissions'
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    submission_type = db.Column(db.String(50), nullable=False)  # asset_created, handover_completed, offense_reported, etc.
    reference_id = db.Column(db.Integer)  # ID of the related record
    reference_table = db.Column(db.String(50))  # Table name for reference
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    user = db.relationship('User')

class UserFormPermission(db.Model):
    __tablename__ = 'user_form_permissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    form_template_id = db.Column(db.Integer, db.ForeignKey('form_templates.id'), nullable=False)
    can_create = db.Column(db.Boolean, default=True)
    can_view = db.Column(db.Boolean, default=True)
    can_generate_qr = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    user = db.relationship('User', back_populates='form_permissions')
    form_template = db.relationship('FormTemplate', back_populates='user_permissions')
    
    # Unique constraint to prevent duplicate permissions
    __table_args__ = (UniqueConstraint('user_id', 'form_template_id', name='unique_user_form_permission'),)

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=True)
    user_email = db.Column(db.String(120), nullable=True)  # For cases where user is deleted
    action = db.Column(db.String(500), nullable=False)
    module = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Success')  # Success, Failed, Warning
    ip_address = db.Column(db.String(45))  # Support IPv6
    user_agent = db.Column(db.Text)
    details = db.Column(db.Text)  # Additional details in JSON format
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    user = db.relationship('User')

class StockItem(db.Model):
    __tablename__ = 'stock_items'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    used_quantity = db.Column(db.Integer, default=0)  # Track used quantity
    status = db.Column(db.String(20), default='received')  # received, unreceived
    location = db.Column(db.String(100))
    room_no = db.Column(db.String(20))
    purchase_date = db.Column(db.Date)
    purchase_cost = db.Column(db.Float)
    serial_number = db.Column(db.String(100))
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)

    # Relationships
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')

class StockMovement(db.Model):
    __tablename__ = 'stock_movements'
    id = db.Column(db.Integer, primary_key=True)
    stock_item_id = db.Column(db.Integer, db.ForeignKey('stock_items.id'), nullable=False)
    movement_type = db.Column(db.String(20), nullable=False)  # IN, OUT, ADJUST, TRANSFER
    quantity = db.Column(db.Integer, nullable=False)
    previous_quantity = db.Column(db.Integer, nullable=False)
    new_quantity = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(200))
    notes = db.Column(db.Text)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)

    # Relationships
    stock_item = db.relationship('StockItem')
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')

class PurchaseRequest(db.Model):
    __tablename__ = 'purchase_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    request_number = db.Column(db.String(50), unique=True, nullable=False)
    pl_number = db.Column(db.String(50))
    request_date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    requested_by = db.Column(db.String(100), nullable=False)
    dc_name = db.Column(db.String(100))
    operation_manager = db.Column(db.String(100))
    general_manager = db.Column(db.String(100))
    requested_by_footer = db.Column(db.String(100))
    recommended_by_footer = db.Column(db.String(100))
    
    # Additional Information Fields
    supplier = db.Column(db.String(200))
    department = db.Column(db.String(100))
    priority = db.Column(db.String(50))
    payment_method = db.Column(db.String(100))
    budget_code = db.Column(db.String(100))
    expected_delivery = db.Column(db.Date)
    justification = db.Column(db.Text)
    
    # Signature Fields - stored as JSON data like room checklist
    dc_signature_data = db.Column(db.Text)  # JSON string with signature info
    operation_manager_signature_data = db.Column(db.Text)  # JSON string with signature info
    general_manager_signature_data = db.Column(db.Text)  # JSON string with signature info
    
    # Financial fields for totals
    subtotal = db.Column(db.Numeric(10, 2), default=0.00)
    other_label = db.Column(db.String(50))  # Tax, Shipping, etc.
    other_amount = db.Column(db.Numeric(10, 2), default=0.00)
    grand_total = db.Column(db.Numeric(10, 2), default=0.00)
    
    status = db.Column(db.String(20), default='Pending')
    approval_status = db.Column(db.String(20), default='Pending')
    approved_by = db.Column(db.String, db.ForeignKey('users.id'))
    approved_date = db.Column(db.DateTime)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)

    # Relationships
    items = db.relationship('PurchaseRequestItem', backref='purchase_request', cascade='all, delete-orphan')
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User', foreign_keys=[created_by])
    approved_by_user = db.relationship('User', foreign_keys=[approved_by])

class PurchaseRequestItem(db.Model):
    __tablename__ = 'purchase_request_items'
    
    id = db.Column(db.Integer, primary_key=True)
    purchase_request_id = db.Column(db.Integer, db.ForeignKey('purchase_requests.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    unit_cost = db.Column(db.Numeric(10, 2), default=0)
    quantity = db.Column(db.Integer, nullable=False)
    total_cost = db.Column(db.Numeric(10, 2), default=0)
    room_no = db.Column(db.String(50))
    unit = db.Column(db.String(50))
    cost_code = db.Column(db.String(50))
    remarks = db.Column(db.Text)
    approved_quantity = db.Column(db.Integer)
    received_quantity = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=singapore_now)

class StockUsage(db.Model):
    __tablename__ = 'stock_usage'
    id = db.Column(db.Integer, primary_key=True)
    stock_item_id = db.Column(db.Integer, db.ForeignKey('stock_items.id'), nullable=False)
    item_name = db.Column(db.String(200), nullable=False)
    used_quantity = db.Column(db.Integer, nullable=False)
    available_quantity = db.Column(db.Integer, nullable=False)
    usage_date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    stock_item = db.relationship('StockItem')
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')

class ImportantNews(db.Model):
    __tablename__ = 'important_news'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    content_type = db.Column(db.String(20), default='text')  # text, html
    priority = db.Column(db.String(20), default='normal')  # high, normal, low
    is_active = db.Column(db.Boolean, default=True)
    show_on_login = db.Column(db.Boolean, default=True)
    pdf_attachment = db.Column(db.String(255))  # File path for PDF
    image_attachment = db.Column(db.String(255))  # File path for image
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    expires_at = db.Column(db.DateTime)  # Optional expiry date
    
    # Relationships
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User')

# Enhanced Multilingual Compliance Records System
class ComplianceRecord(db.Model):
    __tablename__ = 'compliance_records'
    
    id = db.Column(db.Integer, primary_key=True)
    record_number = db.Column(db.String(50), unique=True, nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    record_type = db.Column(db.String(50), nullable=False)
    compliance_category = db.Column(db.String(100), nullable=False)
    priority_level = db.Column(db.String(20), default='Medium')
    
    language_code = db.Column(db.String(10), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    detailed_instructions = db.Column(db.Text)
    
    content_type = db.Column(db.String(20), default='text')
    content_text = db.Column(db.Text)
    content_file_data = db.Column(db.Text)
    content_file_name = db.Column(db.String(255))
    content_file_type = db.Column(db.String(50))
    
    ref_photo_1 = db.Column(db.Text)
    ref_photo_1_caption = db.Column(db.String(255))
    ref_photo_2 = db.Column(db.Text)
    ref_photo_2_caption = db.Column(db.String(255))
    ref_photo_3 = db.Column(db.Text)
    ref_photo_3_caption = db.Column(db.String(255))
    
    effective_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date)
    version_number = db.Column(db.String(20), default='1.0')
    status = db.Column(db.String(20), default='Active')
    
    requires_acknowledgment = db.Column(db.Boolean, default=True)
    acknowledgment_deadline = db.Column(db.Date)
    
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    approved_by = db.Column(db.String, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    approved_at = db.Column(db.DateTime)
    
    organization = db.relationship('Organization')
    compliance_created_by = db.relationship('User', foreign_keys=[created_by])
    compliance_approved_by = db.relationship('User', foreign_keys=[approved_by])

class ComplianceAcknowledgment(db.Model):
    __tablename__ = 'compliance_acknowledgments'
    
    id = db.Column(db.Integer, primary_key=True)
    compliance_record_id = db.Column(db.Integer, db.ForeignKey('compliance_records.id'), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    acknowledged_at = db.Column(db.DateTime, default=singapore_now)
    acknowledgment_method = db.Column(db.String(50), default='digital')
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    language_code = db.Column(db.String(10), nullable=False)
    notes = db.Column(db.Text)
    signature_data = db.Column(db.Text)
    
    compliance_record = db.relationship('ComplianceRecord')
    ack_user = db.relationship('User')
    ack_organization = db.relationship('Organization')

class ComplianceViolation(db.Model):
    __tablename__ = 'compliance_violations'
    
    id = db.Column(db.Integer, primary_key=True)
    violation_number = db.Column(db.String(50), unique=True, nullable=False)
    compliance_record_id = db.Column(db.Integer, db.ForeignKey('compliance_records.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    violator_name = db.Column(db.String(100), nullable=False)
    violator_id = db.Column(db.String(50))
    violator_contact = db.Column(db.String(100))
    violator_room = db.Column(db.String(20))
    violator_company = db.Column(db.String(100))
    
    violation_date = db.Column(db.Date, nullable=False)
    violation_time = db.Column(db.Time)
    violation_location = db.Column(db.String(100))
    severity_level = db.Column(db.String(20), nullable=False)
    
    description_en = db.Column(db.Text)
    description_bn = db.Column(db.Text)
    description_my = db.Column(db.Text)
    description_ta = db.Column(db.Text)
    description_zh = db.Column(db.Text)
    
    has_evidence = db.Column(db.Boolean, default=False)
    evidence_description = db.Column(db.Text)
    
    evidence_photo_1 = db.Column(db.Text)
    evidence_photo_2 = db.Column(db.Text)
    evidence_photo_3 = db.Column(db.Text)
    evidence_photo_4 = db.Column(db.Text)
    evidence_photo_5 = db.Column(db.Text)
    
    penalty_imposed = db.Column(db.Boolean, default=False)
    penalty_amount = db.Column(db.Float)
    penalty_currency = db.Column(db.String(10), default='SGD')
    corrective_action = db.Column(db.Text)
    
    status = db.Column(db.String(20), default='Open')
    resolution_date = db.Column(db.Date)
    resolution_notes = db.Column(db.Text)
    
    reported_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    investigated_by = db.Column(db.String, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    violation_compliance_record = db.relationship('ComplianceRecord')
    violation_organization = db.relationship('Organization')
    violation_reported_by = db.relationship('User', foreign_keys=[reported_by])
    violation_investigated_by = db.relationship('User', foreign_keys=[investigated_by])

class Worker(db.Model):
    __tablename__ = 'workers'
    id = db.Column(db.Integer, primary_key=True)
    
    # Worker Information
    name = db.Column(db.String(100), nullable=False)
    fin_number = db.Column(db.String(20), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    
    # Organization tracking
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # System fields
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    
    def __repr__(self):
        return f'<Worker {self.name} - {self.fin_number}>'

class StaffAttendance(db.Model):
    __tablename__ = 'staff_attendance'
    id = db.Column(db.Integer, primary_key=True)
    
    # Staff Information
    staff_name = db.Column(db.String(100), nullable=False)
    fin_number = db.Column(db.String(20))  # FIN number from worker
    company_name = db.Column(db.String(100), nullable=False)
    worker_id = db.Column(db.Integer, db.ForeignKey('workers.id'))  # Link to worker record
    
    # Attendance Type
    attendance_type = db.Column(db.String(20), nullable=False)  # 'start' or 'end'
    
    # Timestamp and Photos
    timestamp = db.Column(db.DateTime, nullable=False, default=singapore_now)
    selfie_photo = db.Column(db.Text)  # Base64 encoded selfie image
    
    # QR Code and Location Info
    qr_code_scanned = db.Column(db.String(100))  # QR code that was scanned
    location = db.Column(db.String(100))  # Location where attendance was marked
    
    # Organization tracking
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # System fields
    ip_address = db.Column(db.String(45))  # Track IP for security
    user_agent = db.Column(db.Text)  # Track device info
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    worker = db.relationship('Worker')
    
    def __repr__(self):
        return f'<StaffAttendance {self.staff_name} - {self.attendance_type} at {self.timestamp}>'

class Visitor(db.Model):
    __tablename__ = 'visitors'
    id = db.Column(db.Integer, primary_key=True)
    
    # Visitor Information
    visitor_name = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    vehicle_number = db.Column(db.String(50))  # Vehicle registration number
    details = db.Column(db.Text)  # Additional details about the visit
    
    # Visit Type
    visit_type = db.Column(db.String(20), nullable=False)  # 'start' or 'end'
    
    # Timestamp and Photos
    timestamp = db.Column(db.DateTime, nullable=False, default=singapore_now)
    selfie_photo = db.Column(db.Text)  # Base64 encoded selfie image
    
    # QR Code and Location Info
    qr_code_scanned = db.Column(db.String(100))  # QR code that was scanned
    location = db.Column(db.String(100))  # Location where visit was recorded
    
    # Organization tracking
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # System fields
    ip_address = db.Column(db.String(45))  # Track IP for security
    user_agent = db.Column(db.Text)  # Track device info
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    
    def __repr__(self):
        return f'<Visitor {self.visitor_name} - {self.visit_type} at {self.timestamp}>'
