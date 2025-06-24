from datetime import datetime
from timezone_utils import singapore_now
from app_main import db
from sqlalchemy import Index
from timezone_utils import singapore_now

class ComplianceRecord(db.Model):
    """Enhanced multilingual compliance records with separate tracking per language"""
    __tablename__ = 'compliance_records'
    
    id = db.Column(db.Integer, primary_key=True)
    record_number = db.Column(db.String(50), unique=True, nullable=False)  # Auto-generated unique ID
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # Record Type and Category
    record_type = db.Column(db.String(50), nullable=False)  # regulations, safety, conduct, maintenance, inspection
    compliance_category = db.Column(db.String(100), nullable=False)  # Dormitory Rules, Safety Protocols, etc.
    priority_level = db.Column(db.String(20), default='Medium')  # High, Medium, Low
    
    # Language-specific content (5 separate language records)
    language_code = db.Column(db.String(10), nullable=False)  # en, bn, my, ta, zh
    
    # Content fields for each language
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    detailed_instructions = db.Column(db.Text)
    
    # Content input options for each language (text + PDF + 3 images)
    content_text = db.Column(db.Text)  # Text input for regulations/instructions
    
    # PDF upload
    pdf_file_data = db.Column(db.Text)  # Base64 encoded PDF data
    pdf_file_name = db.Column(db.String(255))  # Original PDF filename
    
    # Three image uploads
    image_1_data = db.Column(db.Text)  # Base64 encoded image 1
    image_1_name = db.Column(db.String(255))  # Image 1 filename
    image_2_data = db.Column(db.Text)  # Base64 encoded image 2
    image_2_name = db.Column(db.String(255))  # Image 2 filename
    image_3_data = db.Column(db.Text)  # Base64 encoded image 3
    image_3_name = db.Column(db.String(255))  # Image 3 filename
    
    # Language-specific reference materials (3 photos per language)
    ref_photo_1 = db.Column(db.Text)  # Base64 encoded image
    ref_photo_1_caption = db.Column(db.String(255))
    ref_photo_2 = db.Column(db.Text)  # Base64 encoded image
    ref_photo_2_caption = db.Column(db.String(255))
    ref_photo_3 = db.Column(db.Text)  # Base64 encoded image
    ref_photo_3_caption = db.Column(db.String(255))
    
    # Compliance tracking
    effective_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date)
    version_number = db.Column(db.String(20), default='1.0')
    status = db.Column(db.String(20), default='Active')  # Active, Inactive, Under Review, Archived
    
    # Acknowledgment tracking
    requires_acknowledgment = db.Column(db.Boolean, default=True)
    acknowledgment_deadline = db.Column(db.Date)
    
    # Audit fields
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    approved_by = db.Column(db.String, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=datetime.now)
    approved_at = db.Column(db.DateTime)
    
    # Relationships
    organization = db.relationship('Organization')
    created_by_user = db.relationship('User', foreign_keys=[created_by])
    approved_by_user = db.relationship('User', foreign_keys=[approved_by])
    acknowledgments = db.relationship('ComplianceAcknowledgment', back_populates='compliance_record', cascade='all, delete-orphan')
    violations = db.relationship('ComplianceViolation', back_populates='compliance_record')
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_compliance_org_lang', 'organization_id', 'language_code'),
        Index('idx_compliance_type_status', 'record_type', 'status'),
        Index('idx_compliance_effective_date', 'effective_date'),
    )

class ComplianceAcknowledgment(db.Model):
    """Track user acknowledgments of compliance records"""
    __tablename__ = 'compliance_acknowledgments'
    
    id = db.Column(db.Integer, primary_key=True)
    compliance_record_id = db.Column(db.Integer, db.ForeignKey('compliance_records.id'), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # Acknowledgment details
    acknowledged_at = db.Column(db.DateTime, default=singapore_now)
    acknowledgment_method = db.Column(db.String(50), default='digital')  # digital, physical, verbal
    ip_address = db.Column(db.String(45))  # For audit trail
    user_agent = db.Column(db.String(500))  # Browser/device info
    
    # Language used for acknowledgment
    language_code = db.Column(db.String(10), nullable=False)
    
    # Optional fields
    notes = db.Column(db.Text)
    signature_data = db.Column(db.Text)  # Base64 encoded signature if required
    
    # Relationships
    compliance_record = db.relationship('ComplianceRecord', back_populates='acknowledgments')
    user = db.relationship('User')
    organization = db.relationship('Organization')
    
    # Unique constraint to prevent duplicate acknowledgments
    __table_args__ = (
        db.UniqueConstraint('compliance_record_id', 'user_id', name='uq_compliance_user_ack'),
        Index('idx_ack_record_user', 'compliance_record_id', 'user_id'),
    )

class ComplianceViolation(db.Model):
    """Track violations of compliance records"""
    __tablename__ = 'compliance_violations'
    
    id = db.Column(db.Integer, primary_key=True)
    violation_number = db.Column(db.String(50), unique=True, nullable=False)
    compliance_record_id = db.Column(db.Integer, db.ForeignKey('compliance_records.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # Violator information
    violator_name = db.Column(db.String(100), nullable=False)
    violator_id = db.Column(db.String(50))  # Employee ID, FIN, etc.
    violator_contact = db.Column(db.String(100))
    violator_room = db.Column(db.String(20))
    violator_company = db.Column(db.String(100))
    
    # Violation details
    violation_date = db.Column(db.Date, nullable=False)
    violation_time = db.Column(db.Time)
    violation_location = db.Column(db.String(100))
    severity_level = db.Column(db.String(20), nullable=False)  # Minor, Major, Critical
    
    # Description in multiple languages
    description_en = db.Column(db.Text)
    description_bn = db.Column(db.Text)
    description_my = db.Column(db.Text)
    description_ta = db.Column(db.Text)
    description_zh = db.Column(db.Text)
    
    # Evidence and documentation
    has_evidence = db.Column(db.Boolean, default=False)
    evidence_description = db.Column(db.Text)
    
    # Evidence photos (up to 5 photos)
    evidence_photo_1 = db.Column(db.Text)  # Base64 encoded
    evidence_photo_2 = db.Column(db.Text)
    evidence_photo_3 = db.Column(db.Text)
    evidence_photo_4 = db.Column(db.Text)
    evidence_photo_5 = db.Column(db.Text)
    
    # Penalty and corrective action
    penalty_imposed = db.Column(db.Boolean, default=False)
    penalty_amount = db.Column(db.Float)
    penalty_currency = db.Column(db.String(10), default='SGD')
    corrective_action = db.Column(db.Text)
    
    # Status tracking
    status = db.Column(db.String(20), default='Open')  # Open, Under Investigation, Resolved, Closed
    resolution_date = db.Column(db.Date)
    resolution_notes = db.Column(db.Text)
    
    # Audit fields
    reported_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    investigated_by = db.Column(db.String, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=datetime.now)
    
    # Relationships
    compliance_record = db.relationship('ComplianceRecord', back_populates='violations')
    organization = db.relationship('Organization')
    reported_by_user = db.relationship('User', foreign_keys=[reported_by])
    investigated_by_user = db.relationship('User', foreign_keys=[investigated_by])
    
    # Indexes
    __table_args__ = (
        Index('idx_violation_org_date', 'organization_id', 'violation_date'),
        Index('idx_violation_severity', 'severity_level'),
        Index('idx_violation_status', 'status'),
    )

class ComplianceAuditLog(db.Model):
    """Audit trail for all compliance-related activities"""
    __tablename__ = 'compliance_audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # Event details
    event_type = db.Column(db.String(50), nullable=False)  # create, update, delete, acknowledge, violate
    entity_type = db.Column(db.String(50), nullable=False)  # compliance_record, acknowledgment, violation
    entity_id = db.Column(db.Integer, nullable=False)
    
    # User and context
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    language_code = db.Column(db.String(10))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    # Change details
    old_values = db.Column(db.Text)  # JSON string of old values
    new_values = db.Column(db.Text)  # JSON string of new values
    description = db.Column(db.Text)
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization')
    user = db.relationship('User')
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_org_date', 'organization_id', 'created_at'),
        Index('idx_audit_entity', 'entity_type', 'entity_id'),
        Index('idx_audit_user', 'user_id'),
    )