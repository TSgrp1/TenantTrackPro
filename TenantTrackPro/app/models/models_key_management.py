from datetime import datetime, timedelta
from app_main import db
from timezone_utils import singapore_now

class KeyRecord(db.Model):
    __tablename__ = 'key_records'
    
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(20), nullable=False)
    resident_name = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(10), nullable=False)  # 'out' or 'in'
    scan_time = db.Column(db.DateTime, nullable=False, default=singapore_now)
    qr_code_type = db.Column(db.String(20), nullable=False)  # 'key_out' or 'key_in'
    
    # Status tracking
    status = db.Column(db.String(20), default='Active')  # 'Active', 'Returned', 'Not Returned'
    is_returned = db.Column(db.Boolean, default=False)
    return_time = db.Column(db.DateTime, nullable=True)
    
    # Additional tracking
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    # Relationships
    organization = db.relationship('Organization', backref='key_records')
    created_by_user = db.relationship('User', backref='created_key_records')
    
    @property
    def is_overdue(self):
        """Check if key is overdue (not returned within 30 minutes)"""
        if self.is_returned or self.scan_type != 'out':
            return False
        
        from timezone_utils import singapore_now
        current_time = singapore_now()
        
        # Ensure scan_time is timezone-aware
        if self.scan_time.tzinfo is None:
            from datetime import timezone
            scan_time = self.scan_time.replace(tzinfo=timezone.utc)
        else:
            scan_time = self.scan_time
            
        time_limit = scan_time + timedelta(minutes=30)
        return current_time > time_limit
    
    @property
    def time_held(self):
        """Calculate how long the key has been held"""
        from timezone_utils import singapore_now
        current_time = singapore_now()
        
        # Ensure scan_time is timezone-aware
        if self.scan_time.tzinfo is None:
            from datetime import timezone
            scan_time = self.scan_time.replace(tzinfo=timezone.utc)
        else:
            scan_time = self.scan_time
            
        if self.is_returned and self.return_time:
            if self.return_time.tzinfo is None:
                return_time = self.return_time.replace(tzinfo=timezone.utc)
            else:
                return_time = self.return_time
            return return_time - scan_time
        else:
            return current_time - scan_time
    
    @property
    def time_held_minutes(self):
        """Get time held in minutes"""
        return int(self.time_held.total_seconds() / 60)
    
    def __repr__(self):
        return f'<KeyRecord {self.room_number} - {self.resident_name} ({self.scan_type})>'