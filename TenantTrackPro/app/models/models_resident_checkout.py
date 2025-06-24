from app_main import db
from datetime import datetime
from timezone_utils import singapore_now
import pytz

class ResidentCheckout(db.Model):
    """Model for resident check-out records"""
    __tablename__ = 'resident_checkouts'
    
    id = db.Column(db.Integer, primary_key=True)
    resident_name = db.Column(db.String(255), nullable=False)
    fin = db.Column(db.String(20), nullable=False)
    company_name = db.Column(db.String(255), nullable=False)
    reason = db.Column(db.String(50), nullable=False)  # HOME LEAVE, CHECK-OUT, OTHER, New check-in, Home leave return
    details = db.Column(db.Text)
    checkout_timestamp = db.Column(db.DateTime, nullable=False)
    selfie_photo = db.Column(db.Text)  # Base64 encoded photo
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    is_active = db.Column(db.Boolean, default=True)
    
    def __init__(self, resident_name=None, fin=None, company_name=None, reason=None, 
                 details=None, checkout_timestamp=None, selfie_photo=None, organization_id=None):
        self.resident_name = resident_name
        self.fin = fin
        self.company_name = company_name
        self.reason = reason
        self.details = details
        self.checkout_timestamp = checkout_timestamp
        self.selfie_photo = selfie_photo
        self.organization_id = organization_id
    
    def get_singapore_time(self):
        """Get checkout time in Singapore timezone"""
        if self.checkout_timestamp:
            singapore_tz = pytz.timezone('Asia/Singapore')
            if self.checkout_timestamp.tzinfo is None:
                # Assume UTC if no timezone info
                utc_time = pytz.utc.localize(self.checkout_timestamp)
                return utc_time.astimezone(singapore_tz)
            else:
                return self.checkout_timestamp.astimezone(singapore_tz)
        return None
    
    def __repr__(self):
        return f'<ResidentCheckout {self.resident_name} - {self.fin}>'