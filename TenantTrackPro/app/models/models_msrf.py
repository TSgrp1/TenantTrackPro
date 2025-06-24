from app_main import db
from datetime import datetime
from timezone_utils import singapore_now

def singapore_time():
    """Return current Singapore time (UTC+8)"""
    from datetime import timezone, timedelta
    singapore_tz = timezone(timedelta(hours=8))
    return datetime.now(singapore_tz)

class MSRFRequest(db.Model):
    __tablename__ = 'msrf_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(50), nullable=True)  # Added serial number field
    room_number = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(255), nullable=False)
    item_requested = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    date_requested = db.Column(db.Date, nullable=False)
    date_installed = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=singapore_time)
    organization_id = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f'<MSRFRequest {self.id}: {self.room_number} - {self.item_requested}>'