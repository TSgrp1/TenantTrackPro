from app_main import db
from datetime import datetime
from timezone_utils import singapore_now

class RoomInspection(db.Model):
    __tablename__ = 'room_inspections'
    
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(50), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    inspection_date = db.Column(db.Date, nullable=False)
    action_taken = db.Column(db.Text, nullable=True)
    confiscated_items = db.Column(db.Text, nullable=True)
    
    # Photo storage - JSON array of base64 encoded images
    confiscated_photos = db.Column(db.LargeBinary, nullable=True)  # JSON array of photo data stored as binary
    
    # Room In-charge details
    room_incharge_name = db.Column(db.String(200), nullable=True)
    room_incharge_signature = db.Column(db.Text, nullable=True)  # Base64 encoded signature
    
    # OE/DC details
    oe_dc_name = db.Column(db.String(200), nullable=True)
    oe_dc_signature = db.Column(db.Text, nullable=True)  # Base64 encoded signature
    
    # System fields
    created_at = db.Column(db.DateTime, default=singapore_now)
    created_by = db.Column(db.String, nullable=True)  # Will reference user.id when available
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<RoomInspection {self.room_number} - {self.inspection_date}>'