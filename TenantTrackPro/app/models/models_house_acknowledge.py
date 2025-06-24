from app_main import db
from datetime import datetime
from timezone_utils import singapore_now
import os

class RoomNumber(db.Model):
    """Model for managing room numbers"""
    __tablename__ = 'room_numbers'
    
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(20), unique=True, nullable=False)
    building = db.Column(db.String(10))  # e.g., "80", "81", etc.
    floor = db.Column(db.String(10))     # e.g., "01", "02", etc.
    unit = db.Column(db.String(10))      # e.g., "001", "002", etc.
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    def __init__(self, room_number=None, building=None, floor=None, unit=None):
        self.room_number = room_number
        self.building = building
        self.floor = floor
        self.unit = unit
    
    def __repr__(self):
        return f'<RoomNumber {self.room_number}>'

class HouseAcknowledge(db.Model):
    """Model for House Acknowledge content in multiple languages"""
    __tablename__ = 'house_acknowledge'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # English content
    english_text = db.Column(db.Text, nullable=False)
    english_image1 = db.Column(db.String(255))
    english_image2 = db.Column(db.String(255))
    english_image3 = db.Column(db.String(255))
    
    # Tamil content
    tamil_text = db.Column(db.Text, nullable=False)
    tamil_image1 = db.Column(db.String(255))
    tamil_image2 = db.Column(db.String(255))
    tamil_image3 = db.Column(db.String(255))
    
    # Chinese content
    chinese_text = db.Column(db.Text, nullable=False)
    chinese_image1 = db.Column(db.String(255))
    chinese_image2 = db.Column(db.String(255))
    chinese_image3 = db.Column(db.String(255))
    
    # Myanmar content
    myanmar_text = db.Column(db.Text, nullable=False)
    myanmar_image1 = db.Column(db.String(255))
    myanmar_image2 = db.Column(db.String(255))
    myanmar_image3 = db.Column(db.String(255))
    
    # Bengali content
    bengali_text = db.Column(db.Text, nullable=False)
    bengali_image1 = db.Column(db.String(255))
    bengali_image2 = db.Column(db.String(255))
    bengali_image3 = db.Column(db.String(255))
    
    # QR Code and metadata
    qr_code_path = db.Column(db.String(255))
    qr_code_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=singapore_now)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship with acknowledgments
    acknowledgments = db.relationship('HouseAcknowledgment', backref='house_acknowledge', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<HouseAcknowledge {self.title}>'

class HouseAcknowledgment(db.Model):
    """Model for storing user acknowledgments"""
    __tablename__ = 'house_acknowledgments'
    
    id = db.Column(db.Integer, primary_key=True)
    house_acknowledge_id = db.Column(db.Integer, db.ForeignKey('house_acknowledge.id'), nullable=False)
    
    # User details
    name = db.Column(db.String(100), nullable=False)
    fin = db.Column(db.String(20), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    room_number = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    e_signature = db.Column(db.Text)  # Base64 encoded signature
    selfie_photo = db.Column(db.Text)  # Base64 encoded selfie photo
    
    # Metadata
    language_selected = db.Column(db.String(20), nullable=False)
    acknowledged_at = db.Column(db.DateTime, default=singapore_now)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    def __repr__(self):
        return f'<HouseAcknowledgment {self.name} - {self.fin}>'