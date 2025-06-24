from app_main import db
from datetime import datetime
from timezone_utils import singapore_now

class AssetName(db.Model):
    __tablename__ = 'asset_names'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    category = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    
    # Relationship to assets
    assets = db.relationship('AssetItem', backref='asset_name_ref', lazy=True, cascade='all, delete-orphan')

class AssetItem(db.Model):
    __tablename__ = 'asset_items'
    
    id = db.Column(db.Integer, primary_key=True)
    asset_name_id = db.Column(db.Integer, db.ForeignKey('asset_names.id'), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False, unique=True)
    room_number = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Room')  # Room, Store, Damage, Dispose, Other
    quantity = db.Column(db.Integer, default=1)
    date_added = db.Column(db.DateTime, default=singapore_now)
    last_edited = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    notes = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Asset {self.serial_number}>'
    
    @property
    def status_color(self):
        colors = {
            'Room': 'success',      # Green
            'Store': 'warning',     # Orange
            'Damage': 'warning',    # Yellow (using warning for yellow effect)
            'Dispose': 'danger',    # Red
            'Other': 'danger'       # Red
        }
        return colors.get(self.status, 'secondary')