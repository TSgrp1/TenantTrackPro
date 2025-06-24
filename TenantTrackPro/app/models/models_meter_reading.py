from app_main import db
from datetime import datetime
from timezone_utils import singapore_now

class MeterCompany(db.Model):
    __tablename__ = 'meter_companies'
    
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    meter_rooms = db.relationship('MeterRoom', backref='company', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, company_name=None, created_by=None):
        self.company_name = company_name
        self.created_by = created_by
    
    def __repr__(self):
        return f'<MeterCompany {self.company_name}>'

class MeterRoom(db.Model):
    __tablename__ = 'meter_rooms'
    
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(100), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('meter_companies.id'), nullable=False)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    water_readings = db.relationship('WaterMeterReading', backref='room', lazy=True, cascade='all, delete-orphan')
    electricity_readings = db.relationship('ElectricityMeterReading', backref='room', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, room_number=None, company_id=None, created_by=None):
        self.room_number = room_number
        self.company_id = company_id
        self.created_by = created_by
    
    def __repr__(self):
        return f'<MeterRoom {self.room_number}>'

class WaterMeterReading(db.Model):
    __tablename__ = 'water_meter_readings'
    
    id = db.Column(db.Integer, primary_key=True)
    meter_room_id = db.Column(db.Integer, db.ForeignKey('meter_rooms.id'), nullable=False)
    meter_number = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    start_reading = db.Column(db.Float, nullable=False, default=0.0)
    end_reading = db.Column(db.Float, nullable=False)
    total_consumption = db.Column(db.Float, nullable=False)
    rate_per_unit = db.Column(db.Float, default=0.0)
    total_amount = db.Column(db.Float, default=0.0)
    physical_pax = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    def __init__(self, meter_room_id=None, meter_number=None, start_date=None, end_date=None, 
                 start_reading=0.0, end_reading=0.0, total_consumption=0.0, rate_per_unit=0.0, 
                 total_amount=0.0, physical_pax=0, notes=None, created_by=None):
        self.meter_room_id = meter_room_id
        self.meter_number = meter_number
        self.start_date = start_date
        self.end_date = end_date
        self.start_reading = start_reading
        self.end_reading = end_reading
        self.total_consumption = total_consumption
        self.rate_per_unit = rate_per_unit
        self.total_amount = total_amount
        self.physical_pax = physical_pax
        self.notes = notes
        self.created_by = created_by
    
    def __repr__(self):
        return f'<WaterMeterReading {self.meter_number}>'

class ElectricityMeterReading(db.Model):
    __tablename__ = 'electricity_meter_readings'
    
    id = db.Column(db.Integer, primary_key=True)
    meter_room_id = db.Column(db.Integer, db.ForeignKey('meter_rooms.id'), nullable=False)
    meter_number = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    start_reading = db.Column(db.Float, nullable=False, default=0.0)
    end_reading = db.Column(db.Float, nullable=False)
    total_consumption = db.Column(db.Float, nullable=False)
    rate_per_unit = db.Column(db.Float, default=0.0)
    total_amount = db.Column(db.Float, default=0.0)
    physical_pax = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)
    created_by = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=singapore_now)
    updated_at = db.Column(db.DateTime, default=singapore_now, onupdate=singapore_now)
    
    def __init__(self, meter_room_id=None, meter_number=None, start_date=None, end_date=None, 
                 start_reading=0.0, end_reading=0.0, total_consumption=0.0, rate_per_unit=0.0, 
                 total_amount=0.0, physical_pax=0, notes=None, created_by=None):
        self.meter_room_id = meter_room_id
        self.meter_number = meter_number
        self.start_date = start_date
        self.end_date = end_date
        self.start_reading = start_reading
        self.end_reading = end_reading
        self.total_consumption = total_consumption
        self.rate_per_unit = rate_per_unit
        self.total_amount = total_amount
        self.physical_pax = physical_pax
        self.notes = notes
        self.created_by = created_by
    
    def __repr__(self):
        return f'<ElectricityMeterReading {self.meter_number}>'