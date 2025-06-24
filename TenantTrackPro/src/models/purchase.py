"""Purchase management models"""
from datetime import datetime
from src.config.database import Base
from src.utils.timezone import singapore_now
from sqlalchemy import Column, Integer, String, Text, Date, DateTime, Boolean, ForeignKey, Numeric
from sqlalchemy.orm import relationship

class PurchaseRequest(Base):
    """Purchase request model"""
    __tablename__ = 'purchase_requests'
    
    id = Column(Integer, primary_key=True)
    request_number = Column(String(50), unique=True, nullable=False)
    pl_number = Column(String(50))
    request_date = Column(Date, nullable=False)
    category = Column(String(100), nullable=False)
    requested_by = Column(String(100), nullable=False)
    dc_name = Column(String(100))
    operation_manager = Column(String(100))
    general_manager = Column(String(100))
    requested_by_footer = Column(String(100))
    recommended_by_footer = Column(String(100))
    
    # Additional Information Fields
    supplier = Column(String(200))
    department = Column(String(100))
    priority = Column(String(50))
    payment_method = Column(String(100))
    budget_code = Column(String(100))
    expected_delivery = Column(Date)
    justification = Column(Text)
    
    # Signature Fields - stored as JSON data
    dc_signature_data = Column(Text)
    operation_manager_signature_data = Column(Text)
    general_manager_signature_data = Column(Text)
    
    status = Column(String(20), default='Pending')
    approval_status = Column(String(20), default='Pending')
    approved_by = Column(String, ForeignKey('users.id'))
    approved_date = Column(DateTime)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    created_by = Column(String, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=singapore_now)
    updated_at = Column(DateTime, default=singapore_now, onupdate=singapore_now)

    # Relationships
    items = relationship('PurchaseRequestItem', backref='purchase_request', cascade='all, delete-orphan')
    organization = relationship('Organization')
    created_by_user = relationship('User', foreign_keys=[created_by])
    approved_by_user = relationship('User', foreign_keys=[approved_by])

class PurchaseRequestItem(Base):
    """Purchase request item model"""
    __tablename__ = 'purchase_request_items'
    
    id = Column(Integer, primary_key=True)
    purchase_request_id = Column(Integer, ForeignKey('purchase_requests.id'), nullable=False)
    description = Column(Text, nullable=False)
    unit_cost = Column(Numeric(10, 2), default=0)
    quantity = Column(Integer, nullable=False)
    total_cost = Column(Numeric(10, 2), default=0)
    room_no = Column(String(50))
    unit = Column(String(50))
    cost_code = Column(String(50))
    remarks = Column(Text)
    approved_quantity = Column(Integer)
    received_quantity = Column(Integer, default=0)
    status = Column(String(20), default='Pending')
    created_at = Column(DateTime, default=singapore_now)

class StockItem(Base):
    """Stock item model"""
    __tablename__ = 'stock_items'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    category = Column(String(50), nullable=False)
    quantity = Column(Integer, default=1)
    used_quantity = Column(Integer, default=0)
    status = Column(String(20), default='received')
    location = Column(String(100))
    room_no = Column(String(20))
    purchase_date = Column(Date)
    purchase_cost = Column(Numeric(10, 2))
    serial_number = Column(String(100))
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    created_by = Column(String, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=singapore_now)
    updated_at = Column(DateTime, default=singapore_now, onupdate=singapore_now)

    # Relationships
    organization = relationship('Organization')
    created_by_user = relationship('User')