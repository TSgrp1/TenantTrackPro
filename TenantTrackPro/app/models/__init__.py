"""Models package initialization"""

# Import all model modules to ensure they're registered with SQLAlchemy
from . import models_house_acknowledge
from . import models_meter_reading
from . import models_room_inspection
from . import models_asset
from . import models_msrf
from . import models_food_locker
from . import models_bedding
from . import models_resident_checkout
from . import models_key_management
# Skip models_compliance to avoid table conflicts - ComplianceRecord is already in models.py

__all__ = [
    'models_house_acknowledge',
    'models_meter_reading',
    'models_room_inspection',
    'models_asset',
    'models_msrf',
    'models_food_locker',
    'models_bedding',
    'models_resident_checkout',
    'models_key_management'
]