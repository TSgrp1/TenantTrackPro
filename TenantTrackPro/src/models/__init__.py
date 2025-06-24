"""Models package initialization"""

# Import all model modules to ensure they're registered with SQLAlchemy
from . import user
from . import organization
from . import system_log
from . import news
from . import house_acknowledge
from . import meter_reading
from . import room_inspection
from . import asset
from . import msrf
from . import food_locker
from . import bedding
from . import resident_checkout
from . import key_management
from . import compliance
from . import purchase

__all__ = [
    'user',
    'organization', 
    'system_log',
    'news',
    'house_acknowledge',
    'meter_reading',
    'room_inspection',
    'asset',
    'msrf',
    'food_locker',
    'bedding',
    'resident_checkout',
    'key_management',
    'compliance',
    'purchase'
]