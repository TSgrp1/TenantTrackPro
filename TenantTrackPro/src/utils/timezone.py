"""Timezone utilities"""
import pytz
from datetime import datetime

SINGAPORE_TZ = pytz.timezone('Asia/Singapore')

def singapore_now():
    """Get current time in Singapore timezone"""
    return datetime.now(SINGAPORE_TZ)

def to_singapore_time(dt):
    """Convert datetime to Singapore timezone"""
    if dt.tzinfo is None:
        # Assume UTC if no timezone info
        dt = pytz.UTC.localize(dt)
    return dt.astimezone(SINGAPORE_TZ)

def format_singapore_time(dt, format_string='%Y-%m-%d %H:%M:%S'):
    """Format datetime in Singapore timezone"""
    if dt:
        sg_time = to_singapore_time(dt)
        return sg_time.strftime(format_string)
    return ""