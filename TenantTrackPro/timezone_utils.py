"""
Singapore timezone utilities for the attendance management system.
All datetime functions must use Singapore time (Asia/Singapore).
"""
from datetime import datetime
import pytz

# Singapore timezone constant
SINGAPORE_TZ = pytz.timezone('Asia/Singapore')

def singapore_now():
    """Get current datetime in Singapore timezone"""
    return datetime.now(SINGAPORE_TZ)

def singapore_today():
    """Get today's date in Singapore timezone"""
    return singapore_now().date()

def to_singapore_time(dt):
    """Convert datetime to Singapore timezone"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Assume naive datetime is UTC and convert to Singapore
        utc_dt = pytz.utc.localize(dt)
        return utc_dt.astimezone(SINGAPORE_TZ)
    return dt.astimezone(SINGAPORE_TZ)

def format_singapore_datetime(dt, format_str='%Y-%m-%d %H:%M:%S'):
    """Format datetime in Singapore timezone"""
    if dt is None:
        return ''
    sg_dt = to_singapore_time(dt)
    return sg_dt.strftime(format_str)

def singapore_datetime_filter(dt):
    """Jinja2 filter to format datetime in Singapore timezone"""
    return format_singapore_datetime(dt)

def parse_singapore_datetime(date_str, format_str='%Y-%m-%d %H:%M:%S'):
    """Parse datetime string and localize to Singapore timezone"""
    if not date_str:
        return None
    dt = datetime.strptime(date_str, format_str)
    return SINGAPORE_TZ.localize(dt)