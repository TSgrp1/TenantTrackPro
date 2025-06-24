"""Performance monitoring middleware and utilities"""
import time
import logging
from functools import wraps
from flask import request, g

# Configure performance logging
perf_logger = logging.getLogger('performance')
perf_logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('PERF: %(asctime)s - %(message)s')
handler.setFormatter(formatter)
perf_logger.addHandler(handler)

def monitor_performance(app):
    """Add performance monitoring to Flask app"""
    
    @app.before_request
    def before_request():
        g.start_time = time.time()
    
    @app.after_request
    def after_request(response):
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 0.5:  # Log slow requests (>500ms)
                perf_logger.warning(f"SLOW REQUEST: {request.path} took {duration:.3f}s")
            elif duration > 0.1:  # Log medium requests (>100ms)
                perf_logger.info(f"{request.path} took {duration:.3f}s")
        return response

def performance_timer(func):
    """Decorator to time function execution"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        if duration > 0.1:
            perf_logger.info(f"{func.__name__} took {duration:.3f}s")
        return result
    return wrapper