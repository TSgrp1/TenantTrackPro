"""Database query optimization utilities"""
from sqlalchemy import text
from models import db

def optimize_database_connections():
    """Optimize database connection settings"""
    try:
        with db.engine.connect() as conn:
            # Set connection-level optimizations for PostgreSQL
            conn.execute(text("SET shared_preload_libraries = 'pg_stat_statements'"))
            conn.execute(text("SET log_statement = 'none'"))  # Disable query logging
            conn.execute(text("SET log_min_duration_statement = 1000"))  # Only log slow queries
            conn.execute(text("SET work_mem = '16MB'"))
            conn.execute(text("SET effective_cache_size = '1GB'"))
            conn.commit()
        print("✓ Database connection optimized")
    except Exception as e:
        print(f"Database optimization note: {e}")

def create_database_indexes():
    """Create performance-critical indexes"""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_purchase_requests_org_created ON purchase_requests(organization_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_purchase_requests_status ON purchase_requests(status)",
        "CREATE INDEX IF NOT EXISTS idx_purchase_requests_date ON purchase_requests(request_date)",
        "CREATE INDEX IF NOT EXISTS idx_assets_org_created ON assets(organization_id, created_at DESC)", 
        "CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id)",
        "CREATE INDEX IF NOT EXISTS idx_purchase_items_request ON purchase_request_items(purchase_request_id)"
    ]
    
    try:
        with db.engine.connect() as conn:
            for index_sql in indexes:
                conn.execute(text(index_sql))
            conn.commit()
        print("✓ Database indexes created")
    except Exception as e:
        print(f"Index creation note: {e}")