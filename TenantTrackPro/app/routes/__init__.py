"""Routes package initialization with Blueprint registration"""

def register_routes(app):
    """Register all Blueprint routes with the Flask application"""
    from .dashboard_routes import dashboard_bp
    from .qr_routes import qr_bp
    from .purchase_routes import purchase_bp
    from .other_routes import other_bp
    from .admin_routes import admin_bp
    from .asset_routes import asset_bp
    from .form_routes import form_bp
    from .room_routes import room_bp
    from .key_routes import key_bp
    from .offense_routes import offense_bp
    from .org_routes import org_bp
    from .compliance_routes import compliance_bp
    from .resident_routes import resident_bp
    
    # Register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(qr_bp)
    app.register_blueprint(purchase_bp)
    app.register_blueprint(other_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(asset_bp)
    app.register_blueprint(form_bp)
    app.register_blueprint(room_bp)
    app.register_blueprint(key_bp)
    app.register_blueprint(offense_bp)
    app.register_blueprint(org_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(resident_bp)