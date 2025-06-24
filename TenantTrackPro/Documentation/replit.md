# Pioneer Lodge Dormitory Management System

## Overview

This is a comprehensive multi-tenant dormitory management system built for TS Management Services Pte Ltd. The application provides a complete digital solution for managing dormitory operations including asset tracking, room inspections, meter readings, resident management, and compliance records. The system supports multiple organizations with isolated data and provides role-based access control for secure operations.

## System Architecture

### Backend Architecture
- **Framework**: Flask 3.0+ with Python 3.11
- **Application Pattern**: Factory pattern with modular structure
- **Database**: PostgreSQL via Supabase with SQLite fallback for development
- **ORM**: SQLAlchemy 2.0+ with declarative base model
- **Authentication**: Multi-method authentication (Replit OAuth, email/password) with Flask-Login
- **Session Management**: Flask sessions with JWT token support

### Frontend Architecture
- **UI Framework**: Bootstrap 5 with responsive design
- **JavaScript**: Vanilla JavaScript with minimal dependencies
- **Templating**: Jinja2 templates with base template inheritance
- **Styling**: Custom CSS with Bootstrap theme integration
- **Icons**: Font Awesome 6.0 for consistent iconography

### Database Architecture
- **Primary Database**: Supabase PostgreSQL with connection pooling
- **Fallback Database**: SQLite for development and testing
- **Schema Management**: SQLAlchemy models with automatic table creation
- **Data Isolation**: Organization-based multi-tenancy
- **Performance**: Connection pooling, query optimization, and indexing

## Key Components

### Authentication System
- **Replit OAuth**: Integration with Google, GitHub, X (Twitter), Apple accounts
- **Traditional Auth**: Email/password authentication with secure hashing
- **Multi-Factor Auth**: Additional security layer for sensitive operations
- **Role-Based Access**: Admin, Manager, Staff roles with granular permissions
- **Session Security**: Secure session management with automatic expiration

### Asset Management
- **Asset Categories**: Configurable item classifications
- **Inventory Tracking**: Real-time quantity and status monitoring
- **Serial Number Management**: Unique identifier tracking
- **Location Tracking**: Room-based asset assignment
- **Status Management**: Active, Inactive, Room, Store, Clear, Other statuses

### Room Management
- **Room Inventory**: Comprehensive room condition tracking
- **Handover Processes**: Digital occupant transition workflows
- **Inspection Records**: Detailed room inspection with photo documentation
- **Meter Readings**: Water and electricity consumption tracking
- **Digital Signatures**: Electronic signature capture for all processes

### Form Management
- **Dynamic Forms**: Configurable form templates per organization
- **QR Code Generation**: Dynamic QR codes for mobile access
- **Multi-language Support**: English, Tamil, Chinese, Bengali, Malay
- **Permission System**: Granular form-level access control
- **Offline Capability**: Forms accessible via QR codes without login

### Document Generation
- **PDF Reports**: ReportLab-based PDF generation for official documents
- **Excel Exports**: Pandas-based Excel file generation for data analysis
- **QR Code Generation**: Dynamic QR codes for forms and processes
- **Photo Management**: Base64-encoded image storage and display
- **Digital Signatures**: E-signature capture and storage

## Data Flow

### Authentication Flow
1. User accesses application
2. Redirected to authentication page
3. Chooses OAuth provider or email/password
4. System validates credentials and creates/updates user record
5. User session established with appropriate permissions
6. Organization-specific data access granted

### Form Submission Flow
1. User accesses form via web interface or QR code
2. Form template loaded based on permissions and organization
3. User fills form with text, photos, signatures
4. Data validated and compressed (photos base64-encoded)
5. Submission stored in database with organization isolation
6. Confirmation and optional PDF generation

### Asset Management Flow
1. Assets created with categories and serial numbers
2. Location and status updates tracked
3. Movement history maintained
4. Reports generated for auditing
5. Excel exports for external analysis

## External Dependencies

### Core Dependencies
- **Flask Ecosystem**: Flask, Flask-SQLAlchemy, Flask-Login, Flask-Dance
- **Database**: psycopg2-binary (PostgreSQL), SQLAlchemy
- **Authentication**: PyJWT, oauthlib, Werkzeug
- **Document Processing**: ReportLab (PDF), Pandas (Excel), Pillow (Images)
- **Utilities**: python-dotenv, pytz, qrcode, email-validator

### Cloud Services
- **Supabase**: Primary PostgreSQL database with connection pooling
- **Replit OAuth**: Authentication service integration
- **File Storage**: Local filesystem with configurable upload directories

### Development Dependencies
- **Gunicorn**: Production WSGI server
- **Docker**: Containerization support
- **Environment Management**: python-dotenv for configuration

## Deployment Strategy

### Container Deployment
- **Docker Support**: Multi-stage Dockerfile with Python 3.11 slim base
- **Health Checks**: Built-in health monitoring endpoints
- **Process Management**: Gunicorn with multiple workers
- **Environment Variables**: Comprehensive configuration via environment

### Database Configuration
- **Primary**: Supabase PostgreSQL with connection string
- **Fallback**: SQLite for development environments
- **Migration**: Automatic table creation via SQLAlchemy
- **Performance**: Connection pooling and query optimization

### Security Configuration
- **Environment Variables**: Secure secret management
- **CORS Support**: Configurable cross-origin resource sharing
- **Proxy Support**: ProxyFix middleware for reverse proxy deployment
- **Session Security**: Secure session cookies and CSRF protection

### Monitoring and Performance
- **Performance Monitoring**: Request timing and slow query detection
- **Caching**: In-memory cache for frequently accessed data
- **Database Optimization**: Index creation and connection pooling
- **Health Endpoints**: System status monitoring

## User Preferences

Preferred communication style: Simple, everyday language.

### Dynamic Database-Driven RBAC Implementation (June 24, 2025)
- **COMPLETED**: Upgraded to fully dynamic database-driven role system
- **DATABASE ROLES**: Removed all hardcoded admin email checks, using user.role field
- **SESSION LOGIC**: Login now sets session['role'] = user.role directly from database
- **SCALABILITY**: Ready for admin/user/manager/staff roles without code changes
- **SECURITY**: No hardcoded bypass routes, all role checks use database values
- **COMPATIBILITY**: Pioneer Lodge admin access preserved with database role assignment
- **PERFORMANCE**: Session-first checking with database fallback maintained
- **ARCHITECTURE**: Single source of truth for user roles in database

## Recent Changes

### Model Structure Reorganization (June 24, 2025)
- **COMPLETED**: Moved all models_*.py files to app/models/ directory structure
- **IMPACT**: Improved code organization and modularity
- **FILES AFFECTED**: 10 model files moved, 7 core files updated with new imports
- **ISSUES RESOLVED**: Fixed Python package conflicts, duplicate model definitions
- **RESULT**: Application running successfully with clean model structure

### Route Migration to Blueprint System (June 24, 2025)
- **COMPLETED**: Full migration from monolithic routes.py to organized Blueprint modules
- **STRUCTURE**: Created app/routes/ with 4 Blueprint modules (952 lines organized)
- **DASHBOARD**: Migrated / and /dashboard with full statistics and permissions
- **QR CODES**: Migrated QR management, generation, and redirect functionality
- **PURCHASE**: Migrated purchase forms, PDF generation, and storage
- **AUTHENTICATION**: Migrated login/logout and health check endpoints
- **INTEGRATION**: Updated app_factory.py with complete Blueprint registration
- **TESTING**: All 11 core routes verified and functional
- **RESULT**: Clean modular architecture with maintained functionality

### Template Structure Organization (June 24, 2025)
- **COMPLETED**: Complete template folder structure with hierarchical organization
- **STRUCTURE**: Created 10 organized directories (admin/, assets/, forms/, rooms/, staff/, residents/, compliance/, meters/, reports/, layout/)
- **MIGRATION**: Organized 80+ templates into logical functional groups
- **JINJA GLOBALS**: Centralized all helper functions in jinja_globals.py with proper registration
- **INTEGRATION**: Updated app_factory.py with Jinja globals registration
- **BLUEPRINT UPDATES**: All migrated routes use correct organized template paths
- **TESTING**: All critical routes verified functional with new structure
- **COMPLIANCE**: Maintained backward compatibility with original templates preserved
- **RESULT**: Professional template organization following industry standards

### Blueprint System Expansion (June 24, 2025)
- **COMPLETED**: Created 9 additional Blueprint modules for comprehensive route organization
- **ADMIN**: Admin routes Blueprint (admin_routes.py) with 8 core admin management routes
- **ASSETS**: Asset routes Blueprint (asset_routes.py) with 12 asset management routes
- **FORMS**: Form routes Blueprint (form_routes.py) with 11 form management routes
- **ROOMS**: Room routes Blueprint (room_routes.py) with 12 room management routes
- **KEYS**: Key routes Blueprint (key_routes.py) with 8 key management routes
- **OFFENSES**: Offense routes Blueprint (offense_routes.py) with 10 offense tracking routes
- **ORGANIZATIONS**: Organization routes Blueprint (org_routes.py) with 8 organization management routes
- **COMPLIANCE**: Compliance routes Blueprint (compliance_routes.py) with 8 compliance management routes
- **RESIDENTS**: Resident routes Blueprint (resident_routes.py) with 12 resident and visitor management routes
- **INTEGRATION**: Updated Blueprint registration system for all 13 modules
- **TESTING**: All new Blueprint routes tested and functional
- **ARCHITECTURE**: Total of 80+ routes migrated across 13 organized Blueprint modules
- **RESULT**: Comprehensive modular architecture with complete functional organization

## Changelog

Changelog:
- June 24, 2025. Initial setup
- June 24, 2025. Model files reorganization - moved all models_*.py to app/models/
- June 24, 2025. Route migration to Blueprint system - complete modular architecture (952 lines organized across 4 modules)
- June 24, 2025. Complete template organization - 80+ templates organized into 10 functional directories with centralized Jinja globals
- June 24, 2025. Blueprint system expansion - 80+ routes migrated across 13 organized Blueprint modules (admin, assets, forms, rooms, keys, offenses, organizations, compliance, residents)
- June 24, 2025. Static file organization and session-based RBAC - CSS/JS externalized, role-based navigation implemented
- June 24, 2025. Dynamic database-driven RBAC upgrade - removed hardcoded admin checks, using user.role field for scalable role management