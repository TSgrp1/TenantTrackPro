# Pioneer Lodge Dormitory Management System
## API Documentation & Technical Reference

### System Architecture Overview

#### Technology Stack
- **Backend Framework**: Flask 2.3+ with Python 3.11
- **Database**: PostgreSQL 14+ with SQLAlchemy ORM
- **Authentication**: Replit OAuth with JWT tokens
- **Frontend**: Bootstrap 5 with responsive design
- **File Processing**: ReportLab (PDF), Pandas (Excel), Pillow (Images)
- **QR Codes**: qrcode library with dynamic generation

#### Application Structure
```
├── app.py              # Flask application factory
├── main.py            # Application entry point
├── models.py          # Database models and schemas
├── routes.py          # URL routing and view functions
├── auth.py            # Authentication helpers
├── replit_auth.py     # Replit OAuth integration
├── templates/         # Jinja2 HTML templates
├── static/           # CSS, JS, and asset files
└── requirements.txt  # Python dependencies
```

### Database Schema Reference

#### Core Tables

##### Users Table
```sql
CREATE TABLE users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR(120) UNIQUE,
    first_name VARCHAR,
    last_name VARCHAR,
    profile_image_url VARCHAR,
    password_hash VARCHAR(256),
    organization_id INTEGER REFERENCES organizations(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

##### Organizations Table
```sql
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

##### Assets Table
```sql
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category_id INTEGER REFERENCES asset_categories(id),
    organization_id INTEGER REFERENCES organizations(id),
    quantity INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'Active',
    location VARCHAR(100),
    serial_number VARCHAR(100),
    purchase_date DATE,
    purchase_cost FLOAT,
    created_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

##### Form Templates Table
```sql
CREATE TABLE form_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    organization_id INTEGER REFERENCES organizations(id),
    form_type VARCHAR(50) NOT NULL,
    regulations_text TEXT,
    language_code VARCHAR(10) DEFAULT 'en',
    fields_json TEXT,
    ref_photo_1 TEXT,
    ref_photo_2 TEXT,
    ref_photo_3 TEXT,
    qr_code_id INTEGER REFERENCES qr_codes(id),
    public_access BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

##### QR Codes Table
```sql
CREATE TABLE qr_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR(100) UNIQUE NOT NULL,
    qr_type VARCHAR(30) NOT NULL,
    reference_id VARCHAR(50),
    reference_table VARCHAR(50),
    organization_id INTEGER REFERENCES organizations(id),
    label VARCHAR(100),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    scan_count INTEGER DEFAULT 0,
    last_scanned TIMESTAMP,
    created_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);
```

### API Endpoints Reference

#### Authentication Endpoints

##### POST /auth/login
**Purpose**: Initiate Replit OAuth authentication
**Parameters**: None (redirects to OAuth provider)
**Response**: Redirect to OAuth authorization URL
**Example**:
```http
POST /auth/login
Content-Type: application/json

Response: 302 Redirect to OAuth provider
```

##### GET /auth/logout
**Purpose**: Terminate user session and logout
**Parameters**: None
**Response**: Redirect to logout confirmation
**Example**:
```http
GET /auth/logout

Response: 302 Redirect to home page
```

#### Asset Management Endpoints

##### GET /assets
**Purpose**: Display asset management interface
**Authentication**: Required
**Parameters**: 
- `category` (optional): Filter by asset category
- `status` (optional): Filter by asset status
- `search` (optional): Search by name or description
**Response**: HTML page with asset list

##### POST /assets/create
**Purpose**: Create new asset record
**Authentication**: Required
**Parameters**:
```json
{
    "name": "Asset Name",
    "description": "Asset Description",
    "category_id": 1,
    "quantity": 1,
    "status": "Active",
    "location": "Room 101",
    "serial_number": "SN123456",
    "purchase_date": "2025-01-15",
    "purchase_cost": 299.99
}
```
**Response**: JSON with success/error status

##### GET /assets/export
**Purpose**: Export asset data to Excel
**Authentication**: Required
**Parameters**:
- `category` (optional): Filter by category
- `status` (optional): Filter by status
- `date_from` (optional): Start date filter
- `date_to` (optional): End date filter
**Response**: Excel file download

#### Room Management Endpoints

##### GET /room-checklist
**Purpose**: Display room checklist form
**Authentication**: Required
**Permissions**: handover form access
**Response**: HTML checklist form

##### POST /room-checklist/save
**Purpose**: Save room checklist data
**Authentication**: Required
**Parameters**:
```json
{
    "room_number": "101A",
    "company_name": "ABC Construction",
    "checklist_date": "2025-06-12",
    "water_meter_reading": "12345678",
    "electricity_meter_reading": "87654321",
    "checklist_items_data": "{...json data...}",
    "handover_signature_data": "{...signature json...}",
    "takeover_signature_data": "{...signature json...}"
}
```
**Response**: JSON with success status and record ID

##### GET /room-inventory-records
**Purpose**: Display room inventory records with filtering
**Authentication**: Required
**Parameters**:
- `room` (optional): Filter by room number
- `company` (optional): Filter by company name
- `date_from` (optional): Start date filter
- `date_to` (optional): End date filter
**Response**: HTML page with filtered records

##### GET /export-checklist-pdf/<int:checklist_id>
**Purpose**: Generate PDF report for specific checklist
**Authentication**: Required
**Parameters**: `checklist_id` in URL
**Response**: PDF file download

#### Offense Management Endpoints

##### GET /offense-reporting
**Purpose**: Display offense reporting form
**Authentication**: Required
**Permissions**: offense form access
**Response**: HTML offense form

##### POST /offense-reporting/submit
**Purpose**: Submit new offense report
**Authentication**: Required
**Parameters**:
```json
{
    "case_number": "OFF-2025-001",
    "offense_type": "Disciplinary",
    "severity": "Major",
    "offender_name": "John Doe",
    "fin_number": "S1234567A",
    "nationality": "Singapore",
    "offender_room": "101A",
    "description": "Violation description",
    "incident_date": "2025-06-12",
    "incident_time": "14:30",
    "documentary_proof": true,
    "financial_penalty_imposed": true,
    "penalty_amount": 50.00,
    "incident_photo_1": "base64_encoded_image",
    "witness_names": "Jane Smith, Bob Johnson"
}
```
**Response**: JSON with success status and record ID

##### GET /offense-records
**Purpose**: Display offense records with filtering
**Authentication**: Required
**Parameters**:
- `status` (optional): Filter by case status
- `severity` (optional): Filter by severity level
- `date_from` (optional): Start date filter
- `date_to` (optional): End date filter
**Response**: HTML page with filtered records

#### QR Code Management Endpoints

##### GET /qr-management
**Purpose**: Display QR code management interface
**Authentication**: Required
**Permissions**: QR generation access
**Response**: HTML QR management page

##### POST /generate-qr
**Purpose**: Generate new QR code
**Authentication**: Required
**Parameters**:
```json
{
    "qr_type": "form",
    "reference_id": "12",
    "reference_table": "form_templates",
    "label": "Room Checklist QR",
    "description": "QR code for room inventory checklist"
}
```
**Response**: JSON with QR code data and image

##### GET /qr/<string:qr_code>
**Purpose**: Handle QR code scanning and redirection
**Authentication**: Optional (depends on form settings)
**Parameters**: `qr_code` in URL
**Response**: Redirect to appropriate form or language selection

#### Form System Endpoints

##### GET /form/<int:form_id>
**Purpose**: Display dynamic form by ID
**Authentication**: Optional (depends on form settings)
**Parameters**: 
- `form_id` in URL
- `lang` (optional): Language code for multilingual forms
**Response**: HTML form in requested language

##### POST /form/<int:form_id>/submit
**Purpose**: Submit form data
**Authentication**: Optional (depends on form settings)
**Parameters**:
```json
{
    "form_data": {
        "field1": "value1",
        "field2": "value2"
    },
    "language": "en"
}
```
**Response**: JSON with submission confirmation

#### Admin Endpoints

##### GET /admin
**Purpose**: Display admin dashboard
**Authentication**: Required (admin role)
**Response**: HTML admin interface

##### POST /admin/create-user
**Purpose**: Create new user account
**Authentication**: Required (admin role)
**Parameters**:
```json
{
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "organization_id": 1,
    "form_permissions": [
        {
            "form_template_id": 12,
            "can_create": true,
            "can_view": true,
            "can_generate_qr": false
        }
    ]
}
```
**Response**: JSON with user creation status

##### GET /admin/users
**Purpose**: List all users with management options
**Authentication**: Required (admin role)
**Response**: HTML user list page

##### POST /admin/edit-user/<string:user_id>
**Purpose**: Update user information and permissions
**Authentication**: Required (admin role)
**Parameters**: User data and permission updates
**Response**: JSON with update status

### Error Handling

#### Standard HTTP Status Codes
- `200`: Success
- `201`: Created successfully
- `400`: Bad request (validation errors)
- `401`: Unauthorized (authentication required)
- `403`: Forbidden (insufficient permissions)
- `404`: Not found
- `500`: Internal server error

#### Error Response Format
```json
{
    "error": true,
    "message": "Descriptive error message",
    "code": "ERROR_CODE",
    "details": {
        "field": "validation_error_details"
    }
}
```

### Authentication & Security

#### JWT Token Structure
```json
{
    "sub": "user_id",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "profile_image_url": "https://...",
    "exp": 1735689600,
    "iat": 1735603200
}
```

#### Permission Validation
Each protected route validates:
1. User authentication status
2. Organization membership
3. Form-specific permissions
4. Action-level authorization

#### Session Management
- Sessions stored in Flask session with secure cookies
- Browser session keys for OAuth token storage
- Automatic session refresh for expired tokens

### Data Export Formats

#### Excel Export Structure
**Assets Export**:
- Asset Name, Description, Category, Status
- Quantity, Location, Serial Number
- Purchase Date, Purchase Cost, Created By
- Created Date, Last Updated

**Room Inventory Export**:
- Room Number, Company Name, Checklist Date
- Water/Electricity Meter Readings
- Checklist Items Status, Signatures
- Created By, Created Date

**Offense Records Export**:
- Case Number, Offense Type, Severity
- Offender Details (Name, FIN, Room, Company)
- Incident Details (Date, Time, Location, Description)
- Penalty Information, Status, Created Date

#### PDF Report Structure
**Room Checklist PDF**:
- Header with company and room details
- Comprehensive checklist items with status
- Meter readings with signatures
- Photo documentation
- Digital signature verification

### Rate Limiting & Performance

#### Request Limits
- Authentication: 10 requests/minute per IP
- Form submission: 5 submissions/minute per user
- QR generation: 20 QR codes/hour per user
- Data export: 10 exports/hour per user

#### Performance Optimizations
- Database query optimization with indexes
- Image compression for photo uploads
- Lazy loading for large data sets
- Caching for frequently accessed data

### Integration Guidelines

#### Webhook Support
Currently not implemented, but designed for future webhook integration:
- Form submission notifications
- User activity alerts
- System status updates

#### API Versioning
Current API version: v1
Future versions will maintain backward compatibility

#### External Service Integration
- Email notifications (planned)
- SMS alerts (planned)
- Document storage services (planned)
- Business intelligence tools (planned)

---

**API Version**: 1.0.0  
**Last Updated**: June 12, 2025  
**Base URL**: `https://your-repl-domain.replit.app`  
**Authentication**: Replit OAuth 2.0  
**Content-Type**: `application/json` for API calls, `multipart/form-data` for file uploads