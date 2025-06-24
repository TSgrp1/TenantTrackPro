# Pioneer Lodge Dormitory Management System
## Comprehensive System Documentation

### Overview
The Pioneer Lodge Dormitory Management System is a comprehensive multi-tenant web application developed for TS Management Services Pte Ltd (tsgrp.sg). This system streamlines dormitory administration through advanced digital technologies, providing efficient management of assets, room inventories, offense reporting, and user permissions.

### Key Technologies
- **Backend**: Flask web framework with Python 3.11
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: Replit OAuth integration with role-based access control
- **Frontend**: Bootstrap 5 with responsive design
- **Document Generation**: ReportLab for PDF generation, Pandas for Excel exports
- **QR Code Management**: Dynamic QR code generation and scanning

### System Architecture

#### Multi-Tenant Structure
The system supports multiple organizations with isolated data:
- **Organizations**: Independent dormitory facilities
- **Users**: Role-based access with granular permissions
- **Assets**: Organization-specific inventory management
- **Forms**: Customizable templates per organization

#### Core Modules

##### 1. User Management & Authentication
- **Replit OAuth Integration**: Secure login with Google, GitHub, X, Apple, email/password
- **Role-Based Access Control**: Admin, Manager, Staff, and custom roles
- **Permission System**: Granular form-level permissions (create, view, generate QR)
- **Multi-Tenant Security**: Organization-level data isolation

##### 2. Asset Management System
- **Asset Categories**: Configurable item classifications
- **Inventory Tracking**: Real-time quantity and status monitoring
- **Asset Statuses**: Active, Inactive, Room, Store, Clear, Other
- **Purchase Management**: Cost tracking and purchase date records
- **Serial Number Tracking**: Unique identifier management

##### 3. Room Inventory & Handover System
- **Room Checklist Management**: Comprehensive room condition tracking
- **Handover Processes**: Detailed occupant transition workflows
- **Meter Readings**: Water and electricity consumption tracking
- **Digital Signatures**: Electronic signature capture for handovers
- **Condition Documentation**: Before/after status with photo evidence

##### 4. Offense Reporting & Disciplinary Management
- **Incident Documentation**: Comprehensive offense record keeping
- **Severity Classification**: Minor, Major, Critical incident levels
- **Financial Penalties**: Penalty tracking and payment status
- **Photo Evidence**: Multi-image incident documentation
- **Digital Signatures**: Resident and duty manager verification
- **Case Management**: Status tracking from Open to Closed

##### 5. Multilingual Form System
- **Language Support**: Bengali, Myanmar, Tamil, Chinese, English
- **Dynamic Forms**: JSON-based customizable form structures
- **QR Code Integration**: Single QR leads to language selection
- **Regulation Display**: Text, PDF, and image format support
- **Reference Photos**: Visual guidance materials

##### 6. QR Code Management
- **Dynamic Generation**: Automatic QR code creation for assets, rooms, forms
- **Scan Tracking**: Usage analytics and access logs
- **Public Access**: Guest access for specific form types
- **Reference Linking**: Cross-module QR associations

##### 7. Reporting & Analytics
- **Excel Export**: Comprehensive data export functionality
- **PDF Generation**: Professional document creation
- **Filter Systems**: Advanced search and filtering capabilities
- **Dashboard Analytics**: Real-time system metrics

### Database Schema

#### Core Tables
1. **Users**: Authentication and profile management
2. **Organizations**: Multi-tenant organization data
3. **Assets**: Inventory item management
4. **AssetCategories**: Item classification system
5. **FormTemplates**: Dynamic form definitions
6. **QRCodes**: QR code management and tracking
7. **RoomInventoryChecklists**: Room condition tracking
8. **OffenseRecords**: Disciplinary incident management
9. **UserFormPermissions**: Granular access control
10. **SystemLogs**: Audit trail and activity logging

#### Key Relationships
- Users belong to Organizations (many-to-one)
- Assets belong to Organizations and Categories
- Forms have User Permissions (many-to-many)
- QR Codes link to multiple entity types
- All records maintain audit trails

### Security Features

#### Authentication & Authorization
- **OAuth Integration**: Secure third-party authentication
- **Session Management**: Persistent login sessions
- **Permission Validation**: Route-level access control
- **Data Isolation**: Organization-specific data access

#### Data Protection
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Input sanitization
- **CSRF Protection**: Token-based request validation
- **Audit Logging**: Comprehensive activity tracking

### User Interface Features

#### Responsive Design
- **Mobile-First**: Optimized for mobile devices
- **Bootstrap Integration**: Professional UI components
- **Dark Theme**: Replit-branded dark mode design
- **Accessibility**: WCAG compliance considerations

#### User Experience
- **Intuitive Navigation**: Role-based menu systems
- **Real-time Feedback**: Toast notifications and alerts
- **Progressive Enhancement**: Graceful fallbacks
- **Search & Filter**: Advanced data discovery tools

### API Endpoints

#### Authentication Routes
- `/auth/login` - Replit OAuth login
- `/auth/logout` - Session termination
- `/auth/error` - Authentication error handling

#### Core Application Routes
- `/` - Dashboard and home page
- `/admin` - Administrative interface
- `/assets` - Asset management
- `/room-checklist` - Room inventory management
- `/offense-reporting` - Incident reporting
- `/qr-management` - QR code administration

#### Data Export Routes
- `/export/assets` - Asset data export
- `/export/checklist` - Room inventory export
- `/export/offenses` - Offense records export

### Deployment & Configuration

#### Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `SESSION_SECRET` - Flask session encryption key
- `REPL_ID` - Replit application identifier
- `ISSUER_URL` - OAuth provider endpoint

#### Production Requirements
- **Database**: PostgreSQL 12+
- **Python**: 3.11+
- **Memory**: 512MB minimum
- **Storage**: 2GB+ for file uploads

### Maintenance & Monitoring

#### System Logs
- **User Activity**: Login/logout tracking
- **Data Changes**: CRUD operation logging
- **Error Tracking**: Exception and error logging
- **Performance Metrics**: Response time monitoring

#### Backup Procedures
- **Database Backups**: Automated PostgreSQL dumps
- **File Storage**: Document and image backups
- **Configuration**: Environment variable backup

### Future Enhancements

#### Planned Features
- **Mobile Application**: Native iOS/Android apps
- **Advanced Analytics**: Business intelligence dashboard
- **Integration APIs**: Third-party system connections
- **Automated Workflows**: Email notifications and alerts
- **Document Management**: Enhanced file storage system

#### Scalability Considerations
- **Load Balancing**: Multi-instance deployment
- **Caching Layer**: Redis integration
- **CDN Integration**: Static asset optimization
- **Database Optimization**: Query performance tuning

### Support & Documentation

#### User Guides
- **Administrator Manual**: Complete admin functionality guide
- **User Training**: Role-specific operation procedures
- **API Documentation**: Developer integration guide
- **Troubleshooting**: Common issue resolution

#### Technical Support
- **Issue Tracking**: Bug reporting and resolution
- **Feature Requests**: Enhancement proposal process
- **System Updates**: Version management and deployment
- **Training Materials**: Video tutorials and documentation

### Compliance & Standards

#### Data Privacy
- **GDPR Compliance**: European data protection standards
- **Data Retention**: Configurable retention policies
- **User Consent**: Explicit permission management
- **Data Portability**: Export and deletion capabilities

#### Industry Standards
- **Security Best Practices**: OWASP guidelines
- **Accessibility**: WCAG 2.1 AA compliance
- **Performance**: Web Core Vitals optimization
- **Code Quality**: PEP 8 Python standards

---

**Version**: 1.0.0  
**Last Updated**: June 12, 2025  
**Developed by**: TS Management Services Pte Ltd  
**Contact**: support@tsgrp.sg