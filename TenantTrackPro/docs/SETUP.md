# Setup Guide

## Quick Start

### 1. Environment Setup

Create a `.env` file in the project root:

```env
# Required
DATABASE_URL=your-supabase-connection-string
SECRET_KEY=your-random-secret-key

# Optional
FLASK_ENV=development
PORT=5000
```

### 2. Supabase Database Setup

1. **Create Supabase Project**
   - Go to [supabase.com](https://supabase.com)
   - Create new project
   - Note your project URL and database password

2. **Get Connection String**
   - Project Settings → Database → Connection string
   - Copy the "URI" format
   - Replace `[YOUR-PASSWORD]` with your actual password

   Example:
   ```
   postgresql://postgres:your-password@db.your-project.supabase.co:5432/postgres
   ```

3. **Set Environment Variable**
   ```bash
   export DATABASE_URL="postgresql://postgres:your-password@db.your-project.supabase.co:5432/postgres"
   ```

### 3. Run Application

#### Option A: Using the main app file (Current method)
```bash
python main.py
```

#### Option B: Using the new runner (Recommended for production)
```bash
python run.py
```

#### Option C: Using Gunicorn (Production)
```bash
gunicorn --bind 0.0.0.0:5000 run:app
```

## Project Structure Overview

```
├── run.py                 # New application runner (recommended)
├── main.py               # Original entry point (fallback)
├── app.py                # Flask app configuration
├── auth.py               # Authentication setup
├── routes.py             # All application routes
├── models*.py            # Database models
├── templates/            # HTML templates
├── static/              # CSS, JS, images
│   ├── css/custom.css   # Custom styling
│   └── js/purchase.js   # Purchase form functionality
├── uploads/             # File uploads directory
├── docs/                # Documentation
│   ├── SETUP.md         # This file
│   ├── DEPLOYMENT.md    # Deployment guide
│   └── API.md           # API documentation
└── .env.example         # Environment template
```

## Features Verification Checklist

After setup, verify these features work:

### Purchase Management
- [ ] Access Purchase dropdown menu
- [ ] Create stock items in Stock Storage
- [ ] Items appear in Purchase Form dropdowns
- [ ] E-signatures work on canvas areas
- [ ] Form submission saves to Purchase Form Storage
- [ ] PDF download works from storage

### Database Operations
- [ ] User login/logout
- [ ] Data persistence across sessions
- [ ] Multi-tenant organization separation

### File Operations
- [ ] File uploads work
- [ ] PDF generation works
- [ ] Static files serve correctly

## Troubleshooting

### Database Connection Issues

1. **Connection Failed**
   ```bash
   # Check DATABASE_URL format
   echo $DATABASE_URL
   
   # Test connection manually
   psql $DATABASE_URL -c "SELECT 1;"
   ```

2. **Old Endpoint Error**
   - Remove old DATABASE_URL
   - Use new Supabase connection string
   - Restart application

3. **SQLite Fallback**
   - App automatically uses SQLite if PostgreSQL fails
   - Data stored in `app.db` file
   - Safe for development/testing

### Application Errors

1. **Import Errors**
   ```bash
   # Install missing dependencies
   pip install -r requirements.txt
   
   # Or install individually
   pip install flask flask-sqlalchemy psycopg2-binary
   ```

2. **Template Not Found**
   - Check templates/ directory exists
   - Verify file names match route references

3. **Static Files 404**
   - Check static/ directory structure
   - Verify file paths in templates

### Permission Issues

1. **File Upload Errors**
   ```bash
   # Create upload directory
   mkdir -p uploads
   chmod 755 uploads
   ```

2. **Database Permission**
   - Check Supabase user permissions
   - Verify connection string includes correct credentials

## Development Tips

### Local Development
- Use `FLASK_ENV=development` for debug mode
- SQLite fallback allows offline development
- Check console logs for detailed error messages

### Database Schema Updates
```python
# In Python shell or script
from app import db
db.create_all()  # Creates missing tables
```

### Adding New Features
1. Add models to appropriate `models_*.py` file
2. Create routes in `routes.py`
3. Add templates in `templates/`
4. Update navigation in `templates/base.html`

### Security Best Practices
- Use strong SECRET_KEY (32+ characters)
- Enable HTTPS in production
- Keep DATABASE_URL secret
- Regular security updates

## Support

### Common Commands
```bash
# Start application
python run.py

# Check database connection
python -c "from app import db; print('DB OK')"

# Create admin user (if auth system supports it)
python -c "from auth import create_pioneer_lodge_user; create_pioneer_lodge_user()"
```

### Log Analysis
- Check console output for errors
- Database connection status logged on startup
- Route registration confirms all features loaded

### Contact
For technical issues:
1. Check this documentation
2. Review error logs
3. Verify environment configuration
4. Test with SQLite fallback if needed