# Deployment Guide

## Supabase Setup

### 1. Create Supabase Project

1. Go to [Supabase](https://supabase.com) and create a new project
2. Choose your organization and project name
3. Select a region closest to your users
4. Set a secure database password

### 2. Get Database Connection String

1. Go to Project Settings → Database
2. Copy the connection string under "Connection string"
3. Replace `[YOUR-PASSWORD]` with your actual database password

Example:
```
postgresql://postgres:your-password@db.project-ref.supabase.co:5432/postgres
```

### 3. Configure Environment Variables

Create a `.env` file with:
```env
DATABASE_URL=postgresql://postgres:your-password@db.project-ref.supabase.co:5432/postgres
SECRET_KEY=your-super-secret-key-here
FLASK_ENV=production
```

## Deployment Options

### Option 1: Vercel (Recommended)

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Create `vercel.json`:
   ```json
   {
     "version": 2,
     "builds": [
       {
         "src": "app_factory.py",
         "use": "@vercel/python"
       }
     ],
     "routes": [
       {
         "src": "/(.*)",
         "dest": "app_factory.py"
       }
     ],
     "env": {
       "DATABASE_URL": "@database_url",
       "SECRET_KEY": "@secret_key"
     }
   }
   ```

3. Deploy:
   ```bash
   vercel --prod
   ```

### Option 2: Heroku

1. Create `Procfile`:
   ```
   web: gunicorn app_factory:app
   ```

2. Deploy:
   ```bash
   git add .
   git commit -m "Deploy to Heroku"
   git push heroku main
   ```

### Option 3: Docker

1. Build image:
   ```bash
   docker build -t pioneer-management .
   ```

2. Run container:
   ```bash
   docker run -p 5000:5000 --env-file .env pioneer-management
   ```

## Security Checklist

- [ ] Use strong SECRET_KEY (32+ random characters)
- [ ] Set FLASK_ENV=production
- [ ] Enable HTTPS in production
- [ ] Configure secure session cookies
- [ ] Set up database connection limits
- [ ] Enable Supabase Row Level Security (RLS)
- [ ] Regular security updates

## Performance Optimization

### Database

1. Enable connection pooling
2. Add database indexes for frequently queried columns
3. Use Supabase's built-in performance monitoring

### Application

1. Enable Flask caching
2. Optimize static file serving
3. Use CDN for assets
4. Enable gzip compression

## Monitoring

### Supabase Dashboard

- Monitor database performance
- Check query analytics
- Review connection usage

### Application Monitoring

- Use logging for error tracking
- Monitor response times
- Set up health checks

## Backup Strategy

### Database Backup

Supabase provides automatic backups, but you can also:

1. Create manual backups
2. Download database dumps
3. Set up regular backup schedules

### File Backup

For uploaded files:

1. Use cloud storage (AWS S3, Google Cloud)
2. Set up regular sync
3. Version control important documents

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check DATABASE_URL format
   - Verify Supabase project is active
   - Check password and project reference

2. **Import Errors**
   - Ensure all dependencies in requirements.txt
   - Check Python version compatibility

3. **Permission Errors**
   - Verify file upload permissions
   - Check database user permissions

### Debug Mode

For development debugging:
```bash
FLASK_ENV=development python app_factory.py
```

### Database Migration

If schema changes are needed:
```python
# In Python shell
from app_factory import db
db.create_all()
```

## Support

For deployment issues:
1. Check Supabase logs
2. Review application logs
3. Verify environment variables
4. Test database connectivity