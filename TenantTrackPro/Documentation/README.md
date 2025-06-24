# Pioneer Management System

A comprehensive management system for Pioneer Lodge operations, including purchase management, meter readings, room inspections, and more.

## Features

- **Purchase Management**: Complete purchase requisition workflow with e-signatures
- **Meter Readings**: Water and electricity meter tracking for companies and rooms
- **Room Inspections**: Digital checklist system with photo uploads
- **Asset Management**: Track and manage organizational assets
- **User Management**: Role-based access control and permissions
- **Multi-tenant**: Organization-based data separation

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: PostgreSQL (Supabase) with SQLite fallback
- **Frontend**: Bootstrap 5, vanilla JavaScript
- **Authentication**: Flask-Login with OAuth support
- **File Storage**: Local filesystem with configurable paths

## Installation

### Prerequisites

- Python 3.8+
- PostgreSQL (or Supabase account)
- pip (Python package manager)

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd pioneer-management-system
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Set up database**
   
   **Option A: Supabase (Recommended)**
   - Create a Supabase project at https://supabase.com
   - Get your database URL from Project Settings → Database → Connection string
   - Update DATABASE_URL in .env

   **Option B: Local PostgreSQL**
   ```bash
   createdb pioneer_management
   # Update DATABASE_URL in .env
   ```

6. **Run the application**
   ```bash
   python app_factory.py
   ```

   The application will be available at `http://localhost:5000`

## Deployment

### Supabase + Vercel/Heroku

1. **Prepare for deployment**
   ```bash
   # Ensure all dependencies are in requirements.txt
   pip freeze > requirements.txt
   ```

2. **Set environment variables**
   - `DATABASE_URL`: Your Supabase PostgreSQL connection string
   - `SECRET_KEY`: A secure random string
   - `FLASK_ENV`: Set to `production`

3. **Deploy to Vercel**
   ```bash
   npm i -g vercel
   vercel --prod
   ```

   Or deploy to Heroku:
   ```bash
   git push heroku main
   ```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app_factory:app"]
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Application environment | `development` |
| `SECRET_KEY` | Flask secret key | Required |
| `DATABASE_URL` | PostgreSQL connection string | SQLite fallback |
| `PORT` | Application port | `5000` |
| `UPLOAD_FOLDER` | File upload directory | `uploads` |

### Database Configuration

The application automatically handles database configuration:
- **Production**: Uses Supabase PostgreSQL
- **Development**: Can use PostgreSQL or SQLite
- **Testing**: Uses in-memory SQLite

## Project Structure

```
├── src/                    # Source code
│   ├── config/            # Configuration modules
│   ├── models/            # Database models
│   ├── routes/            # Route handlers
│   ├── auth/              # Authentication
│   └── utils/             # Utility functions
├── templates/             # Jinja2 templates
├── static/               # Static assets
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript
│   └── images/           # Images
├── uploads/              # File uploads
├── docs/                 # Documentation
├── requirements.txt      # Python dependencies
├── app_factory.py       # Application entry point
└── README.md            # This file
```

## API Documentation

### Purchase Management

- `GET /purchase-form` - Purchase requisition form
- `POST /submit-purchase-form` - Submit purchase request
- `GET /purchase-form-storage` - View submitted forms
- `GET /api/purchase-request/<id>/pdf` - Download PDF

### Stock Management

- `GET /stock-storage` - Manage stock items
- `POST /api/stock-items` - Create stock item
- `PUT /api/stock-items/<id>` - Update stock item
- `DELETE /api/stock-items/<id>` - Delete stock item

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Contact the development team

## Changelog

### v2.0.0 (Current)
- Restructured for self-hosting
- Added Supabase support
- Improved purchase management
- Enhanced security and performance

### v1.0.0
- Initial release
- Basic functionality