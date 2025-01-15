# Secure File Share Backend

The backend of the **Secure File Sharing Application** is built using Django. It provides a secure and robust backend to handle file sharing, user role management, and secure API endpoints.

## Features
- **User Role Management**: Admin, Regular User, Guest
- **Secure File Sharing**: Upload and download files securely
- **JWT Authentication**: Token-based authentication for secure APIs
- **CORS Enabled**: For seamless frontend-backend interaction
- **Email Notifications**: For user account actions and file sharing events

---

## 🛠️ Setup Instructions

### 1. Clone the Repository
```bash
git clone <backend-repo-url>
cd secure-file-share-backend
```

### 2. Environment Variables
Create a .env file in the root directory:

```plaintext
SECRET_KEY=<your-secret-key>
EMAIL_HOST_USER=<your-email>
EMAIL_HOST_PASSWORD=<your-email-password>
```

### 3. Run with Docker
Ensure Docker and Docker Compose are installed on your system.

```bash
Copy code
docker-compose up --build
```

### 4. Access the Application
Backend API: http://localhost:8000
API Documentation (if configured): http://localhost:8000/docs
⚙️ Development Setup (Without Docker)
Install dependencies:
```bash
pip install -r requirements.txt
```

Run migrations:
```bash
python manage.py migrate
```

Start the development server:
```bash
python manage.py runserver
```

🔒 API Authentication

Obtain a JWT token:
Endpoint: /api/token/

Use the token in API requests:
```plaintext
Header: Authorization: Bearer <token>
```

🧪 Testing
Run the test suite:

```bash
python manage.py test
```

🐳 Docker Commands
Start the application:
```bash
docker-compose up --build
```
Stop containers:
```bash
docker-compose down
```

🔧 Technologies Used
Django 4.2
Django REST Framework
SQLite (development database)
Docker & Docker Compose
JWT Authentication
Email Services (SMTP)
yaml

