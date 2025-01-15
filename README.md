# Secure File Share Backend

The backend of the **Secure File Sharing Application** is built using Django. It provides a secure and robust backend to handle file sharing, user role management, and secure API endpoints.

Switch to master branch for source code and then perform the below steps

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

# Authentication Guide

This guide explains the steps to authenticate users and obtain an access token for using other endpoints in the application.

---

## API Endpoints

### 1. Register a User
**Endpoint:**
`POST http://localhost:8000/api/users/register/`

**Payload:**
```json
{
  "username": "guest-6",
  "email": "",
  "password": "guest123",
  "role": "Guest"
}
```

Notes:

The role field must be one of the following:
Guest: No email is required.
Regular User: Requires an email for TOTP (Time-Based One-Time Password). The email-based TOTP functionality is currently disabled but can be enabled by uncommenting the email-related code. For now, the OTP will be printed on the console.
Admin: Same behavior as Regular User for email.
2. Login a User
Endpoint: POST http://localhost:8000/api/users/login/

Payload:

json
Copy code
{
  "username": "guest-6",
  "password": "guest123"
}
Notes:

If logging in as a Guest, no OTP verification is required.
For Regular User or Admin, an OTP will be generated and printed in the console (or sent via email if enabled).
3. Verify OTP
Endpoint: POST http://localhost:8000/api/users/verifyotp/

Payload:

json
Copy code
{
  "username": "guest-6",
  "otp": "123456"  // Replace with the OTP printed in the console
}
Notes:

After successful OTP verification, an access_token will be returned.
Use this access_token to authenticate and access other endpoints.
Example Workflow
Register a user:
Register as a Guest or Regular User (with email if email functionality is enabled).
Login:
Login with the registered username and password.
For Guest: No OTP is required.
For Regular User or Admin: Retrieve the OTP from the console (or email if enabled).
Verify OTP:
Use the OTP to verify and obtain the access_token.
Notes
Ensure the backend server is running on localhost:8000 for these endpoints.
Uncomment the email-related code in the backend if you want to enable email-based TOTP for MFA.
Keep the access_token secure and include it in the headers of subsequent requests as Authorization: Bearer <access_token>.

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

