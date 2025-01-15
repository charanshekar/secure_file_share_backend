# secure_file_share_backend

Backend (Django): secure-file-share-backend
Overview
The backend of the Secure File Sharing application is built using Django, designed to handle secure file sharing among three user roles (Admin, Regular User, and Guest). The backend is fully Dockerized for ease of deployment and integrates REST APIs, JWT-based authentication, and email notifications.

Features
User role management: Admin, Regular User, Guest
Secure file upload/download APIs
JWT-based authentication and session management
CORS enabled for seamless frontend-backend interaction
Email notifications for account creation and file sharing
Setup Instructions
Clone the Repository

bash
Copy code
git clone <backend-repo-url>
cd secure-file-share-backend
Environment Variables Create a .env file in the root directory to store sensitive data:

plaintext
Copy code
SECRET_KEY=<your-secret-key>
EMAIL_HOST_USER=<your-email>
EMAIL_HOST_PASSWORD=<your-email-password>
Run with Docker Ensure Docker and Docker Compose are installed on your system.

bash
Copy code
docker-compose up --build
Access the Application

The backend will be available at: http://localhost:8000
API documentation (if added) can be accessed at: http://localhost:8000/docs
Development Setup
For local development without Docker:

Install dependencies:

bash
Copy code
pip install -r requirements.txt
Run migrations:

bash
Copy code
python manage.py migrate
Start the server:

bash
Copy code
python manage.py runserver
API Authentication
Use JWT for API authentication.
Obtain a token via the /api/token/ endpoint.
Include the token in API requests using the Authorization: Bearer <token> header.
Testing
Run tests with:

bash
Copy code
python manage.py test
Docker Commands
Build and start the container:
bash
Copy code
docker-compose up --build
Stop containers:
bash
Copy code
docker-compose down
