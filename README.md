# 🔐 Password Manager Project

A secure, scalable, and full-featured **Password Management System** built with **FastAPI** (Backend) and **PyQt5/Web Interface** (Frontend). It allows users to safely store and manage passwords, with authentication, encryption, and role-based access control.

The backend is configured to run 24/7 as a **Windows service** using **NSSM**, ensuring continuous availability.

---

## 🧩 Project Overview

- 🌐 **Frontend**: Simple user interface built using **HTML/CSS/JS** or **PyQt5**.
- ⚙️ **Backend**: REST API built with **FastAPI**, handling authentication, data storage, and encryption.
- 💾 **Database**: MySQL or SQLite for managing user credentials and metadata.
- 🔄 **Windows Service**: FastAPI backend runs as a Windows service using NSSM for persistent uptime.

---

## 📁 Project Structure

```

password-manager/
├── app/
│   ├── main.py               # FastAPI entrypoint
│   ├── models.py             # SQLAlchemy ORM models
│   ├── schemas.py            # Pydantic schemas
│   ├── crud.py               # CRUD logic + encryption
│   ├── auth.py               # JWT & authentication
│   ├── dependencies.py       # FastAPI dependencies
│   ├── database.py           # DB session setup
│   ├── utils.py              # Helper functions (e.g. password gen)
│   ├── config.py             # Environment & config loader
├── .env                      # Secret keys, DB URL, etc.
├── gui.py                    # PyQt5 GUI launcher
├── requirements.txt          # Project dependencies
├── dist/                     # Folder for generated .exe files
├── start\_server.bat          # Windows batch file to run via NSSM

```

---

## 🧱 Architecture Diagram

```

+--------------------+       		    +---------------------+        		+----------------------+
\|   Client Device    | <--------------->|   FastAPI Server     | <--------------->  |    Database          |
\| (Browser/Desktop)  |                  | (Uvicorn / ASGI)     |                   | (MySQL, SQLite)      |
+--------------------+                  +---------------------+                   +----------------------+
^
|
+-----------------------+
\|   Windows Service     |
\| (NSSM + Uvicorn)      |
+-----------------------+

````

---

## ⚙️ Technology Stack

### ✅ Backend
- **FastAPI** – High-performance Python web framework
- **Uvicorn** – ASGI server for serving FastAPI
- **SQLAlchemy / Tortoise ORM** – ORM for database operations
- **JWT** – User authentication tokens
- **Fernet (cryptography)** – For secure encryption
- **NSSM** – Runs FastAPI app as a Windows service
- **Pydantic** – Data validation and settings

### 🎨 Frontend
- **HTML5 / CSS3 / JavaScript** – Web-based frontend
- **Bootstrap** – UI styling and layout
- **PyQt5** – Optional GUI alternative for desktop use

### 🗃️ Database
- **MySQL** or **SQLite** – Persistent and portable relational databases

---

## 🔒 Security Features

### ✅ Authentication
- Secure JWT-based login
- Tokens must be sent in headers for protected routes

### 🔐 Encryption
- **TLS/SSL** for secure communication (suggested for deployment)
- Passwords are encrypted using **Fernet** before storage

### 🔐 Role-Based Access Control
- Different access levels for different types of users (e.g., Admin, User)

### 🛡️ Database Security
- Secure connections and limited DB user permissions

---

## 📋 Requirements

### Software
- Python 3.10+
- NSSM (Windows only, for service setup)
- MySQL or SQLite installed

### Python Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
````

Or manually:

```bash
pip install fastapi uvicorn sqlalchemy tortoise-orm python-dotenv \
cryptography passlib[bcrypt] python-jose PyQt5 requests pydantic
```

---

## 🚀 Deployment Guide

### 1. Backend Setup

* Configure your `.env` file with:

  * `FERNET_KEY`
  * `DATABASE_URL`
  * `SECRET_KEY`

* Run locally with:

```bash
uvicorn app.main:app --reload
```

### 2. Database Setup

* Use MySQL or SQLite
* Ensure required tables are created via ORM models

### 3. Package with NSSM (Windows Service)

Install NSSM and run the following steps:

1. Execute `nssm install password-manager`
2. Set **Path** to Python executable or `uvicorn.exe`
3. Set **Arguments** to:

   ```
   -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
4. Start the service with:

   ```
   nssm start password-manager
   ```

Now the backend runs as a **persistent background service**.

---

## 🖥️ Frontend Usage

* Launch the PyQt5 GUI (`gui.py`) or develop a web frontend using standard web tools.
* On login, the frontend receives a **JWT**, which is stored and used for further secure API requests.

---

## 🔄 Future Improvements

* 🧱 **Microservices Architecture** – Split core functions for scalability
* 🐳 **Dockerization** – Containerize the app for portability and CI/CD
* 🌐 **Multi-Factor Authentication (MFA)** – Extra layer of login security
* ⚖️ **Rate Limiting** – Prevent abuse via IP/user-based rate control
* 📈 **User Activity Logging** – Monitor and track sensitive actions
* 🖥️ **Load Balancer Integration** – For high-traffic environments (e.g., Nginx)

---

## ✅ Conclusion

This **Password Manager** project is a complete, secure, and user-friendly solution for managing sensitive credentials. It leverages **FastAPI** for backend performance, **JWT and Fernet** for security, and **NSSM** for reliable deployment on Windows.

With support for both GUI and web interfaces, and a modular backend design, this project is ideal for both personal and enterprise use.

---

## 👨‍💻 Author

**Behramm Umrigar**
GitHub: [@behramm10](https://github.com/behramm10)

---

## 📜 License

This project is open source and available under the **MIT License**.
