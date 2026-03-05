# Mini Web Security Demo (Flask)

This project is a small Flask web application created for learning web security concepts.

It demonstrates common vulnerabilities and their secure fixes.

## Branches

- **vulnerable** → intentionally vulnerable version
- **secure** → fixed secure implementation

## Features

- Register / Login system
- Comment system
- Admin panel
- Search functionality

## Vulnerabilities Demonstrated (vulnerable branch)

- SQL Injection
- Stored XSS
- Broken Access Control
- Hardcoded Admin Role
- Missing CSRF protection

## Security Fixes (secure branch)

- Parameterized SQL queries
- Escaped HTML output
- Role-based access control
- Password hashing with bcrypt
- CSRF tokens in forms

## Run Locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python -c "from db import init_db; init_db()"
python app.py