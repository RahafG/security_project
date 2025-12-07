This is a Simple Flask web application demonstrating five vulnerabilities and their fixes.
- Vulnerable endpoints are suffixed with _vuln
- Fixed endpoints are the default ones

Features implemented:
- User registration & login (vulnerable: SQL injection + MD5 password)
- Fixed: parameterized queries + bcrypt
- Comments that demonstrate XSS (vulnerable) and fixed with Bleach
- Role-based access control (RBAC): vulnerable admin page and fixed decorator
- Encryption of a sensitive field (phone) using Fernet
- HTTPS (instructions below) and secure cookie settings via Flask config
 
Dependencies:
pip install flask bcrypt cryptography bleach flask-talisman

Initialize DB:
python secure_flask_app.py --init-db

Create demo admin (resets DB then creates admin):
python secure_flask_app.py --create-admin

Run with self-signed cert (for TLS locally):
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
python secure_flask_app.py --cert cert.pem key.pem

Testing SQL injection (vulnerable login):
On /login_vuln enter username: ' OR '1'='1 and any password -> should bypass login

XSS testing:
Post a comment on /comment with: <script>alert('xss')</script>
View on /comments_vuln to see the alert, /comments to see sanitized output

RBAC testing:
Visit /admin_vuln to see admin page without login. Visit /admin as non-admin -> 403.
Login as demo admin (username=admin password=adminpass) to access /admin.

Notes on encryption and TLS:
- The phone is encrypted at rest using Fernet. In production, the Fernet key must be stored securely
(e.g., an HSM or environment variable in a protected secret manager).
- TLS should be used in production; the example shows how to run with a self-signed cert for local testing.
- Session cookie settings set Secure and HttpOnly to protect tokens in transit and from JS.

Security improvements you can add:
- Rate limiting on login endpoints
- Account lockout after repeated failed attempts
- CSRF protection (Flask-WTF or custom tokens)
- Use a real database server with proper access controls
- Use a proper key management service for encryption keys

