# Secure Health Vault

Secure Health Vault is an information-security focused medical records portal built for coursework in Information Security. It demonstrates how to combine strong data-at-rest protection with role-based access control, encrypted search, and audit-friendly workflows for administrators, doctors, and patients.

## Why This Project Matters
- Protects highly sensitive health information with opinionated defaults and minimal trust in the database layer.
- Illustrates core course concepts: symmetric encryption, keyed hashing, least privilege, secure credential handling, and defense-in-depth for web apps.
- Provides a realistic scenario for exploring secure schema design, encrypted search indexing, and multi-tenant access controls.

## Key Features
- **End-to-end encryption** of health record titles, body text, and all user identifiers (admins, doctors, patients) using Fernet/AES.
- **Deterministic lookup hashes** (HMAC-SHA256) for usernames, emails, and search keywords, enabling secure equality checks without exposing plaintext.
- **Automatic keyword extraction** from record content plus optional user-supplied tags to power partial and exact search.
- **Role-specific dashboards** for admins, doctors, and patients with contextual insights, recent activity, and filtered record views.
- **Granular doctor–patient access control** so only assigned doctors can create or view a patient’s encrypted records.
- **Client-side credential hashing** prior to submission, reducing plaintext password exposure in transit and logs.
- **Audit-friendly schema** with created-at timestamps and immutable relationships for classroom discussions on logging and accountability.

## Architecture Overview
- **Frontend:** Flask templates (Bootstrap, Font Awesome) rendered server-side with progressive enhancement callbacks for password hashing.
- **Backend:** Flask + SQLAlchemy, modularized into `app/` (routes, models, security helpers) and `database/` (schema, migrations).
- **Security Layer:**
	- `app/security/encryption.py` wraps Fernet for symmetric encryption/decryption.
	- `app/security/search_index.py` normalizes keywords, computes HMAC hashes, and extracts salient tokens from record bodies.
- **Database:** MySQL 8.x with carefully designed lookup columns, cascade rules, and keyword indices (`database/schema.sql`).

## Getting Started
### Prerequisites
- Python 3.11+
- MySQL 8.x (tested with 8.0.20)
- Recommended: virtual environment (`python -m venv venv`)

### Installation
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Environment Configuration
Copy `.env.example` to `.env` (create the file if it does not exist) and set:
- `SECRET_KEY` – Flask session secret
- `FERNET_KEY` – base64url-encoded key for Fernet (generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
- `HMAC_KEY` – base64url string for keyword/identity hashing
- `SQLALCHEMY_DATABASE_URI` – e.g. `mysql+pymysql://user:password@localhost/securehealthvault_db`

### Database Setup
1. Ensure the target MySQL schema exists: `CREATE DATABASE securehealthvault_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
2. Apply the baseline structure:
	 ```powershell
	 mysql -u root -p securehealthvault_db < database\schema.sql
	 ```
3. Optionally seed initial admin/doctor/patient records through the admin UI or via custom inserts (encrypt fields with project helpers for consistency).

### Running the Application
```powershell
venv\Scripts\activate
python run.py
```
The server defaults to `http://127.0.0.1:5000/`. Log in using the role selector and credentials created from the admin panel.

## Security Design Notes
- **Data at Rest:** Only encrypted blobs are stored for names, emails, titles, and health records. Even if the database leaks, plaintext identities remain protected.
- **Search:** Keyword hashes allow exact matches, while normalized plaintext copies enable controlled fuzzy matches (substring) without exposing full content.
- **Access Control:** Flask decorators (`role_required`) enforce role segregation. Doctors can only modify records for patients explicitly assigned by an admin.
- **Credential Handling:** Admins provision passwords; users should rotate them after first login via future self-service flows. Hashes are stored exactly as submitted, so integrate a password hashing library (e.g., Argon2) if migrating beyond course scope.
- **Environment Secrets:** Keys are intentionally externalized. Never commit `.env`; rotate keys if compromise is suspected.

## Testing
The `tests/` directory is prepared for pytest-based suites. To run tests once implemented:
```powershell
venv\Scripts\activate
pytest
```

## Operations & Maintenance
- **Keyword Re-indexing:** `_update_keyword_index` in `app/routes.py` controls keyword sync. Re-save a record if you change extraction rules.
- **Auto-increment IDs:** MySQL `AUTO_INCREMENT` values continue after deletions. Use `ALTER TABLE <table> AUTO_INCREMENT = <n>` for lab resets only.
- **Backups:** Always export encrypted data and store keys separately. Without the Fernet/HMAC keys the data is unreadable by design.

## Roadmap Suggestions
- Add user-driven password resets with mandatory rotation on first login.
- Integrate audit logging (success/failure events) for deeper security analysis.
- Expand keyword extraction using medical ontologies (e.g., SNOMED) or NLP pipelines.
- Deploy behind HTTPS with mutual TLS for real-world hardening.

## Acknowledgements
Built as part of the Information Security course project to demonstrate applied cryptography, secure web development, and privacy-aware database design.