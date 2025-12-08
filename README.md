# Secure Health Vault

Secure Health Vault is an information-security focused medical records portal built for coursework in Information Security. It demonstrates how to combine strong data-at-rest protection with role-based access control, encrypted search, and audit-friendly workflows for administrators, doctors, and patients.

## Quick Start (TL;DR)
1. **Clone & enter** the repository.
2. **Create a virtual environment** and install dependencies:
	```cmd
	python -m venv venv
	venv\Scripts\activate
	pip install -r requirements.txt
	```
3. **Copy environment secrets** from `.env.example` to `.env` and fill in `SECRET_KEY`, `FERNET_KEY`, `HMAC_KEY`, and `SQLALCHEMY_DATABASE_URI`.
4. **Start MySQL** and ensure the target schema exists (see *Database Setup* below).
5. **Bootstrap the schema** with `database\schema.sql` or let SQLAlchemy create tables on first run.
6. **Run the server**:
	```cmd
	venv\Scripts\activate
	python run.py
	```
	The app listens on `http://127.0.0.1:5000/`; use the landing page to choose a role and log in with credentials you create via the admin portal.

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
1. Activate your environment (`venv\Scripts\activate`).
2. Confirm MySQL is running and the `SQLALCHEMY_DATABASE_URI` in `.env` points to the correct schema/user.
3. (First run) execute `python run.py` once to let SQLAlchemy call `db.create_all()`; if you already imported `database\schema.sql`, this step simply verifies connectivity.
4. Start the dev server:
	```cmd
	python run.py
	```
5. Navigate to `http://127.0.0.1:5000/`, choose a role, and sign in. Create your first admin account directly in the database if none exists, then use the admin UI to provision doctors/patients.

## Security Design Notes
- **Data at Rest:** Only encrypted blobs are stored for names, emails, titles, and health records. Even if the database leaks, plaintext identities remain protected.
- **Search:** Keyword hashes allow exact matches, while normalized plaintext copies enable controlled fuzzy matches (substring) without exposing full content.
- **Access Control:** Flask decorators (`role_required`) enforce role segregation. Doctors can only modify records for patients explicitly assigned by an admin.
- **Login Hardening:** Flask-Limiter caps login attempts (5/min per IP + identifier), and persistent failures trigger a 10-minute server-side lockout recorded in the database.
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

## Documentation
- `docs/development_security_report.md` — detailed walkthrough of the development process, architecture decisions, and security controls for auditors and maintainers.

## Roadmap Suggestions
- Add user-driven password resets with mandatory rotation on first login.
- Integrate audit logging (success/failure events) for deeper security analysis.
- Expand keyword extraction using medical ontologies (e.g., SNOMED) or NLP pipelines.
- Deploy behind HTTPS with mutual TLS for real-world hardening.

## Acknowledgements
Built as part of the Information Security course project to demonstrate applied cryptography, secure web development, and privacy-aware database design.