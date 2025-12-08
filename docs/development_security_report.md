# Secure Health Vault — Development & Security Report

## 1. Project Overview
Secure Health Vault is a Flask + SQLAlchemy web portal that lets administrators, doctors, and patients collaborate on encrypted health records. The application was developed as an Information Security coursework project to demonstrate applied cryptography, secure data modeling, and least-privilege access controls suitable for sensitive medical data.

## 2. Development Process
1. **Requirements & Threat Modeling**
   - Scoped three primary personas (admin, doctor, patient) and mapped trust boundaries between browser, Flask server, and MySQL.
   - Identified high-value assets: personally identifiable information (PII), health record contents, and credential material.
   - Defined adversary capabilities (database leak, traffic inspection, role abuse) to drive defensive controls.

2. **Architecture & Data Modeling**
   - Chose Flask for rapid server-side rendering with clear separation of routes (`app/routes.py`), models (`app/models.py`), and security helpers (`app/security/`).
   - Designed the schema (`database/schema.sql`) with encrypted columns for identities, lookup hashes for deterministic comparisons, and supporting tables (`health_record_keywords`, `doctor_patient_access`) for access control and search.

3. **Security Layer Implementation**
   - Implemented Fernet-based encryption helpers in `app/security/encryption.py` for symmetric encryption of record payloads, user names, and emails.
   - Built keyword normalization and hashing utilities in `app/security/search_index.py` to power encrypted search without leaking plaintext terms.
   - Added deterministic hashing (HMAC-SHA256) for usernames/emails so queries can match without storing decrypted data.

4. **Feature Development**
   - **Admin workspace:** CRUD for admins/doctors/patients, doctor–patient access mapping, and session logs.
   - **Doctor workspace:** record authoring, encrypted search, and visibility limited to assigned patients.
   - **Patient workspace:** read-only dashboard with encrypted record viewing and profile management.
   - Shared components include client-side password hashing (`static/js/password-hash.js`) and polished Bootstrap-based dashboards.

5. **Testing & QA**
   - Manual verification of role flows and keyword search.
   - Pytest scaffolding (`tests/`) prepared for future automation (models, keyword index, encryption helpers).
   - Browser-level checks for cache headers and session isolation.

## 3. Security Measures
| Control Area | Description | Implementation Highlights |
|--------------|-------------|---------------------------|
| **Data Encryption** | All sensitive fields (names, emails, record titles/body, keyword summaries) encrypted before persistence, minimizing trust in the database. | `app/security/encryption.py`, invoked throughout `app/routes.py` when storing or fetching data. |
| **Deterministic Hashing** | User identifiers and keyword tokens hashed with keyed HMAC to enable equality/partial matches without plaintext exposure. | `hash_keyword` in `app/security/search_index.py`; lookup columns such as `email_lookup` on models. |
| **Access Control** | `role_required` decorator enforces role isolation, while `DoctorPatientAccess` table restricts doctor visibility to explicitly assigned patients. | `app/routes.py` decorators + assignment workflows in admin portal. |
| **Client-side Password Hardening** | Browser hashes passwords before sending them, reducing plaintext exposure in transit and server logs. Server-side storage uses PBKDF2 via `generate_password_hash`. | `static/js/password-hash.js`, `_derive_storage_password` in `app/routes.py`. |
| **Audit & Session Logging** | `UserSessionLog` captures logins/logouts per role, aiding anomaly detection and coursework review. Responses disable browser caching using `@main.after_app_request`. | `_log_session_event` and `apply_cache_headers` in `app/routes.py`. |
| **Encrypted Search Index** | Keyword extraction + hashed variants support search while keeping raw terms encrypted. | `_update_keyword_index` and `_apply_keyword_search` in `app/routes.py`. |
| **Rate Limiting & Lockout** | Flask-Limiter caps login POST requests (5/min per IP+identifier). Repeated failures persist to `login_throttles`, trigger a 10-minute lock, and emit server logs so admins can investigate. | `app/__init__.py` limiter setup, `login()` route decorators, and helper utilities in `app/routes.py`. |
| **Operational Safeguards** | Secrets externalized via `.env`, configurable DB URI, and runbook guidance for backups and key rotation. | `README.md` Environment Configuration + Operations sections. |

## 4. Development Environment & Tooling
- **Language/Framework:** Python 3.11, Flask, SQLAlchemy.
- **Database:** MySQL 8.x with utf8mb4 collation, managed manually or via SQL scripts.
- **Package Management:** `requirements.txt`; virtual environments recommended (`python -m venv venv`).
- **Local Execution:** `python run.py` creates tables via `db.create_all()` and serves the app on `http://127.0.0.1:5000` (debug mode).

## 5. Verification & Testing Strategy
- Use pytest (planned) to cover encryption helpers, keyword indexing, and role-based route protection.
- Manual smoke tests per role:
  1. Admin: create doctor/patient, assign access, inspect session logs.
  2. Doctor: log in, create encrypted record, verify search & access constraints.
  3. Patient: confirm only assigned records appear and profile updates persist.
- Database assertions: ensure encrypted fields appear as base64 strings and keyword hashes populate secondary table.

## 6. Future Hardening Opportunities
1. Replace PBKDF2 with Argon2id and enforce password rotation.
2. Add multi-factor authentication for admin accounts.
3. Implement full-text encrypted search using searchable encryption primitives.
4. Introduce Celery background jobs for re-indexing and audit reporting.
5. Expand automated tests (unit + integration) to cover session handling and SQL injection regression cases.

---
This report should serve as both a development log and a security walkthrough for auditors, classmates, and maintainers reviewing Secure Health Vault.
