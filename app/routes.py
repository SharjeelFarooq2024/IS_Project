from datetime import datetime
from functools import wraps
import re
from hashlib import sha256

from werkzeug.security import generate_password_hash, check_password_hash

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g, abort
from sqlalchemy import or_

from app import db
from app.models import (
    Admin,
    Doctor,
    Patient,
    HealthRecord,
    HealthRecordKeyword,
    DoctorPatientAccess,
    UserSessionLog,
)

from app.security.encryption import encrypt_data
from app.security.encryption import decrypt_data
from app.security.search_index import extract_keywords_from_text, normalize_keywords, hash_keyword

main = Blueprint('main', __name__)

ROLE_HOME = {
    'admin': 'main.admin_dashboard',
    'doctor': 'main.doctor_dashboard',
    'patient': 'main.patient_dashboard',
}

PASSWORD_POLICY_MESSAGE = 'Password must be at least 8 characters long, include one uppercase letter, and one special character.'
PASSWORD_POLICY_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,}$')
HASHED_PASSWORD_REGEX = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)


def _render_admin_admins():
    admins = Admin.query.order_by(Admin.created_at.desc()).all()
    admins = [_decrypt_admin(admin_user) for admin_user in admins]
    return render_template('admin/admins.html', admins=admins)


def _render_admin_doctors():
    doctors = Doctor.query.order_by(Doctor.created_at.desc()).all()
    doctors = [_decrypt_doctor(doc) for doc in doctors]
    return render_template('admin/doctors.html', doctors=doctors)


def _render_admin_patients():
    patients = Patient.query.order_by(Patient.created_at.desc()).all()
    patients = [_decrypt_patient(patient) for patient in patients]
    return render_template('admin/patients.html', patients=patients)


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_strong_password(password: str | None) -> bool:
    if not password:
        return False

    trimmed = password.strip()
    if HASHED_PASSWORD_REGEX.fullmatch(trimmed):
        return True

    return bool(PASSWORD_POLICY_REGEX.match(trimmed))


def _hash_password_sha256(password: str) -> str:
    return sha256(password.encode('utf-8')).hexdigest()


def _normalize_password_input(password: str | None) -> str:
    if not password:
        return ''
    trimmed = password.strip()
    if HASHED_PASSWORD_REGEX.fullmatch(trimmed):
        return trimmed
    return _hash_password_sha256(trimmed)


def _derive_storage_password(password: str | None) -> str:
    normalized = _normalize_password_input(password)
    return generate_password_hash(normalized, method='pbkdf2:sha256')


def _upgrade_password_hash(user, normalized_secret: str):
    try:
        user.password_hash = generate_password_hash(normalized_secret, method='pbkdf2:sha256')
        db.session.commit()
    except Exception:
        db.session.rollback()


def _password_matches(user, submitted_password: str | None) -> bool:
    if user is None or not submitted_password:
        return False

    normalized = _normalize_password_input(submitted_password)
    stored = (user.password_hash or '').strip()

    if stored.startswith('pbkdf2:'):
        return check_password_hash(stored, normalized)

    stored_normalized = (
        stored if HASHED_PASSWORD_REGEX.fullmatch(stored)
        else _hash_password_sha256(stored)
    )

    if stored_normalized == normalized:
        _upgrade_password_hash(user, normalized)
        return True

    return False



def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None


def _attach_decrypted_content(record: HealthRecord):
    decrypted = decrypt_data(record.encrypted_record)
    record.decrypted_record = decrypted or ''
    decrypted_name = decrypt_data(record.record_name)
    record.decrypted_record_name = (decrypted_name or '').strip()
    decrypted_keywords = decrypt_data(record.keyword_hash) if record.keyword_hash else ''
    if decrypted_keywords is None and record.keyword_hash:
        decrypted_keywords = record.keyword_hash
    record.decrypted_keywords = (decrypted_keywords or '').strip()

    if record.doctor:
        _decrypt_doctor(record.doctor)
    if record.patient:
        _decrypt_patient(record.patient)
    return record


def _update_keyword_index(
    record: HealthRecord,
    raw_keywords: str | None,
    record_title: str | None = None,
    record_body: str | None = None,
):
    def _keyword_variants(keyword: str) -> list[str]:
        normalized = keyword.strip().lower()
        if not normalized:
            return []

        variants: list[str] = [normalized]
        # Persist short, deterministic prefixes so hashed lookups can support
        # "starts with" matches without ever touching decrypted text.
        max_prefix = min(len(normalized), 6)
        for length in range(2, max_prefix):
            variants.append(normalized[:length])
        return variants

    keywords = normalize_keywords(raw_keywords)

    if record_title:
        for token in normalize_keywords(record_title):
            if token not in keywords:
                keywords.append(token)

    for token in extract_keywords_from_text(record_body):
        if token not in keywords:
            keywords.append(token)

    seen: set[str] = set()
    deduped: list[str] = []
    for token in keywords:
        lowered = token.strip().lower()
        if not lowered or lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(lowered)
    keywords = deduped

    # Persist encrypted keyword labels so stored values cannot leak search terms.
    keyword_summary = ', '.join(keywords)
    encrypted_keywords = encrypt_data(keyword_summary or '')
    record.keyword_hash = encrypted_keywords or ''
    HealthRecordKeyword.query.filter_by(record_id=record.id).delete(synchronize_session=False)

    unique_hashes: set[str] = set()
    for keyword in keywords:
        for variant in _keyword_variants(keyword):
            unique_hashes.add(hash_keyword(variant))
    for token_hash in unique_hashes:
        db.session.add(HealthRecordKeyword(record_id=record.id, encrypted_keyword=token_hash))


def _apply_keyword_search(query, search_term: str | None):
    if not search_term:
        return query

    tokens = normalize_keywords(search_term)
    token_hashes = [hash_keyword(token) for token in tokens if token]
    if not token_hashes:
        return query

    # Only rely on the encrypted keyword index so partial plaintext matches do not leak
    # information about the decrypted content during search.
    return (
        query.join(HealthRecordKeyword)
        .filter(HealthRecordKeyword.encrypted_keyword.in_(token_hashes))
        .distinct()
    )


def _filter_records_by_search(records, search_term: str | None):
    # Legacy helper retained for compatibility; filtering now occurs exclusively through
    # encrypted keyword hashes so we no longer inspect decrypted payloads for search.
    return records


def _normalize_identity(value: str | None) -> str:
    return (value or '').strip().lower()


def _hash_identity(value: str | None) -> str | None:
    normalized = _normalize_identity(value)
    return hash_keyword(normalized) if normalized else None


def _log_session_event(role: str | None, user_id: int | None, event: str, lookup: str | None = None):
    if role not in ROLE_HOME:
        return

    try:
        entry = UserSessionLog(
            user_role=role,
            user_id=user_id,
            event=event,
            user_lookup=lookup,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        main.logger.error('Unable to persist %s event for %s (id=%s): %s', event, role, user_id, exc)


def _decrypt_admin(admin: Admin | None):
    if admin is None:
        return None
    username = decrypt_data(admin.username)
    email = decrypt_data(admin.email)
    admin.decrypted_username = (username or '').strip()
    admin.decrypted_email = (email or '').strip()
    admin.decrypted_name = admin.decrypted_username
    return admin


def _decrypt_doctor(doctor: Doctor | None):
    if doctor is None:
        return None
    doctor.decrypted_name = decrypt_data(doctor.name) or ''
    doctor.decrypted_email = decrypt_data(doctor.email) or ''
    return doctor


def _decrypt_patient(patient: Patient | None):
    if patient is None:
        return None
    patient.decrypted_name = decrypt_data(patient.name) or ''
    patient.decrypted_email = decrypt_data(patient.email) or ''
    return patient


def _prepare_session_logs(logs: list[UserSessionLog]) -> list[dict]:
    admin_ids = {log.user_id for log in logs if log.user_role == 'admin' and log.user_id}
    doctor_ids = {log.user_id for log in logs if log.user_role == 'doctor' and log.user_id}
    patient_ids = {log.user_id for log in logs if log.user_role == 'patient' and log.user_id}

    admin_map: dict[int, Admin] = {}
    doctor_map: dict[int, Doctor] = {}
    patient_map: dict[int, Patient] = {}

    if admin_ids:
        admins = Admin.query.filter(Admin.id.in_(admin_ids)).all()
        for admin in admins:
            _decrypt_admin(admin)
            admin_map[admin.id] = admin

    if doctor_ids:
        doctors = Doctor.query.filter(Doctor.id.in_(doctor_ids)).all()
        for doctor in doctors:
            _decrypt_doctor(doctor)
            doctor_map[doctor.id] = doctor

    if patient_ids:
        patients = Patient.query.filter(Patient.id.in_(patient_ids)).all()
        for patient in patients:
            _decrypt_patient(patient)
            patient_map[patient.id] = patient

    entries: list[dict] = []
    for log in logs:
        display_name = 'Account removed'
        if log.user_role == 'admin':
            user = admin_map.get(log.user_id)
            display_name = user.decrypted_username if user else display_name
        elif log.user_role == 'doctor':
            user = doctor_map.get(log.user_id)
            display_name = user.decrypted_name if user else display_name
        elif log.user_role == 'patient':
            user = patient_map.get(log.user_id)
            display_name = user.decrypted_name if user else display_name

        entries.append(
            {
                'id': log.id,
                'user_id': log.user_id,
                'role': log.user_role,
                'event': log.event,
                'lookup': log.user_lookup,
                'display_name': display_name,
                'created_at': log.created_at,
            }
        )

    return entries


@main.before_app_request
def load_logged_in_user():
    g.user_role = session.get('user_role')
    g.current_user = None
    user_id = session.get('user_id')

    if not g.user_role or not user_id:
        return

    model_map = {
        'admin': Admin,
        'doctor': Doctor,
        'patient': Patient,
    }

    model = model_map.get(g.user_role)
    if model is None:
        session.clear()
        return

    user = model.query.get(user_id)
    if user is None:
        session.clear()
    else:
        if g.user_role == 'admin':
            _decrypt_admin(user)
        elif g.user_role == 'doctor':
            _decrypt_doctor(user)
        elif g.user_role == 'patient':
            _decrypt_patient(user)
        g.current_user = user


@main.after_app_request
def apply_cache_headers(response):
    # Prevent sensitive pages from being cached so browser back button cannot
    # resurrect authenticated views after logout.
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def _login_user(role: str, user_id: int):
    session.clear()
    session['user_role'] = role
    session['user_id'] = user_id


def _logout_user():
    session.clear()


def role_required(role: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if g.current_user is None or g.user_role != role:
                flash('Please log in with the correct role to continue.', 'danger')
                return redirect(url_for('main.login', role=role))
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


@main.route('/')
def landing():
    if g.current_user is not None and g.user_role in ROLE_HOME:
        return redirect(url_for(ROLE_HOME[g.user_role]))
    return render_template('index.html')


@main.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    if role not in ROLE_HOME:
        abort(404)

    if g.current_user is not None and g.user_role == role:
        return redirect(url_for(ROLE_HOME[role]))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        if not identifier or not password:
            flash('Both fields are required.', 'danger')
            return redirect(url_for('main.login', role=role))

        lookup = _hash_identity(identifier)

        if role == 'admin':
            user = None
            if lookup:
                user = Admin.query.filter(
                    or_(
                        Admin.username_lookup == lookup,
                        Admin.email_lookup == lookup,
                    )
                ).first()
            if user is None:
                user = Admin.query.filter(
                    (Admin.username == identifier) | (Admin.email == identifier)
                ).first()
        elif role == 'doctor':
            user = Doctor.query.filter_by(email_lookup=lookup).first() if lookup else None
        else:
            user = Patient.query.filter_by(email_lookup=lookup).first() if lookup else None

        if user is None or not _password_matches(user, password):
            flash('Invalid credentials. Please try again.', 'danger')
            return redirect(url_for('main.login', role=role))

        _login_user(role, user.id)
        _log_session_event(role, user.id, 'login', lookup)
        flash('Login successful.', 'success')
        return redirect(url_for(ROLE_HOME[role]))

    return render_template('auth/login.html', role=role)


@main.route('/logout')
def logout():
    role = session.get('user_role')
    user_id = session.get('user_id')
    if role in ROLE_HOME:
        _log_session_event(role, user_id, 'logout')
    redirect_role = role if role in ROLE_HOME else 'admin'
    _logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.login', role=redirect_role))


# ----------------------
# Admin Portal
# ----------------------


@main.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    stats = {
        'doctors': Doctor.query.count(),
        'patients': Patient.query.count(),
        'records': HealthRecord.query.count(),
        'admins': Admin.query.count(),
    }

    recent_records = (
        HealthRecord.query.order_by(HealthRecord.created_at.desc()).limit(5).all()
    )
    recent_records = [_attach_decrypted_content(record) for record in recent_records]

    assignments = (
        DoctorPatientAccess.query.order_by(DoctorPatientAccess.created_at.desc())
        .limit(5)
        .all()
    )
    for assignment in assignments:
        _decrypt_doctor(assignment.doctor)
        _decrypt_patient(assignment.patient)

    return render_template(
        'admin/dashboard.html',
        stats=stats,
        recent_records=recent_records,
        assignments=assignments,
    )


@main.route('/admin/profile', methods=['GET', 'POST'])
@role_required('admin')
def admin_profile():
    admin_user = Admin.query.get_or_404(g.current_user.id)
    _decrypt_admin(admin_user)

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip() or None
        password = request.form.get('password', '')

        email_lookup = None
        encrypted_email = None
        if email:
            email_lookup = _hash_identity(email)
            if email_lookup is None:
                flash('Please provide a valid email address.', 'danger')
                return render_template('admin/profile.html', admin_user=admin_user), 400

            conflict = (
                Admin.query.filter(Admin.email_lookup == email_lookup, Admin.id != admin_user.id).first()
            )
            if conflict:
                flash('Another admin already uses that email.', 'warning')
                return render_template('admin/profile.html', admin_user=admin_user), 400

            encrypted_email = encrypt_data(email)

        admin_user.email = encrypted_email
        admin_user.email_lookup = email_lookup

        if password:
            if not _is_strong_password(password):
                flash(PASSWORD_POLICY_MESSAGE, 'danger')
                return render_template('admin/profile.html', admin_user=admin_user), 400
            admin_user.password_hash = _derive_storage_password(password)

        try:
            db.session.commit()
            _decrypt_admin(admin_user)
            g.current_user = admin_user
            flash('Profile updated successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update profile: {exc}', 'danger')

        return redirect(url_for('main.admin_profile'))

    return render_template('admin/profile.html', admin_user=admin_user)


@main.route('/admin/logs')
@role_required('admin')
def admin_logs():
    limit = request.args.get('limit', default=250, type=int)
    limit = max(1, min(limit or 250, 1000))
    logs = (
        UserSessionLog.query.order_by(UserSessionLog.created_at.desc())
        .limit(limit)
        .all()
    )
    entries = _prepare_session_logs(logs)
    return render_template('admin/logs.html', logs=entries, limit=limit)


@main.route('/admin/admins', methods=['GET', 'POST'])
@role_required('admin')
def admin_admins():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = (request.form.get('email') or '').strip() or None
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return _render_admin_admins(), 400

        if not _is_strong_password(password):
            flash(PASSWORD_POLICY_MESSAGE, 'danger')
            return _render_admin_admins(), 400

        username_lookup = _hash_identity(username)
        if username_lookup is None:
            flash('A valid username is required.', 'danger')
            return _render_admin_admins(), 400

        existing_username = Admin.query.filter_by(username_lookup=username_lookup).first()
        if existing_username:
            flash('An admin with that username already exists.', 'warning')
            return _render_admin_admins(), 400

        email_lookup = None
        encrypted_email = None
        if email:
            email_lookup = _hash_identity(email)
            if email_lookup is None:
                flash('A valid email address is required.', 'danger')
                return _render_admin_admins(), 400

            existing_email = Admin.query.filter_by(email_lookup=email_lookup).first()
            if existing_email:
                flash('An admin with that email already exists.', 'warning')
                return _render_admin_admins(), 400

            encrypted_email = encrypt_data(email)

        try:
            admin_user = Admin(
                username=encrypt_data(username),
                username_lookup=username_lookup,
                email=encrypted_email,
                email_lookup=email_lookup,
                password_hash=_derive_storage_password(password),
            )
            db.session.add(admin_user)
            db.session.commit()
            flash('Admin account created successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to create admin: {exc}', 'danger')
            return _render_admin_admins(), 500

        return redirect(url_for('main.admin_admins'))

    return _render_admin_admins()


@main.route('/admin/admins/<int:admin_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_admin(admin_id):
    admin_user = Admin.query.get_or_404(admin_id)
    _decrypt_admin(admin_user)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = (request.form.get('email') or '').strip() or None
        password = request.form.get('password', '')

        if not username:
            flash('Username is required.', 'danger')
            return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

        username_lookup = _hash_identity(username)
        if username_lookup is None:
            flash('A valid username is required.', 'danger')
            return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

        conflict_username = (
            Admin.query.filter(Admin.username_lookup == username_lookup, Admin.id != admin_user.id).first()
        )
        if conflict_username:
            flash('Another admin already uses that username.', 'warning')
            return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

        email_lookup = None
        encrypted_email = None
        if email:
            email_lookup = _hash_identity(email)
            if email_lookup is None:
                flash('A valid email address is required.', 'danger')
                return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

            conflict_email = (
                Admin.query.filter(Admin.email_lookup == email_lookup, Admin.id != admin_user.id).first()
            )
            if conflict_email:
                flash('Another admin already uses that email address.', 'warning')
                return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

            encrypted_email = encrypt_data(email)

        admin_user.username = encrypt_data(username)
        admin_user.username_lookup = username_lookup
        admin_user.email = encrypted_email
        admin_user.email_lookup = email_lookup

        if password:
            if not _is_strong_password(password):
                flash(PASSWORD_POLICY_MESSAGE, 'danger')
                return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))
            admin_user.password_hash = _derive_storage_password(password)

        try:
            db.session.commit()
            flash('Admin account updated successfully.', 'success')
            return redirect(url_for('main.admin_admins'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update admin: {exc}', 'danger')

        _decrypt_admin(admin_user)

    return render_template('admin/edit_admin.html', admin_user=admin_user)


@main.route('/admin/admins/<int:admin_id>/delete', methods=['POST'])
@role_required('admin')
def admin_delete_admin(admin_id):
    admin_user = Admin.query.get_or_404(admin_id)

    if admin_user.id == g.current_user.id:
        flash('You cannot delete the account you are currently using.', 'warning')
        return redirect(url_for('main.admin_admins'))

    remaining_admins = Admin.query.count()
    if remaining_admins <= 1:
        flash('At least one admin account must remain in the system.', 'warning')
        return redirect(url_for('main.admin_admins'))

    try:
        db.session.delete(admin_user)
        db.session.commit()
        flash('Admin account removed successfully.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to delete admin: {exc}', 'danger')

    return redirect(url_for('main.admin_admins'))


@main.route('/admin/doctors', methods=['GET', 'POST'])
@role_required('admin')
def admin_doctors():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        specialization = request.form.get('specialization')
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password')

        if not all([name, email, password]):
            flash('Name, email, and password are required.', 'danger')
            return _render_admin_doctors(), 400

        if not _is_strong_password(password):
            flash(PASSWORD_POLICY_MESSAGE, 'danger')
            return _render_admin_doctors(), 400

        email_lookup = _hash_identity(email)
        if email_lookup is None:
            flash('A valid email address is required.', 'danger')
            return _render_admin_doctors(), 400

        if Doctor.query.filter_by(email_lookup=email_lookup).first():
            flash('A doctor with that email already exists.', 'warning')
            return _render_admin_doctors(), 400

        try:
            doctor = Doctor(
                name=encrypt_data(name),
                specialization=specialization,
                email=encrypt_data(email),
                email_lookup=email_lookup,
                password_hash=_derive_storage_password(password),
            )
            db.session.add(doctor)
            db.session.commit()
            flash('Doctor created successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to create doctor: {exc}', 'danger')
            return _render_admin_doctors(), 500

        return redirect(url_for('main.admin_doctors'))

    return _render_admin_doctors()


@main.route('/admin/doctors/<int:doctor_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    _decrypt_doctor(doctor)

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        specialization = request.form.get('specialization')
        email = (request.form.get('email') or '').strip()

        if not name or not email:
            flash('Name and email are required.', 'danger')
            return redirect(url_for('main.admin_edit_doctor', doctor_id=doctor.id))

        email_lookup = _hash_identity(email)
        if email_lookup is None:
            flash('A valid email address is required.', 'danger')
            return redirect(url_for('main.admin_edit_doctor', doctor_id=doctor.id))

        existing = (
            Doctor.query.filter(Doctor.email_lookup == email_lookup, Doctor.id != doctor.id).first()
        )
        if existing:
            flash('A doctor with that email already exists.', 'warning')
            return redirect(url_for('main.admin_edit_doctor', doctor_id=doctor.id))

        doctor.name = encrypt_data(name)
        doctor.specialization = specialization
        doctor.email = encrypt_data(email)
        doctor.email_lookup = email_lookup

        password = request.form.get('password')
        if password:
            if not _is_strong_password(password):
                flash(PASSWORD_POLICY_MESSAGE, 'danger')
                return redirect(url_for('main.admin_edit_doctor', doctor_id=doctor.id))
            doctor.password_hash = _derive_storage_password(password)

        try:
            db.session.commit()
            flash('Doctor updated successfully.', 'success')
            return redirect(url_for('main.admin_doctors'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update doctor: {exc}', 'danger')

        _decrypt_doctor(doctor)

    return render_template('admin/edit_doctor.html', doctor=doctor)


@main.route('/admin/doctors/<int:doctor_id>/delete', methods=['POST'])
@role_required('admin')
def admin_delete_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    try:
        db.session.delete(doctor)
        db.session.commit()
        flash('Doctor removed successfully.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to delete doctor: {exc}', 'danger')

    return redirect(url_for('main.admin_doctors'))


@main.route('/admin/patients', methods=['GET', 'POST'])
@role_required('admin')
def admin_patients():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        dob = _parse_date(request.form.get('dob'))
        gender = request.form.get('gender') or None
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password')

        if not all([name, email, password]):
            flash('Name, email, and password are required.', 'danger')
            return _render_admin_patients(), 400

        if not _is_strong_password(password):
            flash(PASSWORD_POLICY_MESSAGE, 'danger')
            return _render_admin_patients(), 400

        email_lookup = _hash_identity(email)
        if email_lookup is None:
            flash('A valid email address is required.', 'danger')
            return _render_admin_patients(), 400

        if Patient.query.filter_by(email_lookup=email_lookup).first():
            flash('A patient with that email already exists.', 'warning')
            return _render_admin_patients(), 400

        try:
            patient = Patient(
                name=encrypt_data(name),
                dob=dob,
                gender=gender,
                email=encrypt_data(email),
                email_lookup=email_lookup,
                password_hash=_derive_storage_password(password),
            )
            db.session.add(patient)
            db.session.commit()
            flash('Patient added successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to add patient: {exc}', 'danger')
            return _render_admin_patients(), 500

        return redirect(url_for('main.admin_patients'))

    return _render_admin_patients()


@main.route('/admin/patients/<int:patient_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    _decrypt_patient(patient)

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        gender = request.form.get('gender') or None
        email = (request.form.get('email') or '').strip()
        dob = _parse_date(request.form.get('dob'))

        if not name or not email:
            flash('Name and email are required.', 'danger')
            return redirect(url_for('main.admin_edit_patient', patient_id=patient.id))

        email_lookup = _hash_identity(email)
        if email_lookup is None:
            flash('A valid email address is required.', 'danger')
            return redirect(url_for('main.admin_edit_patient', patient_id=patient.id))

        existing = (
            Patient.query.filter(Patient.email_lookup == email_lookup, Patient.id != patient.id).first()
        )
        if existing:
            flash('A patient with that email already exists.', 'warning')
            return redirect(url_for('main.admin_edit_patient', patient_id=patient.id))

        patient.name = encrypt_data(name)
        patient.gender = gender
        patient.email = encrypt_data(email)
        patient.email_lookup = email_lookup
        patient.dob = dob

        password = request.form.get('password')
        if password:
            if not _is_strong_password(password):
                flash(PASSWORD_POLICY_MESSAGE, 'danger')
                return redirect(url_for('main.admin_edit_patient', patient_id=patient.id))
            patient.password_hash = _derive_storage_password(password)

        try:
            db.session.commit()
            flash('Patient updated successfully.', 'success')
            return redirect(url_for('main.admin_patients'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update patient: {exc}', 'danger')

        _decrypt_patient(patient)

    return render_template('admin/edit_patient.html', patient=patient)


@main.route('/admin/patients/<int:patient_id>/delete', methods=['POST'])
@role_required('admin')
def admin_delete_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    try:
        db.session.delete(patient)
        db.session.commit()
        flash('Patient removed successfully.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to delete patient: {exc}', 'danger')

    return redirect(url_for('main.admin_patients'))


@main.route('/admin/access', methods=['GET', 'POST'])
@role_required('admin')
def admin_access():
    doctors = [_decrypt_doctor(doc) for doc in Doctor.query.all()]
    doctors.sort(key=lambda doc: doc.decrypted_name.lower())

    patients = [_decrypt_patient(patient) for patient in Patient.query.all()]
    patients.sort(key=lambda patient: patient.decrypted_name.lower())

    assignments = DoctorPatientAccess.query.order_by(
        DoctorPatientAccess.created_at.desc()
    ).all()
    for assignment in assignments:
        _decrypt_doctor(assignment.doctor)
        _decrypt_patient(assignment.patient)

    if request.method == 'POST':
        doctor_id = _safe_int(request.form.get('doctor_id'))
        patient_id = _safe_int(request.form.get('patient_id'))

        if doctor_id is None or patient_id is None:
            flash('Select both a doctor and a patient.', 'danger')
            return redirect(url_for('main.admin_access'))

        existing = DoctorPatientAccess.query.filter_by(
            doctor_id=doctor_id, patient_id=patient_id
        ).first()
        if existing:
            flash('This doctor already has access to that patient.', 'warning')
            return redirect(url_for('main.admin_access'))

        try:
            assignment = DoctorPatientAccess(
                doctor_id=doctor_id,
                patient_id=patient_id,
                assigned_by=g.current_user.id,
            )
            db.session.add(assignment)
            db.session.commit()
            flash('Access granted successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to grant access: {exc}', 'danger')

        return redirect(url_for('main.admin_access'))

    return render_template(
        'admin/access.html',
        doctors=doctors,
        patients=patients,
        assignments=assignments,
    )


@main.route('/admin/access/<int:assignment_id>/delete', methods=['POST'])
@role_required('admin')
def admin_delete_access(assignment_id):
    assignment = DoctorPatientAccess.query.get_or_404(assignment_id)
    try:
        db.session.delete(assignment)
        db.session.commit()
        flash('Access revoked successfully.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to revoke access: {exc}', 'danger')

    return redirect(url_for('main.admin_access'))


@main.route('/admin/records')
@role_required('admin')
def admin_records():
    query = request.args.get('q', '', type=str).strip()

    records_query = HealthRecord.query.order_by(HealthRecord.created_at.desc())
    records_query = _apply_keyword_search(records_query, query)
    records = [_attach_decrypted_content(record) for record in records_query.all()]
    records = _filter_records_by_search(records, query)

    return render_template('admin/records.html', records=records, search=query)


# ----------------------
# Doctor Portal
# ----------------------


@main.route('/doctor/dashboard')
@role_required('doctor')
def doctor_dashboard():
    doctor: Doctor = g.current_user
    search = request.args.get('q', '', type=str).strip()

    assignments = DoctorPatientAccess.query.filter_by(doctor_id=doctor.id).all()
    assigned_patient_ids = [assignment.patient_id for assignment in assignments]

    if assigned_patient_ids:
        assigned_patients = Patient.query.filter(Patient.id.in_(assigned_patient_ids)).all()
        assigned_patients = [_decrypt_patient(patient) for patient in assigned_patients]
        assigned_patients.sort(key=lambda patient: patient.decrypted_name.lower())
    else:
        assigned_patients = []

    records_query = (
        HealthRecord.query.filter_by(doctor_id=doctor.id)
        .order_by(HealthRecord.created_at.desc())
    )
    records_query = _apply_keyword_search(records_query, search)
    records = [_attach_decrypted_content(record) for record in records_query.all()]
    records = _filter_records_by_search(records, search)

    return render_template(
        'doctor/dashboard.html',
        doctor=doctor,
        assigned_patients=assigned_patients,
        patients=assigned_patients,
        records=records,
        search=search,
    )


@main.route('/doctor/profile', methods=['GET', 'POST'])
@role_required('doctor')
def doctor_profile():
    doctor = Doctor.query.get_or_404(g.current_user.id)
    _decrypt_doctor(doctor)

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password', '')

        if not email:
            flash('Email is required.', 'danger')
            return render_template('doctor/profile.html', doctor=doctor), 400

        email_lookup = _hash_identity(email)
        if email_lookup is None:
            flash('Please provide a valid email address.', 'danger')
            return render_template('doctor/profile.html', doctor=doctor), 400

        conflict = (
            Doctor.query.filter(Doctor.email_lookup == email_lookup, Doctor.id != doctor.id).first()
        )
        if conflict:
            flash('Another doctor already uses that email.', 'warning')
            return render_template('doctor/profile.html', doctor=doctor), 400

        doctor.email = encrypt_data(email)
        doctor.email_lookup = email_lookup

        if password:
            if not _is_strong_password(password):
                flash(PASSWORD_POLICY_MESSAGE, 'danger')
                return render_template('doctor/profile.html', doctor=doctor), 400
            doctor.password_hash = _derive_storage_password(password)

        try:
            db.session.commit()
            _decrypt_doctor(doctor)
            g.current_user = doctor
            flash('Profile updated successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update profile: {exc}', 'danger')

        return redirect(url_for('main.doctor_profile'))

    return render_template('doctor/profile.html', doctor=doctor)


@main.route('/doctor/records', methods=['POST'])
@role_required('doctor')
def doctor_add_record():
    doctor: Doctor = g.current_user

    patient_id = _safe_int(request.form.get('patient_id'))
    record_title = (request.form.get('record_name') or '').strip()
    record_body = request.form.get('encrypted_record')
    raw_keywords = request.form.get('keyword_hash')

    if patient_id is None or not record_body:
        flash('Patient and medical details are required.', 'danger')
        return redirect(url_for('main.doctor_dashboard'))

    assignment = DoctorPatientAccess.query.filter_by(
        doctor_id=doctor.id, patient_id=patient_id
    ).first()
    if assignment is None:
        flash('You do not have access to that patient.', 'danger')
        return redirect(url_for('main.doctor_dashboard'))

    try:
        record = HealthRecord(
            patient_id=patient_id,
            doctor_id=doctor.id,
            record_name=encrypt_data(record_title) if record_title else None,
            encrypted_record=encrypt_data(record_body),
            keyword_hash='',
        )
        db.session.add(record)
        db.session.flush()
        _update_keyword_index(record, raw_keywords, record_title, record_body)
        db.session.commit()
        flash('Health record saved successfully.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to save health record: {exc}', 'danger')

    return redirect(url_for('main.doctor_dashboard'))


@main.route('/doctor/records/<int:record_id>')
@role_required('doctor')
def doctor_record_detail(record_id):
    doctor: Doctor = g.current_user
    record = HealthRecord.query.get_or_404(record_id)

    if record.doctor_id != doctor.id:
        abort(404)

    _attach_decrypted_content(record)

    return render_template('doctor/record_detail.html', doctor=doctor, record=record)


@main.route('/doctor/records/<int:record_id>/edit', methods=['GET', 'POST'])
@role_required('doctor')
def doctor_edit_record(record_id):
    doctor: Doctor = g.current_user
    record = HealthRecord.query.get_or_404(record_id)

    if record.doctor_id != doctor.id:
        abort(404)

    if request.method == 'POST':
        record_title = (request.form.get('record_name') or '').strip()
        plaintext = request.form.get('encrypted_record')
        keywords_input = request.form.get('keyword_hash')

        record.record_name = encrypt_data(record_title) if record_title else None
        record.encrypted_record = encrypt_data(plaintext)
        _update_keyword_index(record, keywords_input, record_title, plaintext)

        try:
            db.session.commit()
            flash('Health record updated successfully.', 'success')
            return redirect(url_for('main.doctor_dashboard'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update health record: {exc}', 'danger')

    _attach_decrypted_content(record)

    return render_template('doctor/edit_record.html', doctor=doctor, record=record)


@main.route('/doctor/records/<int:record_id>/delete', methods=['POST'])
@role_required('doctor')
def doctor_delete_record(record_id):
    doctor: Doctor = g.current_user
    record = HealthRecord.query.get_or_404(record_id)

    if record.doctor_id != doctor.id:
        abort(404)

    try:
        db.session.delete(record)
        db.session.commit()
        flash('Health record removed.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to delete health record: {exc}', 'danger')

    return redirect(url_for('main.doctor_dashboard'))


# ----------------------
# Patient Portal
# ----------------------


@main.route('/patient/dashboard')
@role_required('patient')
def patient_dashboard():
    patient: Patient = g.current_user
    search = request.args.get('q', '', type=str).strip()

    records_query = (
        HealthRecord.query.filter_by(patient_id=patient.id)
        .order_by(HealthRecord.created_at.desc())
    )
    records_query = _apply_keyword_search(records_query, search)
    records = [_attach_decrypted_content(record) for record in records_query.all()]
    records = _filter_records_by_search(records, search)

    return render_template(
        'patient/dashboard.html',
        patient=patient,
        records=records,
        search=search,
    )


@main.route('/patient/profile', methods=['GET', 'POST'])
@role_required('patient')
def patient_profile():
    patient = Patient.query.get_or_404(g.current_user.id)
    _decrypt_patient(patient)

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password', '')

        if not email:
            flash('Email is required.', 'danger')
            return render_template('patient/profile.html', patient=patient), 400

        email_lookup = _hash_identity(email)
        if email_lookup is None:
            flash('Please provide a valid email address.', 'danger')
            return render_template('patient/profile.html', patient=patient), 400

        existing = (
            Patient.query.filter(Patient.email_lookup == email_lookup, Patient.id != patient.id).first()
        )
        if existing:
            flash('Another account already uses that email address.', 'warning')
            return render_template('patient/profile.html', patient=patient), 400

        patient.email = encrypt_data(email)
        patient.email_lookup = email_lookup

        if password:
            if not _is_strong_password(password):
                flash(PASSWORD_POLICY_MESSAGE, 'danger')
                return render_template('patient/profile.html', patient=patient), 400
            patient.password_hash = _derive_storage_password(password)

        try:
            db.session.commit()
            _decrypt_patient(patient)
            g.current_user = patient
            flash('Profile updated successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update profile: {exc}', 'danger')

        return redirect(url_for('main.patient_profile'))

    return render_template('patient/profile.html', patient=patient)

@main.route('/patient/records/<int:record_id>')
@role_required('patient')
def patient_record_detail(record_id):
    patient: Patient = g.current_user
    record = HealthRecord.query.get_or_404(record_id)

    if record.patient_id != patient.id:
        abort(404)

    _attach_decrypted_content(record)

    return render_template('patient/record_detail.html', patient=patient, record=record)
