from datetime import datetime
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g, abort
from sqlalchemy import or_

from app import db
from app.models import Admin, Doctor, Patient, HealthRecord, DoctorPatientAccess

main = Blueprint('main', __name__)

ROLE_HOME = {
    'admin': 'main.admin_dashboard',
    'doctor': 'main.doctor_dashboard',
    'patient': 'main.patient_dashboard',
}


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None


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
        g.current_user = user


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

        if role == 'admin':
            user = Admin.query.filter(
                (Admin.username == identifier) | (Admin.email == identifier)
            ).first()
        elif role == 'doctor':
            user = Doctor.query.filter_by(email=identifier).first()
        else:
            user = Patient.query.filter_by(email=identifier).first()

        if user is None or user.password_hash != password:
            flash('Invalid credentials. Please try again.', 'danger')
            return redirect(url_for('main.login', role=role))

        _login_user(role, user.id)
        flash('Login successful.', 'success')
        return redirect(url_for(ROLE_HOME[role]))

    return render_template('auth/login.html', role=role)


@main.route('/logout')
def logout():
    role = session.get('user_role', 'admin')
    _logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.login', role=role))


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

    assignments = (
        DoctorPatientAccess.query.order_by(DoctorPatientAccess.created_at.desc())
        .limit(5)
        .all()
    )

    return render_template(
        'admin/dashboard.html',
        stats=stats,
        recent_records=recent_records,
        assignments=assignments,
    )


@main.route('/admin/admins', methods=['GET', 'POST'])
@role_required('admin')
def admin_admins():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = (request.form.get('email') or '').strip() or None
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('main.admin_admins'))

        unique_checks = [Admin.username == username]
        if email:
            unique_checks.append(Admin.email == email)

        conflict_filter = or_(*unique_checks) if len(unique_checks) > 1 else unique_checks[0]
        conflict = Admin.query.filter(conflict_filter).first()

        if conflict:
            flash('An admin with that username or email already exists.', 'warning')
            return redirect(url_for('main.admin_admins'))

        try:
            admin_user = Admin(
                username=username,
                email=email,
                password_hash=password,
            )
            db.session.add(admin_user)
            db.session.commit()
            flash('Admin account created successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to create admin: {exc}', 'danger')

        return redirect(url_for('main.admin_admins'))

    admins = Admin.query.order_by(Admin.created_at.desc()).all()
    return render_template('admin/admins.html', admins=admins)


@main.route('/admin/admins/<int:admin_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_admin(admin_id):
    admin_user = Admin.query.get_or_404(admin_id)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = (request.form.get('email') or '').strip() or None
        password = request.form.get('password', '')

        if not username:
            flash('Username is required.', 'danger')
            return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

        unique_checks = [Admin.username == username]
        if email:
            unique_checks.append(Admin.email == email)

        conflict_filter = or_(*unique_checks) if len(unique_checks) > 1 else unique_checks[0]
        conflict = (
            Admin.query.filter(conflict_filter)
            .filter(Admin.id != admin_user.id)
            .first()
        )

        if conflict:
            flash('Another admin already uses that username or email.', 'warning')
            return redirect(url_for('main.admin_edit_admin', admin_id=admin_id))

        admin_user.username = username
        admin_user.email = email

        if password:
            admin_user.password_hash = password

        try:
            db.session.commit()
            flash('Admin account updated successfully.', 'success')
            return redirect(url_for('main.admin_admins'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update admin: {exc}', 'danger')

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
        name = request.form.get('name')
        specialization = request.form.get('specialization')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([name, email, password]):
            flash('Name, email, and password are required.', 'danger')
            return redirect(url_for('main.admin_doctors'))

        if Doctor.query.filter_by(email=email).first():
            flash('A doctor with that email already exists.', 'warning')
            return redirect(url_for('main.admin_doctors'))

        try:
            doctor = Doctor(
                name=name,
                specialization=specialization,
                email=email,
                password_hash=password,
            )
            db.session.add(doctor)
            db.session.commit()
            flash('Doctor created successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to create doctor: {exc}', 'danger')

        return redirect(url_for('main.admin_doctors'))

    doctors = Doctor.query.order_by(Doctor.created_at.desc()).all()
    return render_template('admin/doctors.html', doctors=doctors)


@main.route('/admin/doctors/<int:doctor_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)

    if request.method == 'POST':
        doctor.name = request.form.get('name')
        doctor.specialization = request.form.get('specialization')
        doctor.email = request.form.get('email')

        password = request.form.get('password')
        if password:
            doctor.password_hash = password

        try:
            db.session.commit()
            flash('Doctor updated successfully.', 'success')
            return redirect(url_for('main.admin_doctors'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update doctor: {exc}', 'danger')

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
        name = request.form.get('name')
        dob = _parse_date(request.form.get('dob'))
        gender = request.form.get('gender') or None
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([name, email, password]):
            flash('Name, email, and password are required.', 'danger')
            return redirect(url_for('main.admin_patients'))

        if Patient.query.filter_by(email=email).first():
            flash('A patient with that email already exists.', 'warning')
            return redirect(url_for('main.admin_patients'))

        try:
            patient = Patient(
                name=name,
                dob=dob,
                gender=gender,
                email=email,
                password_hash=password,
            )
            db.session.add(patient)
            db.session.commit()
            flash('Patient added successfully.', 'success')
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to add patient: {exc}', 'danger')

        return redirect(url_for('main.admin_patients'))

    patients = Patient.query.order_by(Patient.created_at.desc()).all()
    return render_template('admin/patients.html', patients=patients)


@main.route('/admin/patients/<int:patient_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)

    if request.method == 'POST':
        patient.name = request.form.get('name')
        patient.gender = request.form.get('gender') or None
        patient.email = request.form.get('email')
        patient.dob = _parse_date(request.form.get('dob'))

        password = request.form.get('password')
        if password:
            patient.password_hash = password

        try:
            db.session.commit()
            flash('Patient updated successfully.', 'success')
            return redirect(url_for('main.admin_patients'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update patient: {exc}', 'danger')

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
    doctors = Doctor.query.order_by(Doctor.name.asc()).all()
    patients = Patient.query.order_by(Patient.name.asc()).all()
    assignments = DoctorPatientAccess.query.order_by(
        DoctorPatientAccess.created_at.desc()
    ).all()

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
    query = request.args.get('q', '', type=str)
    records_query = HealthRecord.query

    if query:
        like_pattern = f"%{query}%"
        records_query = records_query.filter(
            or_(
                HealthRecord.record_name.ilike(like_pattern),
                HealthRecord.keyword_hash.ilike(like_pattern),
                HealthRecord.encrypted_record.ilike(like_pattern),
            )
        )

    records = records_query.order_by(HealthRecord.created_at.desc()).all()
    return render_template('admin/records.html', records=records, search=query)


# ----------------------
# Doctor Portal
# ----------------------


@main.route('/doctor/dashboard')
@role_required('doctor')
def doctor_dashboard():
    doctor: Doctor = g.current_user
    search = request.args.get('q', '', type=str)

    assignments = DoctorPatientAccess.query.filter_by(doctor_id=doctor.id).all()
    assigned_patient_ids = [assignment.patient_id for assignment in assignments]

    assigned_patients = (
        Patient.query.filter(Patient.id.in_(assigned_patient_ids)).order_by(Patient.name.asc()).all()
        if assigned_patient_ids
        else []
    )

    records_query = HealthRecord.query.filter_by(doctor_id=doctor.id)
    if search:
        like_pattern = f"%{search}%"
        records_query = records_query.filter(
            or_(
                HealthRecord.record_name.ilike(like_pattern),
                HealthRecord.keyword_hash.ilike(like_pattern),
                HealthRecord.encrypted_record.ilike(like_pattern),
            )
        )

    records = records_query.order_by(HealthRecord.created_at.desc()).all()

    return render_template(
        'doctor/dashboard.html',
        doctor=doctor,
        assigned_patients=assigned_patients,
        patients=assigned_patients,
        records=records,
        search=search,
    )


@main.route('/doctor/records', methods=['POST'])
@role_required('doctor')
def doctor_add_record():
    doctor: Doctor = g.current_user

    patient_id = _safe_int(request.form.get('patient_id'))
    record_name = request.form.get('record_name')
    encrypted_record = request.form.get('encrypted_record')
    keyword_hash = request.form.get('keyword_hash')

    if patient_id is None or not encrypted_record or not keyword_hash:
        flash('Patient, medical details, and keywords are required.', 'danger')
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
            record_name=record_name,
            encrypted_record=encrypted_record,
            keyword_hash=keyword_hash,
        )
        db.session.add(record)
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

    return render_template('doctor/record_detail.html', doctor=doctor, record=record)


@main.route('/doctor/records/<int:record_id>/edit', methods=['GET', 'POST'])
@role_required('doctor')
def doctor_edit_record(record_id):
    doctor: Doctor = g.current_user
    record = HealthRecord.query.get_or_404(record_id)

    if record.doctor_id != doctor.id:
        abort(404)

    if request.method == 'POST':
        record.record_name = request.form.get('record_name')
        record.encrypted_record = request.form.get('encrypted_record')
        record.keyword_hash = request.form.get('keyword_hash')

        try:
            db.session.commit()
            flash('Health record updated successfully.', 'success')
            return redirect(url_for('main.doctor_dashboard'))
        except Exception as exc:
            db.session.rollback()
            flash(f'Unable to update health record: {exc}', 'danger')

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
    search = request.args.get('q', '', type=str)

    records_query = HealthRecord.query.filter_by(patient_id=patient.id)
    if search:
        like_pattern = f"%{search}%"
        records_query = records_query.filter(
            or_(
                HealthRecord.record_name.ilike(like_pattern),
                HealthRecord.keyword_hash.ilike(like_pattern),
                HealthRecord.encrypted_record.ilike(like_pattern),
            )
        )

    records = records_query.order_by(HealthRecord.created_at.desc()).all()

    return render_template(
        'patient/dashboard.html',
        patient=patient,
        records=records,
        search=search,
    )


@main.route('/patient/records/<int:record_id>')
@role_required('patient')
def patient_record_detail(record_id):
    patient: Patient = g.current_user
    record = HealthRecord.query.get_or_404(record_id)

    if record.patient_id != patient.id:
        abort(404)

    return render_template('patient/record_detail.html', patient=patient, record=record)


@main.route('/patient/profile', methods=['POST'])
@role_required('patient')
def patient_update_profile():
    patient: Patient = g.current_user

    patient.name = request.form.get('name')
    patient.email = request.form.get('email')
    patient.gender = request.form.get('gender') or None
    patient.dob = _parse_date(request.form.get('dob'))

    try:
        db.session.commit()
        flash('Profile updated successfully.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'Unable to update profile: {exc}', 'danger')

    return redirect(url_for('main.patient_dashboard'))
