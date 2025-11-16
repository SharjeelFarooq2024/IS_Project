from app import db

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False)
    username_lookup = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.Text)
    email_lookup = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    assignments = db.relationship('DoctorPatientAccess', backref='assigned_admin', lazy=True)

class Doctor(db.Model):
    __tablename__ = 'doctors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    specialization = db.Column(db.String(100))
    email = db.Column(db.Text)
    email_lookup = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    records = db.relationship('HealthRecord', backref='doctor', lazy=True)

class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    dob = db.Column(db.Date)
    gender = db.Column(db.Enum('Male','Female','Other'))
    email = db.Column(db.Text)
    email_lookup = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    records = db.relationship('HealthRecord', backref='patient', cascade='all, delete-orphan', passive_deletes=True, lazy=True)
    doctor_access = db.relationship('DoctorPatientAccess', backref='patient', cascade='all, delete-orphan', passive_deletes=True, lazy=True)

class HealthRecord(db.Model):
    __tablename__ = 'health_records'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='SET NULL'), nullable=True)
    record_name = db.Column(db.Text)
    encrypted_record = db.Column(db.Text, nullable=False)
    keyword_hash = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    keyword_tokens = db.relationship('HealthRecordKeyword', cascade='all, delete-orphan', backref='record', lazy=True)


class DoctorPatientAccess(db.Model):
    __tablename__ = 'doctor_patient_access'
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='CASCADE'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('admins.id', ondelete='SET NULL'))
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    doctor = db.relationship('Doctor', backref=db.backref('patient_access', cascade='all, delete-orphan', passive_deletes=True, lazy=True))


class HealthRecordKeyword(db.Model):
    __tablename__ = 'health_record_keywords'
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.Integer, db.ForeignKey('health_records.id', ondelete='CASCADE'), nullable=False)
    encrypted_keyword = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
