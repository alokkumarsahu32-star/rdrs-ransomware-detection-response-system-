from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Float,
    text
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)

from datetime import datetime
import  secrets
import hashlib

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Float,
    text
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)

from datetime import datetime
import os


# ==================================================
# DATABASE CONFIGURATION
# ==================================================

DATABASE_URL = "sqlite:///rdrs.db"


engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)
from pathlib import Path

print("[RDRS DATABASE CHECK]")
print("Database URL:", engine.url.render_as_string(hide_password=True))
print("Database file:", Path("rdrs.db").resolve())
print("Database exists:", Path("rdrs.db").exists())

Base = declarative_base()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# ==================================================
# SECURITY EVENT TABLE
# ==================================================

class SecurityEvent(Base):

    __tablename__ = "security_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )
    user_id = Column(Integer, nullable=True, index=True)

    event_type = Column(
        String,
        nullable=False
    )

    file_path = Column(
        String,
        nullable=False
    )

    score = Column(
        Integer,
        default=0
    )

    risk_level = Column(
        String,
        default="NORMAL"
    )

    # Shannon entropy of the file
    entropy = Column(
        Float,
        nullable=True
    )

    # Process metadata
    process_name = Column(
        String,
        nullable=True
    )

    process_pid = Column(
        Integer,
        nullable=True
    )

    process_exe = Column(
        String,
        nullable=True
    )

    process_cpu = Column(
        Float,
        nullable=True
    )

    process_memory = Column(
        Float,
        nullable=True
    )

    timestamp = Column(
        DateTime,
        default=datetime.now
    )


# ==================================================
# QUARANTINE EVENT TABLE
# ==================================================

class QuarantineEvent(Base):

    __tablename__ = "quarantine_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )
    user_id = Column(Integer, nullable=True, index=True)

    file_path = Column(
        String,
        nullable=False
    )

    quarantine_path = Column(
        String,
        nullable=False
    )

    reason = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        default="SUCCESS"
    )

    timestamp = Column(
        DateTime,
        default=datetime.now
    )


# ==================================================
# USER TABLE
# ==================================================

class User(Base):

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    email = Column(
    String,
    unique=True,
    nullable=True,
    index=True
)

    password_hash = Column(
        String,
        nullable=False
    )

    role = Column(
        String,
        default="analyst"
    )

    is_active = Column(
        Integer,
        default=1
    )

    created_at = Column(
        DateTime,
        default=datetime.now
    )


# ==================================================
# MONITORED FOLDERS TABLE
# ==================================================

class MonitoredFolder(Base):
    __tablename__ = "monitored_folders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    folder_path = Column(String, unique=True, nullable=False)
    folder_name = Column(String, nullable=False)
    status = Column(String, default="ACTIVE")
    created_at = Column(DateTime, default=datetime.now)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, nullable=False, index=True)
    device_name = Column(String, nullable=False)
    operating_system = Column(String, nullable=True)
    user_id = Column(Integer, nullable=True)
    device_token = Column(String, unique=True, nullable=True, index=True)
    status = Column(String, default="OFFLINE")
    agent_version = Column(String, default="1.0.0")
    created_at = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, nullable=True)

class DeviceEnrollment(Base):
    __tablename__ = "device_enrollments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    code_hash = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)

# ==================================================
# CREATE DATABASE TABLES
# ==================================================

Base.metadata.create_all(
    bind=engine
)


# ==================================================
# DATABASE MIGRATION
# ==================================================

def migrate_security_events_table():

    required_columns = {
        "entropy": "REAL",
        "process_name": "TEXT",
        "process_pid": "INTEGER",
        "process_exe": "TEXT",
        "process_cpu": "REAL",
        "process_memory": "REAL"
    }

    with engine.connect() as connection:

        result = connection.execute(
            text(
                "PRAGMA table_info(security_events)"
            )
        )

        existing_columns = {
            row[1]
            for row in result
        }

        for column_name, column_type in required_columns.items():

            if column_name not in existing_columns:

                connection.execute(
                    text(
                        f"""
                        ALTER TABLE security_events
                        ADD COLUMN {column_name}
                        {column_type}
                        """
                    )
                )

        connection.commit()


# Run security event migration automatically
migrate_security_events_table()


# ==================================================
# DEVICE TOKEN MIGRATION
# ==================================================

def migrate_devices_table():

    required_columns = {
        "device_token": "TEXT"
    }

    with engine.connect() as connection:

        result = connection.execute(
            text(
                "PRAGMA table_info(devices)"
            )
        )

        existing_columns = {
            row[1]
            for row in result
        }

        for column_name, column_type in required_columns.items():

            if column_name not in existing_columns:

                connection.execute(
                    text(
                        f"""
                        ALTER TABLE devices
                        ADD COLUMN {column_name}
                        {column_type}
                        """
                    )
                )

        connection.commit()


# Run device migration automatically
migrate_devices_table()


# ==================================================
# USER EMAIL MIGRATION
# ==================================================

def migrate_users_table():
    """Safely add the email column to existing users tables."""
    with engine.connect() as connection:
        result = connection.execute(
            text("PRAGMA table_info(users)")
        )

        existing_columns = {
            row[1] for row in result
        }

        if "email" not in existing_columns:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN email TEXT")
            )

        # SQLite allows multiple NULL values in a unique index.
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ix_users_email_unique ON users (email)"
            )
        )

        connection.commit()


# Run user email migration automatically
migrate_users_table()

# ==================================================
# SAVE SECURITY EVENT
# ==================================================


def save_event(
    event_type,
    file_path,
    score,
    risk_level,
    entropy=None,
    process=None,
    user_id=None,
):
    """Save a file-monitoring security event."""
    db = SessionLocal()

    try:
        process = process or {}

        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            file_path=str(file_path),
            score=int(score or 0),
            risk_level=str(risk_level or "NORMAL"),
            entropy=entropy,
            process_name=process.get("name"),
            process_pid=process.get("pid"),
            process_exe=process.get("exe"),
            process_cpu=process.get("cpu_percent"),
            process_memory=process.get("memory_percent"),
            timestamp=datetime.now(),
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
        
def save_scan_finding_once(file_path, score, risk_level, user_id):
    """Save a scan finding only once per user and normalized file path."""
    normalized_path = os.path.normcase(
        os.path.abspath(str(file_path))
    )

    db = SessionLocal()

    try:
        existing_events = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user_id == user_id,
                SecurityEvent.event_type == "scan_suspicious_extension",
            )
            .all()
        )

        for existing in existing_events:
            if not existing.file_path:
                continue

            existing_path = os.path.normcase(
                os.path.abspath(str(existing.file_path))
            )

            if existing_path == normalized_path:
                return existing

        event = SecurityEvent(
            user_id=user_id,
            event_type="scan_suspicious_extension",
            file_path=str(file_path),
            score=score,
            risk_level=risk_level,
            process_name="RDRS directory scan",
            timestamp=datetime.now(),
        )

        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()



# ==================================================
# GET RECENT SECURITY EVENTS
# ==================================================


def get_recent_events(limit=10, user_id=None):
    db = SessionLocal()

    try:
        query = db.query(SecurityEvent)

        if user_id is not None:
            query = query.filter(SecurityEvent.user_id == user_id)

        events = (
            query
            .order_by(SecurityEvent.id.desc())
            .limit(limit)
            .all()
        )

        return events

    finally:
        db.close()


# ==================================================
# GET ALL SECURITY EVENTS
# ==================================================


def get_all_events(user_id=None):
    db = SessionLocal()

    try:
        query = db.query(SecurityEvent)

        if user_id is not None:
            query = query.filter(SecurityEvent.user_id == user_id)

        events = (
            query
            .order_by(SecurityEvent.id.desc())
            .all()
        )

        return events

    finally:
        db.close()


# ==================================================
# GET THREAT EVENTS
# ==================================================


def get_threat_events(user_id=None):
    db = SessionLocal()

    try:
        query = (
            db.query(SecurityEvent)
            .filter(
                (SecurityEvent.score >= 10)
                | (
                    SecurityEvent.event_type
                    == "scan_suspicious_extension"
                )
            )
        )

        if user_id is not None:
            query = query.filter(
                SecurityEvent.user_id == user_id
            )

        events = (
            query
            .order_by(SecurityEvent.id.desc())
            .all()
        )

        return events

    finally:
        db.close()


# ==================================================
# GET TOTAL EVENTS
# ==================================================


def get_total_events(user_id=None):
    db = SessionLocal()
    try:
        query = db.query(SecurityEvent)

        if user_id is not None:
            query = query.filter(SecurityEvent.user_id == user_id)

        return query.count()
    finally:
        db.close()


# ==================================================
# GET HIGH RISK EVENTS
# ==================================================


def get_high_risk_events(user_id=None):
    db = SessionLocal()
    try:
        query = db.query(SecurityEvent).filter(
            SecurityEvent.risk_level == "HIGH"
        )

        if user_id is not None:
            query = query.filter(SecurityEvent.user_id == user_id)

        return query.count()
    finally:
        db.close()


# ==================================================
# GET SUSPICIOUS EVENTS
# ==================================================


def get_suspicious_events(user_id=None):
    db = SessionLocal()
    try:
        query = db.query(SecurityEvent).filter(
    (SecurityEvent.score >= 10)
    | (
        SecurityEvent.event_type
        == "scan_suspicious_extension"
    )
)

        if user_id is not None:
            query = query.filter(SecurityEvent.user_id == user_id)

        return query.count()
    finally:
        db.close()


# ==================================================
# SAVE QUARANTINE EVENT
# ==================================================


def save_quarantine_event(
    file_path,
    quarantine_path,
    reason,
    status="SUCCESS",
    user_id=None,
):
    db = SessionLocal()

    try:
        quarantine_event = QuarantineEvent(
            user_id=user_id,
            file_path=str(file_path),
            quarantine_path=str(quarantine_path),
            reason=reason,
            status=status,
            timestamp=datetime.now(),
        )

        db.add(quarantine_event)
        db.commit()
        db.refresh(quarantine_event)
        return quarantine_event

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# GET QUARANTINED EVENTS COUNT
# ==================================================


def get_quarantined_events(user_id=None):
    db = SessionLocal()
    try:
        query = db.query(QuarantineEvent).filter(
            QuarantineEvent.status == "SUCCESS"
        )

        if user_id is not None:
            query = query.filter(QuarantineEvent.user_id == user_id)

        return query.count()
    finally:
        db.close()


# ==================================================
# GET RECENT QUARANTINE EVENTS
# ==================================================


def get_recent_quarantines(limit=10, user_id=None):
    db = SessionLocal()

    try:
        query = db.query(QuarantineEvent)

        if user_id is not None:
            query = query.filter(
                QuarantineEvent.user_id == user_id
            )

        return (
            query
            .order_by(QuarantineEvent.id.desc())
            .limit(limit)
            .all()
        )

    finally:
        db.close()

# ==================================================
# USER AUTHENTICATION
# ==================================================


def create_user(
    username,
    password_hash,
    role="analyst",
    email=None
):
    db = SessionLocal()

    try:
        user = User(
            username=username,
            email=email.strip().lower() if email else None,
            password_hash=password_hash,
            role=role,
            is_active=1
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user

    finally:
        db.close()


def get_user_by_username(username):

    db = SessionLocal()

    try:

        return (
            db.query(User)
            .filter(
                User.username == username
            )
            .first()
        )

    finally:

        db.close()
        

def get_user_by_email(email):
    if not email:
        return None

    db = SessionLocal()

    try:
        return (
            db.query(User)
            .filter(User.email == email.strip().lower())
            .first()
        )

    finally:
        db.close()

def get_user_by_id(user_id):
    if user_id is None:
        return None

    db = SessionLocal()

    try:
        return (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )
    finally:
        db.close()


def create_device_enrollment(user_id, expires_in_minutes=5):
    import secrets
    import hashlib
    from datetime import timedelta

    code = secrets.token_urlsafe(32)
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

    db = SessionLocal()
    try:
        enrollment = DeviceEnrollment(
            user_id=user_id,
            code_hash=code_hash,
            expires_at=datetime.now() + timedelta(minutes=expires_in_minutes),
        )
        db.add(enrollment)
        db.commit()

        return code
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def consume_device_enrollment(code):
    import hashlib
    from datetime import datetime

    if not code or not isinstance(code, str):
        return None

    code_hash = hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()

    db = SessionLocal()
    try:
        enrollment = (
            db.query(DeviceEnrollment)
            .filter(DeviceEnrollment.code_hash == code_hash)
            .with_for_update()
            .first()
        )

        if enrollment is None:
            return None

        if enrollment.used_at is not None:
            return None

        if enrollment.expires_at <= datetime.now():
            return None

        enrollment.used_at = datetime.now()
        db.commit()

        return enrollment.user_id

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ==================================================
# MONITORED FOLDER FUNCTIONS
# ==================================================


def add_monitored_folder(folder_path, folder_name, user_id=None):
    db = SessionLocal()

    try:
        existing_folder = (
            db.query(MonitoredFolder)
            .filter(MonitoredFolder.folder_path == folder_path)
            .first()
        )

        if existing_folder:
            # Claim an older folder that has no owner yet.
            if (
                user_id is not None
                and getattr(existing_folder, "user_id", None) is None
            ):
                existing_folder.user_id = user_id
                db.commit()
                db.refresh(existing_folder)

            elif (
                user_id is not None
                and existing_folder.user_id != user_id
            ):
                raise ValueError(
                    "This folder path is already assigned to another user."
                )

            return existing_folder

        folder = MonitoredFolder(
            folder_path=folder_path,
            folder_name=folder_name,
            status="ACTIVE",
            user_id=user_id,
        )

        db.add(folder)
        db.commit()
        db.refresh(folder)

        return folder

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def get_monitored_folders():

    db = SessionLocal()

    try:

        return (
            db.query(MonitoredFolder)
            .order_by(
                MonitoredFolder.id.desc()
            )
            .all()
        )

    finally:

        db.close()


def remove_monitored_folder(
    folder_id
):

    db = SessionLocal()

    try:

        folder = (
            db.query(MonitoredFolder)
            .filter(
                MonitoredFolder.id
                == folder_id
            )
            .first()
        )

        if not folder:

            return False

        db.delete(folder)

        db.commit()

        return True

    finally:

        db.close()


def update_monitored_folder_status(
    folder_id,
    status
):

    db = SessionLocal()

    try:

        folder = (
            db.query(MonitoredFolder)
            .filter(
                MonitoredFolder.id
                == folder_id
            )
            .first()
        )

        if not folder:

            return False

        folder.status = status

        db.commit()

        return True

    finally:

        db.close()

# ==================================================
# register_device
# ==================================================

# ==================================================
# register_device
# ==================================================

def register_device(
    device_id,
    device_name,
    operating_system,
    user_id=None,
    agent_version="1.0.0"
):

    db = SessionLocal()

    try:

        existing_device = (
            db.query(Device)
            .filter(
                Device.device_id == device_id
            )
            .first()
        )

        if existing_device:

            existing_device.device_name = device_name
            existing_device.operating_system = operating_system

            if existing_device.user_id is None and user_id is not None:
                existing_device.user_id = user_id

            elif user_id is not None and existing_device.user_id != user_id:
                raise ValueError("Device is already assigned to another user")

            existing_device.agent_version = agent_version
            existing_device.status = "ONLINE"
            existing_device.last_seen = datetime.now()

            # Generate token if old device has no token
            if not existing_device.device_token:
                existing_device.device_token = secrets.token_urlsafe(32)

            db.commit()
            db.refresh(existing_device)

            return existing_device

            # Generate token if old device has no token
            if not existing_device.device_token:
                existing_device.device_token = secrets.token_urlsafe(32)

            db.commit()
            db.refresh(existing_device)

            return existing_device

        device_token = secrets.token_urlsafe(32)

        device = Device(
            device_id=device_id,
            device_name=device_name,
            operating_system=operating_system,
            user_id=user_id,
            device_token=device_token,
            status="ONLINE",
            agent_version=agent_version,
            created_at=datetime.now(),
            last_seen=datetime.now()
        )

        db.add(device)
        db.commit()
        db.refresh(device)

        return device

    finally:

        db.close()
# ==================================================
# update_device_heartbeat
# ==================================================
# ==================================================
# update_device_heartbeat
# ==================================================

def update_device_heartbeat(device_id):
    db = SessionLocal()

    try:
        device = (
            db.query(Device)
            .filter(Device.device_id == device_id)
            .first()
        )

        if not device:
            return None

        device.status = "ONLINE"
        device.last_seen = datetime.now()

        db.commit()
        db.refresh(device)

        return device

    finally:
        db.close()

        
def migrate_user_isolation_columns():
    """Add user_id columns to existing tables without deleting old data."""

    tables = [
        "security_events",
        "quarantine_events",
        "monitored_folders",
    ]

    with engine.begin() as connection:
        for table in tables:
            result = connection.execute(text(f"PRAGMA table_info({table})"))
            existing_columns = {row[1] for row in result}

            if "user_id" not in existing_columns:
                connection.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER")
                )

            connection.execute(
                text(
                    f"CREATE INDEX IF NOT EXISTS ix_{table}_user_id "
                    f"ON {table} (user_id)"
                )
            )


migrate_user_isolation_columns()
def get_devices_by_user(user_id: int):
    db = SessionLocal()
    try:
        return (
            db.query(Device)
            .filter(Device.user_id == user_id)
            .order_by(Device.id.desc())
            .all()
        )
    finally:
        db.close()