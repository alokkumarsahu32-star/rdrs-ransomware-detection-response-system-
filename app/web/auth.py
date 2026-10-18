
import re
import bcrypt

from app.database.database import (
    create_user,
    get_user_by_username,
    get_user_by_email
)


# ==================================================
# PASSWORD HASHING
# ==================================================

def hash_password(password):
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


# ==================================================
# PASSWORD VERIFICATION
# ==================================================

def verify_password(password, password_hash):
    password_bytes = password.encode("utf-8")
    hash_bytes = password_hash.encode("utf-8")

    try:
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except (ValueError, TypeError):
        return False


# ==================================================
# EMAIL VALIDATION
# ==================================================

def is_valid_email(email):
    if not email or len(email) > 254:
        return False

    email = email.strip()

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
            email
        )
    )


# ==================================================
# CREATE USER
# ==================================================

def register_user(
    username,
    password,
    email=None,
    role="analyst"
):
    if not username or not password or not email:
        return None

    username = username.strip()
    email = email.strip().lower()

    if not username or len(username) > 50:
        return None

    if len(password) < 8:
        return None

    if not is_valid_email(email):
        return None

    if get_user_by_username(username):
        return None

    if get_user_by_email(email):
        return None

    password_hash = hash_password(password)

    try:
        return create_user(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role
        )
    except Exception:
        # For example, a concurrent duplicate registration.
        # Do not expose database details to the caller.
        return None


# ==================================================
# AUTHENTICATE USER
# ==================================================

def authenticate_user(username, password):
    if not username or not password:
        return None

    user = get_user_by_username(username.strip())

    if not user:
        return None

    if not user.is_active:
        return None

    if verify_password(password, user.password_hash):
        return user

    return None