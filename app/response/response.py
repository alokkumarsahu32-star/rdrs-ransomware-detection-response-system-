
import os
import shutil
from datetime import datetime

# ==================================================
# PATHS
# ==================================================

PROJECT_ROOT = os.path.abspath(os.getcwd())

QUARANTINE_FOLDER = os.path.abspath(
    os.path.join(PROJECT_ROOT, "data", "quarantine")
)

# Files/folders that must never be quarantined.
PROTECTED_FILES = {
    "rdrs.db",
    "rdrs.db-journal",
    "rdrs.db-wal",
    "rdrs.db-shm",
}

PROTECTED_FOLDERS = {
    os.path.abspath(PROJECT_ROOT),
    QUARANTINE_FOLDER,
}


def is_protected_file(file_path):
    """Return True for RDRS internal files and folders."""
    path = os.path.abspath(file_path)
    name = os.path.basename(path).lower()

    # Protect database files, including SQLite sidecar files.
    if name in PROTECTED_FILES:
        return True

    # Protect all files inside the RDRS project directory.
    # This prevents quarantining the application's own code,
    # database and runtime files.
    try:
        if os.path.commonpath(
            [PROJECT_ROOT, path]
        ) == PROJECT_ROOT:
            return True
    except ValueError:
        pass

    # Protect quarantine directory and its contents.
    try:
        if os.path.commonpath(
            [QUARANTINE_FOLDER, path]
        ) == QUARANTINE_FOLDER:
            return True
    except ValueError:
        pass

    return False


# ==================================================
# CREATE QUARANTINE FOLDER
# ==================================================

def create_quarantine_folder():
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)


# ==================================================
# QUARANTINE FILE
# ==================================================

def quarantine_file(file_path):
    path = os.path.abspath(file_path)

    # Safety check before moving anything.
    if is_protected_file(path):
        print(
            f"[RESPONSE] Protected RDRS file; "
            f"quarantine skipped: {path}"
        )
        return None

    if not os.path.isfile(path):
        print("[RESPONSE] File not found.")
        return None

    try:
        create_quarantine_folder()

        file_name = os.path.basename(path)
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        destination = os.path.join(
            QUARANTINE_FOLDER,
            f"{timestamp}_{file_name}"
        )

        shutil.move(path, destination)

        print("[RESPONSE] File quarantined successfully.")
        print(f"[RESPONSE] Location: {destination}")

        return destination

    except Exception as error:
        print(f"[RESPONSE ERROR] {error}")
        return None