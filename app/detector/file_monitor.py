
import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.detector.detector import RansomwareDetector
from app.system.status import system_status
from app.database.database import (
    save_event,
    save_quarantine_event,
    get_monitored_folders,
)
from app.response.response import quarantine_file


# Resolve paths from the project root.
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

QUARANTINE_FOLDER = os.path.join(
    PROJECT_ROOT, "data", "quarantine"
)

DATABASE_PATH = os.path.join(
    PROJECT_ROOT, "rdrs.db"
)

SQLITE_SUFFIXES = (
    "-journal",
    "-wal",
    "-shm",
)

INTERNAL_DIRECTORY_NAMES = {
    "__pycache__",
    ".venv",
    ".git",
}


class RansomwareMonitor(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.detector = RansomwareDetector()
        self.quarantined_files = set()

    def normalize_path(self, file_path):
        return os.path.normcase(
            os.path.abspath(file_path)
        )

    def is_quarantine_file(self, file_path):
        path = self.normalize_path(file_path)
        quarantine = self.normalize_path(
            QUARANTINE_FOLDER
        )

        try:
            return os.path.commonpath(
                [path, quarantine]
            ) == quarantine
        except ValueError:
            return False

    def is_internal_file(self, file_path):
        """Ignore RDRS internals and Python cache files."""

        path = self.normalize_path(file_path)
        filename = os.path.basename(path).lower()

        # Ignore Python bytecode and temporary bytecode files.
        if (
            filename.endswith((".pyc", ".pyo"))
            or ".pyc." in filename
            or ".pyo." in filename
        ):
            return True

        # Ignore internal runtime directories.
        path_parts = {
            part.lower()
            for part in os.path.normpath(path).split(os.sep)
        }

        if path_parts.intersection(
            INTERNAL_DIRECTORY_NAMES
        ):
            return True

        # Ignore the RDRS database and its SQLite sidecars.
        database = self.normalize_path(DATABASE_PATH)

        protected_paths = {
            database,
            *(
                database + suffix
                for suffix in SQLITE_SUFFIXES
            ),
        }

        if path in protected_paths:
            return True

        if filename in {
            "rdrs.db",
            "rdrs.db-journal",
            "rdrs.db-wal",
            "rdrs.db-shm",
        }:
            return True

        return False

    def get_folder_owner_id(self, file_path):
        """Return the owner of the most specific ACTIVE folder."""

        normalized_file = self.normalize_path(file_path)
        matching_folders = []

        for folder in get_monitored_folders():
            if folder.status != "ACTIVE":
                continue

            user_id = getattr(folder, "user_id", None)

            # Never attribute an event to an unknown owner.
            if user_id is None:
                continue

            folder_path = folder.folder_path

            if not os.path.isabs(folder_path):
                folder_path = os.path.join(
                    PROJECT_ROOT,
                    folder_path,
                )

            folder_path = self.normalize_path(folder_path)

            try:
                is_inside_folder = (
                    os.path.commonpath(
                        [normalized_file, folder_path]
                    )
                    == folder_path
                )
            except ValueError:
                # Paths on different drives cannot match.
                continue

            if is_inside_folder:
                matching_folders.append(
                    (len(folder_path), user_id)
                )

        if not matching_folders:
            return None

        # When registered folders overlap, use the most specific one.
        matching_folders.sort(
            key=lambda item: item[0],
            reverse=True,
        )

        return matching_folders[0][1]

    def process_event(self, event_type, file_path):
        file_path = os.path.abspath(file_path)

        # Filter internal files before detection or database logging.
        if self.is_quarantine_file(file_path):
            return

        if self.is_internal_file(file_path):
            return

        normalized_path = self.normalize_path(file_path)

        if normalized_path in self.quarantined_files:
            return

        # Determine the owner from the registered folder, not login session.
        user_id = self.get_folder_owner_id(file_path)

        if user_id is None:
            return

        result = self.detector.record_event(
            event_type,
            file_path,
        )

        print()
        print("=" * 60)
        print(f"EVENT       : {event_type.upper()}")
        print(f"FILE        : {file_path}")
        print(f"USER ID     : {user_id}")
        print(f"SCORE       : {result['score']}")
        print(f"RISK LEVEL  : {result['risk']}")
        print(f"SUSPICIOUS  : {result['suspicious']}")
        print(f"REASON      : {result['reason']}")
        print(f"ENTROPY     : {result.get('entropy')}")

        process = result.get("process")

        if process:
            print(f"PROCESS     : {process.get('name')}")
            print(f"PID         : {process.get('pid')}")
            print(f"CPU         : {process.get('cpu_percent')}%")
            print(
                f"MEMORY      : "
                f"{process.get('memory_percent')}%"
            )

        print("=" * 60)

        # Save the security event under its folder owner.
        try:
            save_event(
                event_type,
                file_path,
                result["score"],
                result["risk"],
                entropy=result.get("entropy"),
                process=process,
                user_id=user_id,
            )
            print("[DATABASE] Security event saved.")

        except Exception as error:
            print(
                f"[DATABASE ERROR] Could not save event: {error}"
            )
            return

        # Automatically quarantine HIGH-risk files only.
        if result["risk"] != "HIGH":
            return

        print()
        print(
            "[WARNING] Suspicious ransomware-like activity detected."
        )
        print("[RESPONSE] Starting quarantine...")

        self.quarantined_files.add(normalized_path)

        try:
            quarantine_result = quarantine_file(file_path)
        except Exception as error:
            print(f"[RESPONSE ERROR] {error}")
            self.quarantined_files.discard(normalized_path)
            return

        if not quarantine_result:
            print("[RESPONSE] QUARANTINE FAILED")
            self.quarantined_files.discard(normalized_path)
            return

        print("[RESPONSE] QUARANTINE SUCCESS")
        print("[DATABASE] Saving quarantine event...")

        try:
            quarantine_record = save_quarantine_event(
                file_path=file_path,
                quarantine_path=quarantine_result,
                reason=result["reason"],
                status="SUCCESS",
                user_id=user_id,
            )

            print(
                "[DATABASE] Quarantine event saved. "
                f"ID: {quarantine_record.id}"
            )

        except Exception as error:
            print(
                "[DATABASE ERROR] Failed to save quarantine event: "
                f"{error}"
            )

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event("deleted", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return

        # A file moved into quarantine is not a new threat.
        if self.is_quarantine_file(event.dest_path):
            return

        self.process_event("moved", event.dest_path)


def get_active_monitored_folders():
    """Return existing ACTIVE folders assigned to a user."""

    active_folders = []

    for folder in get_monitored_folders():
        if folder.status != "ACTIVE":
            continue

        if getattr(folder, "user_id", None) is None:
            print(
                "[MONITORING WARNING] Skipping folder without owner: "
                f"{folder.folder_path}"
            )
            continue

        folder_path = folder.folder_path

        if not os.path.isabs(folder_path):
            folder_path = os.path.join(
                PROJECT_ROOT,
                folder_path,
            )

        folder_path = os.path.abspath(folder_path)

        if not os.path.isdir(folder_path):
            print(
                "[MONITORING WARNING] Folder not found: "
                f"{folder_path}"
            )
            continue

        if folder_path not in active_folders:
            active_folders.append(folder_path)

    return active_folders


def get_required_monitored_folders():
    # Do not automatically add the project's data directory.
    return get_active_monitored_folders()


def sync_monitored_folders(
    observer,
    event_handler,
    active_watches,
):
    required_folders = set(
        get_required_monitored_folders()
    )

    current_folders = set(active_watches.keys())

    # Start watching newly registered ACTIVE folders.
    for folder in required_folders - current_folders:
        try:
            watch = observer.schedule(
                event_handler,
                folder,
                recursive=True,
            )

            active_watches[folder] = watch

            print(
                f"[MONITORING] Started watching: {folder}"
            )

        except Exception as error:
            print(
                f"[MONITORING ERROR] Could not watch "
                f"{folder}: {error}"
            )

    # Stop watching folders that are no longer ACTIVE.
    for folder in current_folders - required_folders:
        watch = active_watches.get(folder)

        if watch is None:
            continue

        try:
            observer.unschedule(watch)

            print(
                f"[MONITORING] Stopped watching: {folder}"
            )

        except Exception as error:
            print(
                f"[MONITORING ERROR] Could not stop watching "
                f"{folder}: {error}"
            )

        finally:
            active_watches.pop(folder, None)


def start_monitor():
    event_handler = RansomwareMonitor()
    observer = Observer()
    active_watches = {}

    print("=" * 60)
    print("RANSOMWARE DETECTION & RESPONSE SYSTEM")
    print(f"[SYSTEM] Project root: {PROJECT_ROOT}")
    print(f"[SYSTEM] Database excluded: {DATABASE_PATH}")
    print("=" * 60)

    try:
        observer.start()
        system_status.set_monitor_running()

        print("[SYSTEM] Live monitoring started.")
        print("[SYSTEM] Dynamic folder synchronization enabled.")
        print("[SYSTEM] Press CTRL+C to stop.")
        print("=" * 60)

        while True:
            sync_monitored_folders(
                observer,
                event_handler,
                active_watches,
            )
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[SYSTEM] Stopping monitor...")

    finally:
        if observer.is_alive():
            observer.stop()
            observer.join()

        system_status.set_monitor_stopped()


if __name__ == "__main__":
    start_monitor()