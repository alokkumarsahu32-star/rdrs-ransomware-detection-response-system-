
import os
from datetime import datetime

from app.database.database import (
    get_monitored_folders,
    save_scan_finding_once,
)


SUSPICIOUS_EXTENSIONS = {
    ".encrypted",
    ".enc",
    ".locked",
    ".crypt",
    ".ransom",
    ".wncry",
    ".lockbit",
}


def scan_folder(folder_path):
    folder_path = os.path.abspath(folder_path)

    result = {
        "folder_path": folder_path,
        "folder_exists": False,
        "files_scanned": 0,
        "folders_found": 0,
        "total_size": 0,
        "suspicious_files": [],
        "suspicious_count": 0,
        "risk_level": "NORMAL",
        "errors": [],
    }

    if not os.path.isdir(folder_path):
        result["errors"].append(
            "Folder does not exist or is not accessible."
        )
        return result

    result["folder_exists"] = True

    try:
        for root, directories, files in os.walk(folder_path):
            result["folders_found"] += len(directories)

            for file_name in files:
                file_path = os.path.join(root, file_name)

                try:
                    if not os.path.isfile(file_path):
                        continue

                    file_size = os.path.getsize(file_path)

                    result["files_scanned"] += 1
                    result["total_size"] += file_size

                    extension = os.path.splitext(file_name)[1].lower()

                    if extension in SUSPICIOUS_EXTENSIONS:
                        result["suspicious_files"].append({
                            "file_name": file_name,
                            "file_path": file_path,
                            "extension": extension,
                            "size": file_size,
                        })

                except (PermissionError, OSError) as error:
                    result["errors"].append(
                        f"{file_path}: {error}"
                    )

    except (PermissionError, OSError) as error:
        result["errors"].append(str(error))

    result["suspicious_count"] = len(result["suspicious_files"])
    count = result["suspicious_count"]

    if count >= 5:
        result["risk_level"] = "HIGH"
    elif count >= 2:
        result["risk_level"] = "MEDIUM"
    elif count == 1:
        result["risk_level"] = "LOW"

    return result


def scan_monitored_folders(user_id=None):
    """
    Scan active folders belonging to users.

    If user_id is provided, scan only that user's folders.
    Save each suspicious extension finding once per user and file.
    """

    folders = get_monitored_folders()

    scan_results = []
    total_files = 0
    total_folders = 0
    total_size = 0
    total_suspicious = 0

    scan_start = datetime.now()

    for folder in folders:
        if folder.status != "ACTIVE":
            continue

        folder_owner_id = getattr(folder, "user_id", None)

        # Skip folders without an owner.
        if folder_owner_id is None:
            continue

        # Keep user scans isolated.
        if user_id is not None and folder_owner_id != user_id:
            continue

        folder_path = folder.folder_path

        if not os.path.isabs(folder_path):
            folder_path = os.path.abspath(folder_path)

        result = scan_folder(folder_path)
        scan_results.append(result)

        total_files += result["files_scanned"]
        total_folders += result["folders_found"]
        total_size += result["total_size"]
        total_suspicious += result["suspicious_count"]

        # Save findings without repeatedly inserting the same scan event.
        for finding in result["suspicious_files"]:
            try:
               save_scan_finding_once(
    file_path=finding["file_path"],
    score=5,
    risk_level="LOW",
    user_id=folder_owner_id,
)

            except Exception as error:
                result["errors"].append(
                    f"Could not save scan event for "
                    f"{finding['file_path']}: {error}"
                )

    scan_end = datetime.now()

    if total_suspicious >= 5:
        overall_risk = "HIGH"
    elif total_suspicious >= 2:
        overall_risk = "MEDIUM"
    elif total_suspicious == 1:
        overall_risk = "LOW"
    else:
        overall_risk = "NORMAL"

    return {
        "scan_started": scan_start,
        "scan_completed": scan_end,
        "folders_scanned": len(scan_results),
        "total_files": total_files,
        "total_folders": total_folders,
        "total_size": total_size,
        "total_suspicious": total_suspicious,
        "overall_risk": overall_risk,
        "results": scan_results,
    }


def format_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"

    if size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"

    return f"{size / (1024 ** 3):.2f} GB"