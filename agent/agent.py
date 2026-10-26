import platform
import socket
import requests
import os
import uuid
import time
import threading
from tkinter import Tk, filedialog

from agent.config import (
    SERVER_URL,
    DEVICE_ID_FILE,
    DEVICE_TOKEN_FILE,
    AGENT_VERSION
)


# ==================================================
# DEVICE ID FUNCTIONS
# ==================================================

def save_device_id(device_id):
    with open(DEVICE_ID_FILE, "w", encoding="utf-8") as file:
        file.write(device_id)


def load_device_id():
    if not os.path.exists(DEVICE_ID_FILE):
        return None

    with open(DEVICE_ID_FILE, "r", encoding="utf-8") as file:
        return file.read().strip()


def save_device_token(device_token):
    with open(
        DEVICE_TOKEN_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(device_token)


def load_device_token():
    if not os.path.exists(DEVICE_TOKEN_FILE):
        return None

    with open(
        DEVICE_TOKEN_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return file.read().strip()


# ==================================================
# DEVICE REGISTRATION
# ==================================================
# ==================================================
# DEVICE REGISTRATION / ENROLLMENT
# ==================================================

def register_agent():

    existing_device_id = load_device_id()
    existing_device_token = load_device_token()

    # Preserve and reuse existing registered device.
    if existing_device_id and existing_device_token:
        print("Existing Device ID found")
        print("Device ID:", existing_device_id)
        print("Existing Device Token found")
        print("Token Length:", len(existing_device_token))
        return existing_device_id, existing_device_token

    print("\nRDRS Device Enrollment")
    print("Open your RDRS dashboard and click '+ Enroll Device'.")
    print("Copy the one-time code. It expires in 5 minutes.\n")

    enrollment_code = input("Paste enrollment code: ").strip()

    if not enrollment_code:
        raise RuntimeError("Enrollment code cannot be empty.")

    device_name = socket.gethostname()
    operating_system = platform.system() + " " + platform.release()

    response = requests.post(
        f"{SERVER_URL}/api/devices/enroll",
        json={
            "code": enrollment_code,
            "device_name": device_name,
            "operating_system": operating_system
        },
        timeout=15
    )

    if response.status_code == 400:
        try:
            detail = response.json().get("detail", "Enrollment failed.")
        except ValueError:
            detail = "Enrollment failed."
        raise RuntimeError(detail)

    response.raise_for_status()
    data = response.json()

    device_id = data.get("device_id")
    device_token = data.get("device_token")

    if not device_id or not device_token:
        raise RuntimeError("Server response is missing device credentials.")

    # Save only after successful enrollment.
    save_device_id(device_id)
    save_device_token(device_token)

    print("\nDevice enrolled successfully!")
    print("Device ID:", device_id)
    print("Device Name:", data.get("device_name", device_name))
    print("Operating System:", data.get("operating_system", operating_system))
    print("Agent Version:", data.get("agent_version", AGENT_VERSION))
    print("Device Token Length:", len(device_token))

    return device_id, device_token


# ==================================================
# HEARTBEAT
# ==================================================

def send_heartbeat(device_id, device_token):

    response = requests.post(
        f"{SERVER_URL}/api/devices/heartbeat",
        params={
            "device_id": device_id
        },
        headers={
            "Authorization": f"Bearer {device_token}"
        },
        timeout=10
    )
    print("Heartbeat HTTP Status:", response.status_code, "| Response:", response.text[:500])
    response.raise_for_status()

    data = response.json()

    print(
        "Heartbeat:",
        data.get("status"),
        "| Last Seen:",
        data.get("last_seen")
    )


# ==================================================
# LOCAL FOLDER SCANNING AND RESULT UPLOAD
# ==================================================

from tkinter import Tk, filedialog

SUSPICIOUS_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypt",
    ".ransom", ".wncry", ".lockbit"
}


def select_folder():
    root = Tk()
    root.withdraw()

    try:
        root.attributes("-topmost", True)

        folder_path = filedialog.askdirectory(
            title="Select a folder to scan with RDRS"
        )
        return folder_path
    finally:
        root.destroy()



def scan_local_folder(folder_path):
    scan_id = str(uuid.uuid4())

    result = {
        "scan_id": scan_id,
        "folder_path": os.path.abspath(folder_path),
        "files_scanned": 0,
        "suspicious_files": [],
        "file_results": [],
        "errors": []
    }

    for root, directories, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            try:
                if not os.path.isfile(file_path):
                    continue

                result["files_scanned"] += 1
                extension = os.path.splitext(file_name)[1].lower()

                if extension in SUSPICIOUS_EXTENSIONS:
                    finding = {
                        "file_path": file_path,
                        "score": 5,
                        "risk_level": "LOW"
                    }
                    result["suspicious_files"].append(finding)
                    result["file_results"].append(finding.copy())
                else:
                    result["file_results"].append({
                        "file_path": file_path,
                        "score": 0,
                        "risk_level": "NORMAL"
                    })

            except OSError as error:
                result["errors"].append(str(error))

    return result



def upload_scan_results(device_id, device_token, scan_result):
    response = requests.post(
        f"{SERVER_URL}/api/devices/scan-results",
        params={"device_id": device_id},
        headers={
            "Authorization": f"Bearer {device_token}"
        },
        json=scan_result,
        timeout=60
    )

    response.raise_for_status()
    return response.json()


# ==================================================
# MAIN AGENT
# ==================================================

# ==================================================
# MAIN AGENT
# ==================================================

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="RDRS Windows Agent")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Scan a local folder without enrollment, upload, or heartbeat.",
    )
    parser.add_argument(
        "--folder",
        type=str,
        help="Folder to scan in self-test mode. If omitted, a folder picker opens.",
    )
    args = parser.parse_args()

    print("RDRS Agent started")

    if args.self_test:
        # Local-only mode: do not call register_agent, upload, or heartbeat.
        selected_folder = args.folder or select_folder()

        if not selected_folder:
            print("No folder selected. Self-test skipped.")
            raise SystemExit(1)

        if not os.path.isdir(selected_folder):
            print("Error: Folder does not exist.")
            raise SystemExit(1)

        print("\nLOCAL SELF-TEST MODE — no server requests will be made.")
        print("Scanning folder:", os.path.abspath(selected_folder))

        scan_result = scan_local_folder(selected_folder)

        print(json.dumps({
            "mode": "local-only",
            "scan_id": scan_result["scan_id"],
            "files_scanned": scan_result["files_scanned"],
            "suspicious_count": len(scan_result["suspicious_files"]),
            "file_results": scan_result["file_results"],
            "errors": scan_result["errors"],
        }, indent=2))

        raise SystemExit(0)

    # Normal mode: existing live-server workflow.
    device_id, device_token = register_agent()

    print("\nSelect a folder to scan.")
    selected_folder = select_folder()

    if selected_folder:
        print("\nScanning folder:", selected_folder)
        scan_result = scan_local_folder(selected_folder)

        print("Files scanned:", scan_result["files_scanned"])
        print("Suspicious files:", len(scan_result["suspicious_files"]))

        try:
            upload_result = upload_scan_results(
                device_id,
                device_token,
                scan_result
            )
            print("Upload status:", upload_result.get("status"))
            print("Server response:", upload_result)
        except requests.RequestException as error:
            print("Scan results upload failed:", error)
    else:
        print("No folder selected. Scan skipped.")

    print("\nStarting heartbeat...")

    while True:
        try:
            send_heartbeat(device_id, device_token)
        except requests.RequestException as error:
            print("Heartbeat failed:", error)

        time.sleep(30)
