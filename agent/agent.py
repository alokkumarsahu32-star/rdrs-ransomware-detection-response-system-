import platform
import socket
import requests
import os
import time

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

    response.raise_for_status()

    data = response.json()

    print(
        "Heartbeat:",
        data.get("status"),
        "| Last Seen:",
        data.get("last_seen")
    )

# ==================================================
# MAIN AGENT
# ==================================================

if __name__ == "__main__":
    print("RDRS Agent started")

    device_id, device_token = register_agent()

    print("Starting heartbeat...")

    while True:

        try:
            send_heartbeat(device_id, device_token)

        except requests.RequestException as error:

            print(
                "Heartbeat failed:",
                error
            )

        time.sleep(30)