
import os
import sys

SERVER_URL = "https://rdrs-ransomware-detection-response.onrender.com"

AGENT_VERSION = "1.0.0"

# Installed EXE: keep credentials in persistent Windows user data.
# Source mode: preserve the existing project folder locations.
if getattr(sys, "frozen", False):
    APP_DATA_DIR = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "RDRS",
    )
    os.makedirs(APP_DATA_DIR, exist_ok=True)
else:
    APP_DATA_DIR = os.path.dirname(os.path.abspath(__file__))

DEVICE_ID_FILE = os.path.join(
    APP_DATA_DIR,
    "device_id.txt",
)

DEVICE_TOKEN_FILE = os.path.join(
    APP_DATA_DIR,
    "device_token.txt",
)
