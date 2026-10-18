import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEVICE_ID_FILE = os.path.join(
    BASE_DIR,
    "device_id.txt"
)
DEVICE_TOKEN_FILE = os.path.join(
    BASE_DIR,
    "device_token.txt"
)

SERVER_URL = "http://127.0.0.1:8001"

AGENT_VERSION = "1.0.0"