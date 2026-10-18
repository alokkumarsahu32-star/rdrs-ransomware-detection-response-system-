
import threading
import uvicorn

from app.detector.file_monitor import start_monitor


def main():

    print("=" * 55)
    print("RANSOMWARE DETECTION & RESPONSE SYSTEM")
    print("=" * 55)
    print("System starting...")
    print()

    # ================================================
    # START FILE MONITOR IN BACKGROUND
    # ================================================

    monitor_thread = threading.Thread(
        target=start_monitor,
        daemon=True
    )

    monitor_thread.start()

    # ================================================
    # START WEB SERVER
    # ================================================

    print()
    print("[WEB] Starting RDRS Web Application...")
    print("[WEB] URL: http://127.0.0.1:8000")
    print()

    uvicorn.run(
        "app.web.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )


if __name__ == "__main__":
    main()
