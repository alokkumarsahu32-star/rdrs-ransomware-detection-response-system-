
import os
import threading
import uvicorn

from app.detector.file_monitor import start_monitor


def main():
    print("=" * 55)
    print("RANSOMWARE DETECTION & RESPONSE SYSTEM")
    print("=" * 55)
    print("System starting...")
    print()

    # Start file monitor in the background
    monitor_thread = threading.Thread(
        target=start_monitor,
        daemon=True
    )
    monitor_thread.start()

    # Start web server
    port = int(os.environ.get("PORT", 8000))

    print()
    print("[WEB] Starting RDRS Web Application...")
    print(f"[WEB] Listening on port: {port}")
    print()

    uvicorn.run(
        "app.web.main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )


if __name__ == "__main__":
    main()
