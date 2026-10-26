
from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, FileResponse
from starlette.middleware.sessions import SessionMiddleware

import os
try:
    import tkinter as tk
    from tkinter import filedialog
except ImportError:
    tk = None
    filedialog = None
from datetime import timezone, timedelta
import asyncio
from contextlib import asynccontextmanager
import inspect
import traceback
import secrets
import hmac
from fastapi import HTTPException
from server.api.device import router as devices_router

from app.database.database import (
    create_device_enrollment,
    get_devices_by_user,
    get_total_events,
    get_total_scanned_files,
    get_high_risk_events,
    get_suspicious_events,
    get_quarantined_events,
    get_recent_events,
    get_all_events,
    get_recent_quarantines,
    get_threat_events,
    get_monitored_folders,
    add_monitored_folder,
    remove_monitored_folder,
    update_monitored_folder_status,
)

from app.web.auth import authenticate_user, register_user
from app.system.status import system_status
from app.detector.scanner import scan_monitored_folders, format_size


# ==================================================
# FASTAPI APP
# ==================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    scan_task = asyncio.create_task(background_scan_loop())

    try:
        yield
    finally:
        scan_task.cancel()

        try:
            await scan_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Ransomware Detection & Response System",
    description="RDRS Web Application",
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(devices_router)

@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# ==================================================
# SESSION
# ==================================================
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv(
        "RDRS_SESSION_SECRET",
        "RDRS-CHANGE-THIS-SECRET-KEY",
    ),
    same_site="lax",
    https_only=False,
)


# ==================================================
# STATIC FILES AND TEMPLATES
# ==================================================
app.mount(
    "/static",
    StaticFiles(directory="app/web/static"),
    name="static",
)

templates = Jinja2Templates(directory="app/web/templates")

SCAN_INTERVAL_SECONDS = 60


async def background_scan_loop():
    """Periodically scan active, user-owned monitored folders."""
    while True:
        try:
            print("[RDRS BACKGROUND SCAN] Starting automatic scan...")

            result = await asyncio.to_thread(scan_monitored_folders)

            print(
                "[RDRS BACKGROUND SCAN] Completed. "
                f"Folders: {result['folders_scanned']}, "
                f"Files: {result['total_files']}, "
                f"Suspicious: {result['total_suspicious']}, "
                f"Risk: {result['overall_risk']}"
            )

        except asyncio.CancelledError:
            raise

        except Exception:
            print("[RDRS BACKGROUND SCAN] Scan failed:")
            traceback.print_exc()

        await asyncio.sleep(SCAN_INTERVAL_SECONDS)


# ==================================================
# HELPER FUNCTIONS
# ==================================================
def is_logged_in(request: Request) -> bool:
    return bool(
        request.session.get("logged_in")
        and request.session.get("user_id") is not None
    )


def login_redirect():
    return RedirectResponse(url="/", status_code=303)


def get_current_user_id(request: Request):
    return request.session.get("user_id")


def get_user_folders(user_id):
    """Return only folders owned by the current user."""
    folders = get_monitored_folders()
    return [
        folder for folder in folders
        if getattr(folder, "user_id", None) == user_id
    ]

def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token

    return token


def verify_csrf_token(request: Request, submitted_token: str) -> bool:
    session_token = request.session.get("csrf_token")

    if not session_token or not submitted_token:
        return False

    return hmac.compare_digest(session_token, submitted_token)


@app.post("/devices/enrollment")
def create_enrollment_code(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    submitted_token = request.headers.get("X-CSRF-Token", "")

    if not verify_csrf_token(request, submitted_token):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing CSRF token"
        )

    user_id = get_current_user_id(request)
    code = create_device_enrollment(user_id=user_id)

    return {
        "status": "success",
        "enrollment_code": code,
        "expires_in_minutes": 5,
        "message": "Use this code to enroll your RDRS agent."
    }


# ==================================================
# LOGIN PAGE
# ==================================================
@app.get("/")
def login_page(request: Request):
    error = request.session.pop("login_error", None)
    register_success = request.session.pop(
        "register_success", None
    )

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": error,
            "register_success": register_success,
        },
    )


# ==================================================
# LOGIN
# ==================================================
@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate_user(username, password)

    if user:
        request.session.clear()
        request.session["logged_in"] = True
        request.session["user_id"] = user.id
        request.session["username"] = user.username
        request.session["role"] = user.role

        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    request.session["login_error"] = (
        "Invalid username or password"
    )
    return RedirectResponse(url="/", status_code=303)


# ==================================================
# REGISTRATION PAGE
# ==================================================
@app.get("/register")
def registration_page(request: Request):
    error = request.session.pop("register_error", None)

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": error},
    )


# ==================================================
# REGISTER
# ==================================================
@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    username = username.strip()
    email = email.strip().lower()

    if not username or not email:
        request.session["register_error"] = (
            "Username and email are required."
        )
        return RedirectResponse(
            url="/register", status_code=303
        )

    if password != confirm_password:
        request.session["register_error"] = (
            "Passwords do not match."
        )
        return RedirectResponse(
            url="/register", status_code=303
        )

    if len(password) < 8:
        request.session["register_error"] = (
            "Password must contain at least 8 characters."
        )
        return RedirectResponse(
            url="/register", status_code=303
        )

    user = register_user(
        username=username,
        password=password,
        email=email,
        role="analyst",
    )

    if user is None:
        request.session["register_error"] = (
            "Registration failed. Check your details "
            "or use a different username and email."
        )
        return RedirectResponse(
            url="/register", status_code=303
        )

    request.session["register_success"] = (
        "Account created successfully. Please log in."
    )
    return RedirectResponse(url="/", status_code=303)


# ==================================================
# DASHBOARD
# ==================================================

@app.get("/dashboard")
def dashboard(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)
    devices = get_devices_by_user(user_id)
    health = system_status.get_system_health()

    total_events = get_total_events(user_id=user_id)
    total_scanned_files = get_total_scanned_files(user_id=user_id)
    high_risk_events = get_high_risk_events(user_id=user_id)
    suspicious_events = get_suspicious_events(user_id=user_id)
    quarantined_events = get_quarantined_events(user_id=user_id)
    recent_events = get_recent_events(10, user_id=user_id)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "username": request.session.get("username"),
            "csrf_token": get_csrf_token(request),
            "devices": devices,
            "total_events": total_events,
            "total_scanned_files": total_scanned_files,
            "high_risk_events": high_risk_events,
            "suspicious_events": suspicious_events,
            "quarantined_events": quarantined_events,
            "recent_events": recent_events,
            "overall_status": health["overall_status"],
            "detection_status": health["detection_status"],
            "response_status": health["response_status"],
            "database_status": health["database_status"],
            "monitoring_status": health["monitoring_status"],
        },
    )


# ==================================================
# QUARANTINE
# ==================================================
@app.get("/quarantine")
def quarantine_page(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)
    
    all_quarantines = get_recent_quarantines(
    limit=500,
    user_id=user_id,
                    )


    quarantines = [
        item for item in all_quarantines
        if getattr(item, "user_id", None) == user_id
    ][:50]

    return templates.TemplateResponse(
        request=request,
        name="quarantine.html",
        context={
            "username": request.session.get("username"),
            "quarantine_count": get_quarantined_events(
                user_id=user_id
            ),
            "quarantines": quarantines,
        },
    )


# ==================================================
# SECURITY EVENTS
# ==================================================
@app.get("/events")
def security_events_page(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)

    return templates.TemplateResponse(
        request=request,
        name="events.html",
        context={
            "username": request.session.get("username"),
            "events": get_all_events(user_id=user_id),
        },
    )


# ==================================================
# SECURITY EVENTS CSV EXPORT
# ==================================================
@app.get("/events/export")
def export_security_events_csv(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    from app.reports.csv_report import (
        generate_security_events_csv,
    )

    # NOTE: The CSV function must be updated to filter by user_id
    # before this endpoint is used in a multi-user deployment.
    report_path = generate_security_events_csv()

    return FileResponse(
        path=report_path,
        media_type="text/csv",
        filename="security_events_report.csv",
    )


# ==================================================
# THREATS CSV EXPORT
# ==================================================
@app.get("/threats/export")
def export_threats_csv(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    from app.reports.csv_report import (
        generate_security_events_csv,
    )

    # NOTE: The CSV function must be updated to filter by user_id.
    report_path = generate_security_events_csv()

    return FileResponse(
        path=report_path,
        media_type="text/csv",
        filename="threats_report.csv",
    )


# ==================================================
# THREATS
# ==================================================
@app.get("/threats")
def threats_page(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)

    return templates.TemplateResponse(
        request=request,
        name="threats.html",
        context={
            "username": request.session.get("username"),
            "threats": get_threat_events(user_id=user_id),
        },
    )


# ==================================================
# MONITORING PAGE
# ==================================================
@app.get("/monitoring")
def monitoring_page(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)
    health = system_status.get_system_health()

    return templates.TemplateResponse(
        request=request,
        name="monitoring.html",
        context={
            "username": request.session.get("username"),
            "detection_status": health["detection_status"],
            "response_status": health["response_status"],
            "database_status": health["database_status"],
            "file_monitor_status": health["monitoring_status"],
            "watch_folder": "User Selected Folders",
            "monitored_folders": get_user_folders(user_id),
        },
    )


# ==================================================
# ADD MONITORED FOLDER
# ==================================================

@app.get("/monitoring/select-folder")
def select_folder(request: Request):
    # Require login
    if not is_logged_in(request):
        return login_redirect()

    # Desktop folder picker is not available on Render
    if tk is None or filedialog is None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Desktop folder picker is unavailable on Render. "
                "Run the RDRS agent on the device you want to monitor."
            ),
        )

    folder_path = None
    root = None

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        folder_path = filedialog.askdirectory(
            title="Select Folder to Monitor"
        )

    except Exception:
        print("\n[FOLDER PICKER ERROR]")
        traceback.print_exc()

    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass

    if not folder_path:
        print("[MONITORING] Folder selection cancelled.")
        return RedirectResponse(
            url="/monitoring",
            status_code=303,
        )

    folder_path = os.path.abspath(folder_path)
    folder_name = os.path.basename(
        os.path.normpath(folder_path)
    )

    if not folder_name:
        folder_name = folder_path

    try:
        parameters = inspect.signature(
            add_monitored_folder
        ).parameters

        if "user_id" in parameters:
            add_monitored_folder(
                folder_path,
                folder_name,
                user_id=request.session["user_id"],
            )
        else:
            add_monitored_folder(
                folder_path,
                folder_name,
            )

        print("\n" + "=" * 60)
        print("[MONITORING] Folder save function completed.")
        print(f"[MONITORING] Path: {folder_path}")
        print(f"[MONITORING] User ID: {request.session['user_id']}")
        print("=" * 60)

    except Exception:
        print("\n" + "=" * 60)
        print("[DATABASE ERROR] Folder could not be added.")
        print(f"[MONITORING] Path: {folder_path}")
        traceback.print_exc()
        print("=" * 60)

    return RedirectResponse(
        url="/monitoring",
        status_code=303,
    )


# ==================================================
# MONITORING TOGGLE
# ==================================================
@app.get("/monitoring/toggle/{folder_id}")
def toggle_monitoring(
    request: Request,
    folder_id: int,
):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)
    selected_folder = next(
        (
            folder for folder in get_user_folders(user_id)
            if folder.id == folder_id
        ),
        None,
    )

    if selected_folder is None:
        return RedirectResponse(
            url="/monitoring", status_code=303
        )

    new_status = (
        "PAUSED"
        if selected_folder.status == "ACTIVE"
        else "ACTIVE"
    )

    update_monitored_folder_status(
        folder_id,
        new_status,
    )

    print(
        f"[MONITORING] Folder {folder_id} status: {new_status}"
    )

    return RedirectResponse(
        url="/monitoring", status_code=303
    )


# ==================================================
# REMOVE MONITORED FOLDER
# ==================================================
@app.post("/monitoring/remove-folder/{folder_id}")
def remove_folder(
    request: Request,
    folder_id: int,
):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)
    owns_folder = any(
        folder.id == folder_id
        for folder in get_user_folders(user_id)
    )

    if owns_folder:
        remove_monitored_folder(folder_id)

    return RedirectResponse(
        url="/monitoring", status_code=303
    )


# ==================================================
# SCAN NOW
# ==================================================
@app.get("/scan")
def scan_now(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    scan_results = scan_monitored_folders(
    user_id=get_current_user_id(request)
)

    return templates.TemplateResponse(
        request=request,
        name="scan_results.html",
        context={
            "username": request.session.get("username"),
            "scan_results": scan_results,
            "format_size": format_size,
        },
    )


# ==================================================
# SYSTEM STATUS
# ==================================================
@app.get("/system-status")
def system_status_page(request: Request):
    if not is_logged_in(request):
        return login_redirect()

    user_id = get_current_user_id(request)
    health = system_status.get_system_health()

    return templates.TemplateResponse(
        request=request,
        name="system_status.html",
        context={
            "username": request.session.get("username"),
            "total_events": get_total_events(user_id=user_id),
            "high_risk_events": get_high_risk_events(user_id=user_id),
            "suspicious_events": get_suspicious_events(user_id=user_id),
            "quarantined_events": get_quarantined_events(
                user_id=user_id
            ),
            "overall_status": health["overall_status"],
            "detection_status": health["detection_status"],
            "response_status": health["response_status"],
            "database_status": health["database_status"],
            "monitoring_status": health["monitoring_status"],
            "web_status": "RUNNING",
            "monitor_started_at": (
                system_status.get_monitor_started_at()
            ),
        },
    )


# ==================================================
# LOGOUT
# ==================================================
@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


# ==================================================
# DASHBOARD API
# ==================================================
@app.get("/api/dashboard")
def dashboard_api(request: Request):
    if not is_logged_in(request):
        return {"authenticated": False}

    user_id = get_current_user_id(request)
    health = system_status.get_system_health()
    recent_events = get_recent_events(10, user_id=user_id)

    return {
        "authenticated": True,
        "total_events": get_total_events(user_id=user_id),
        "total_scanned_files": get_total_scanned_files(user_id=user_id),
        "high_risk_events": get_high_risk_events(user_id=user_id),
        "suspicious_events": get_suspicious_events(user_id=user_id),
        "quarantined_events": get_quarantined_events(
            user_id=user_id
        ),
        "monitoring_status": health["monitoring_status"],
        "detection_status": health["detection_status"],
        "response_status": health["response_status"],
        "database_status": health["database_status"],
        "recent_events": [
            {
                "id": event.id,
                "timestamp": (
                    event.timestamp.replace(tzinfo=timezone.utc)
                    + timedelta(hours=5, minutes=30)
                ).strftime("%H:%M:%S"),
                "event_type": event.event_type,
                "file_path": event.file_path,
                "score": event.score,
                "risk_level": event.risk_level,
            }
            for event in recent_events
        ],
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.web.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )
