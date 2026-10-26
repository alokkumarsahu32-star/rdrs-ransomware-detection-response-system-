from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

import platform
import uuid
from datetime import datetime


from app.database.database import (
    register_device,
    consume_device_enrollment,
    update_device_heartbeat,
    save_scan_finding_once,
    SessionLocal,
    Device,
    ScanFileResult
)


router = APIRouter(
    prefix="/api/devices",
    tags=["Devices"]
)

class DeviceEnrollmentRequest(BaseModel):
    code: str
    device_name: str
    operating_system: str


@router.post("/enroll")
def enroll_device(request: DeviceEnrollmentRequest):
    user_id = consume_device_enrollment(request.code)

    if user_id is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid, expired, or already-used enrollment code"
        )

    device_id = str(uuid.uuid4())

    device = register_device(
        device_id=device_id,
        device_name=request.device_name,
        operating_system=request.operating_system,
        user_id=user_id
    )

    return {
        "status": "registered",
        "device_id": device.device_id,
        "device_name": device.device_name,
        "operating_system": device.operating_system,
        "agent_version": device.agent_version,
        "device_token": device.device_token,
        "message": "Device enrolled successfully"
    }


@router.post("/register")
def register_device_api(
    device_name: str,
    operating_system: str
):
    device_id = str(uuid.uuid4())

    device = register_device(
        device_id=device_id,
        device_name=device_name,
        operating_system=operating_system
    )

    return {
        "status": "registered",
        "device_id": device.device_id,
        "device_name": device.device_name,
        "operating_system": device.operating_system,
        "status": device.status,
        "agent_version": device.agent_version,
        "device_token": device.device_token,
        "message": "Device registered successfully"
    }

# ==================================================
# DEVICE HEARTBEAT API
# ==================================================


@router.post("/heartbeat")
def device_heartbeat(
    device_id: str,
    authorization: str = Header(...)
):
    db = SessionLocal()

    try:
        # STEP 1: Authorization header check
        if not authorization.startswith("Bearer "):
            return {
                "status": "error",
                "message": "Invalid authorization header"
            }

        # STEP 2: Extract device token
        device_token = authorization.replace(
            "Bearer ",
            "",
            1
        ).strip()

        # STEP 3: Find device
        device = (
            db.query(Device)
            .filter(Device.device_id == device_id)
            .first()
        )

        if not device:
            return {
                "status": "error",
                "message": "Device not found"
            }

        # STEP 4: Verify token
        if device.device_token != device_token:
            return {
                "status": "error",
                "message": "Invalid device token"
            }

        # STEP 5: Update heartbeat
        device.status = "ONLINE"
        device.last_seen = datetime.now()

        db.commit()
        db.refresh(device)

        return {
            "status": "ONLINE",
            "device_id": device.device_id,
            "last_seen": device.last_seen,
            "message": "Heartbeat received successfully"
        }

    finally:
        db.close()
# ==================================================
# GET ALL DEVICES
# ==================================================

@router.get("/")
def get_devices():

    db = SessionLocal()

    try:

        devices = (
            db.query(Device)
            .order_by(Device.id.desc())
            .all()
        )

        return {
            "status": "success",
            "count": len(devices),
            "devices": [
                {
                    "id": device.id,
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "operating_system": device.operating_system,
                    "status": device.status,
                    "agent_version": device.agent_version,
                    "last_seen": device.last_seen
                }
                for device in devices
            ]
        }

    finally:

        db.close()

# ==================================================
# GET SINGLE DEVICE
# ==================================================

@router.get("/{device_id}")
def get_device(device_id: str):

    db = SessionLocal()

    try:

        device = (
            db.query(Device)
            .filter(Device.device_id == device_id)
            .first()
        )

        if not device:
            return {
                "status": "error",
                "message": "Device not found"
            }

        return {
            "status": "success",
            "device": {
                "id": device.id,
                "device_id": device.device_id,
                "device_name": device.device_name,
                "operating_system": device.operating_system,
                "status": device.status,
                "agent_version": device.agent_version,
                "last_seen": device.last_seen
            }
        }

    finally:

        db.close()

# ==================================================
# GET DEVICES BY USER
# ==================================================

@router.get("/user/{user_id}")
def get_user_devices(user_id: int):

    db = SessionLocal()

    try:

        devices = (
            db.query(Device)
            .filter(Device.user_id == user_id)
            .order_by(Device.id.desc())
            .all()
        )

        return {
            "status": "success",
            "user_id": user_id,
            "count": len(devices),
            "devices": [
                {
                    "id": device.id,
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "operating_system": device.operating_system,
                    "status": device.status,
                    "agent_version": device.agent_version,
                    "last_seen": device.last_seen
                }
                for device in devices
            ]
        }

    finally:

        db.close()


# ==================================================
# UPLOAD LOCAL SCAN RESULTS
# ==================================================

from pydantic import BaseModel, Field
from typing import List


class ScanFinding(BaseModel):
    file_path: str = Field(min_length=1, max_length=4096)
    score: int = Field(default=0, ge=0, le=100)
    risk_level: str = "NORMAL"


class ScanResultsRequest(BaseModel):
    folder_path: str = Field(min_length=1, max_length=4096)
    files_scanned: int = Field(default=0, ge=0)
    suspicious_files: List[ScanFinding] = Field(
        default_factory=list,
        max_length=500
    )
    scan_id: str = Field(default="", max_length=100)
    file_results: List[ScanFinding] = Field(
        default_factory=list,
        max_length=10000
    )

@router.post("/scan-results")
def upload_scan_results(
    request: ScanResultsRequest,
    device_id: str,
    authorization: str = Header(...)
):
    db = SessionLocal()

    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Invalid authorization header"
            )

        device_token = authorization.replace("Bearer ", "", 1).strip()

        device = db.query(Device).filter(
            Device.device_id == device_id
        ).first()

        if not device or device.device_token != device_token:
            raise HTTPException(
                status_code=401,
                detail="Invalid device credentials"
            )

        if device.user_id is None:
            raise HTTPException(
                status_code=403,
                detail="Device is not linked to a user"
            )

        processed_count = 0
        saved_results = 0
        scan_id = request.scan_id.strip() or str(uuid.uuid4())

        # Save each scanned file result
        for result in request.file_results:
            db.add(
                ScanFileResult(
                    user_id=device.user_id,
                    device_id=device.device_id,
                    scan_id=scan_id,
                    folder_path=request.folder_path,
                    file_path=result.file_path,
                    risk_level=result.risk_level.upper(),
                    score=result.score,
                )
            )
            saved_results += 1

                 # Preserve existing suspicious-event logging
        for finding in request.suspicious_files:
            save_scan_finding_once(
                file_path=finding.file_path,
                score=finding.score,
                risk_level=finding.risk_level,
                user_id=device.user_id,
                db=db,
            )
            processed_count += 1

        db.commit()


        return {
              "status": "success",
             "device_id": device.device_id,
              "scan_id": scan_id,
              "files_scanned": request.files_scanned,
              "results_received": len(request.file_results),
              "results_saved": saved_results,
              "suspicious_count": len(request.suspicious_files),
               "findings_processed": processed_count,
              "message": "Scan results processed"
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
