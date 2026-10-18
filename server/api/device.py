from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

import platform
import uuid
from datetime import datetime

from app.database.database import (
    register_device,
    consume_device_enrollment,
    update_device_heartbeat,
    SessionLocal,
    Device
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