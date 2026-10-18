from fastapi import FastAPI
from server.api.device import router as device_router

app = FastAPI(
    title="RDRS Central Server",
    description="Central server for Ransomware Detection and Response System",
    version="1.0.0"
)

app.include_router(device_router)


@app.get("/")
def home():
    return {
        "status": "online",
        "message": "RDRS Central Server is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }