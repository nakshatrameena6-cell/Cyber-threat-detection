"""FastAPI Application Foundation (REQ-API-001)."""
from fastapi import FastAPI
from ai_threat_detection.api.routes import router

app = FastAPI(
    title="AI Threat Detection & Response Control Plane",
    description="Safety-First Cyber Threat Detection and Response API",
    version="0.1.0"
)

app.include_router(router)


@app.get("/healthz")
def healthz():
    return {"status": "HEALTHY", "service": "ai-threat-detection", "version": "0.1.0"}
