"""GET /qkd/status - which QKD and TLS mode the server is running in."""

import os

from fastapi import APIRouter

from app.core.qkd_api import QKDEncryptedAPI

router = APIRouter(tags=["QKD"])


@router.get("/qkd/status")
def qkd_status():
    api = QKDEncryptedAPI()
    status = api.status()
    return {
        "qkd_mode": status.mode,
        "qkd_available": status.available,
        "detail": status.detail,
        "tls_psk_supported": api.psk_supported(),
        "tls_mode_in_use": os.getenv("TLS_MODE", "none (plain HTTP)"),
    }