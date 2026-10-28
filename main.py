import logging

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------- Routers ----------
from app.api.auth import router as auth_router
from app.api.documents import router as documents_router
from app.api.encryption import router as encryption_router
from app.api.decrypt_watermarked import router as decrypt_watermarked_router  # Step 7
from app.api.batch_decrypt import router as batch_decrypt_router              # Step 10
from app.api.extract_watermark import router as extract_watermark_router      # Step 4
from app.api.attribute_with_zkp import router as attribute_with_zkp_router    # Step 5
from app.api.fabric import router as fabric_router
from app.api.ledger_chain import router as ledger_chain_router                # hash-chain ledger
from app.api.ledger_proof import router as ledger_proof_router                # Step 6
from app.api.revocation import router as revocation_router                    # Step 11
from app.api.attribution_report import router as attribution_report_router    # Step 12
from app.api.access_log import router as access_log_router                    # Step 14
from app.api.provenance import router as provenance_router                    # Step 15
from app.api.qkd_status import router as qkd_status_router                    # Step 16

# NOT registered any more (legacy, replaced by the routers above):
#   decryption, watermark, attribution, ledger, batch, reports

from app.core.audit import install_audit
from app.core.dependencies import get_current_user
from app.core.rate_limit import rate_limit
from app.database.database import engine

# ---------- Models (imported so their tables get created) ----------
from app.models.document import Base, Document
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.decryption_record import DecryptionRecord
from app.models.key_revocation import KeyRevocation
from app.models.access_log import AccessLog  # Step 14


Base.metadata.create_all(bind=engine)

logger = logging.getLogger("app")

app = FastAPI(
    title="SIH26237 Backend",
    description="Cryptographic attribution and decryption provenance (privacy-first)",
    version="0.8.0",
)

# Request IDs + audit log of every request.
install_audit(app)

# Desktop frontend (Electron): dev server origin, plus "null" for the packaged file:// app.
import os
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,null"
    ).split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Request-ID"],
)


# ---------- Global error handlers ----------
@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # Default FastAPI echoes the submitted input (could include private keys).
    # Return only where/what/type.
    errors = [
        {
            "loc": list(e.get("loc", [])),
            "msg": e.get("msg", ""),
            "type": e.get("type", ""),
        }
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "detail": errors,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.exception("Unhandled error (request_id=%s)", request_id)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )


def guarded(name: str, limit: int) -> dict:
    """Rate limit first (so floods are cut early), then require a valid JWT."""
    return {
        "dependencies": [
            Depends(rate_limit(name, limit)),
            Depends(get_current_user),
        ]
    }


app.include_router(auth_router, dependencies=[Depends(rate_limit("auth", 10))])
app.include_router(documents_router, dependencies=[Depends(rate_limit("documents", 60))])

app.include_router(encryption_router, **guarded("encrypt", 20))
app.include_router(decrypt_watermarked_router, **guarded("decrypt", 30))
app.include_router(batch_decrypt_router, **guarded("batch-decrypt", 5))
app.include_router(extract_watermark_router, **guarded("extract", 60))
app.include_router(attribute_with_zkp_router, **guarded("attribute", 60))
app.include_router(ledger_proof_router, **guarded("ledger", 60))
app.include_router(fabric_router, **guarded("fabric", 10))
app.include_router(ledger_chain_router, **guarded("ledger-chain", 30))
app.include_router(attribution_report_router, **guarded("report", 20))
app.include_router(revocation_router, **guarded("revocation", 30))
app.include_router(access_log_router, **guarded("access-log", 30))
app.include_router(provenance_router, **guarded("provenance", 60))
app.include_router(qkd_status_router, **guarded("qkd-status", 60))



@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "SIH26237 Backend",
    }

from pathlib import Path
from fastapi.staticfiles import StaticFiles

_web = Path(__file__).parent / "frontend" / "out" / "renderer"
if _web.exists():
    app.mount("/", StaticFiles(directory=_web, html=True), name="web")