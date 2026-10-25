"""
Request audit logging + request IDs.

Every API request is written to access_logs (who, what, when, result).
Audit logging is fail-open: if the database write fails, the request still
completes and the failure goes to the server log.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from starlette.concurrency import run_in_threadpool

from app.core.security import decode_access_token
from app.database.database import SessionLocal
from app.models.access_log import AccessLog

logger = logging.getLogger("audit")

SKIP_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc"}


def _outcome(status_code: int) -> str:
    if status_code < 400:
        return "success"
    if status_code in (401, 403):
        return "denied"
    if status_code == 429:
        return "limited"
    if status_code >= 500:
        return "error"
    return "rejected"


def _user_id(request: Request) -> int | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    try:
        return int(decode_access_token(header[7:].strip()).get("sub"))
    except Exception:
        return None


def _resource(request: Request) -> str | None:
    value = getattr(request.state, "audit_resource", None)
    if value is None and request.url.path.startswith("/ledger/"):
        value = request.url.path[len("/ledger/"):]
    return str(value)[:128] if value else None


def _write_row(row: AccessLog) -> None:
    try:
        with SessionLocal() as db:
            db.add(row)
            db.commit()
    except Exception:
        logger.exception("Could not write access log (request_id=%s)", row.request_id)


def install_audit(app: FastAPI) -> None:
    @app.middleware("http")
    async def audit_middleware(request: Request, call_next):
        started = time.perf_counter()
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            if request.url.path not in SKIP_PATHS:
                row = AccessLog(
                    request_id=request_id,
                    user_id=_user_id(request),
                    method=request.method,
                    path=request.url.path[:255],
                    resource=_resource(request),
                    status_code=status_code,
                    outcome=_outcome(status_code),
                    client_ip=request.client.host if request.client else None,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
                await run_in_threadpool(_write_row, row)