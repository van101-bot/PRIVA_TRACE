"""GET /access-log - the caller's own recent API activity."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.access_log import AccessLog
from app.models.user import User

router = APIRouter(tags=["Audit"])


class AccessLogItem(BaseModel):
    created_at: datetime
    method: str
    path: str
    resource: str | None
    status_code: int
    outcome: str
    request_id: str


@router.get("/access-log", response_model=list[AccessLogItem])
def my_access_log(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AccessLog)
        .filter(AccessLog.user_id == current_user.id)
        .order_by(AccessLog.id.desc())
        .limit(limit)
        .all()
    )
    return [
        AccessLogItem(
            created_at=r.created_at,
            method=r.method,
            path=r.path,
            resource=r.resource,
            status_code=r.status_code,
            outcome=r.outcome,
            request_id=r.request_id,
        )
        for r in rows
    ]