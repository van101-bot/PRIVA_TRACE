from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DocumentResponse(BaseModel):
    id: int
    filename: str
    uploaded_at: datetime
    status: str
    sha256: str | None = None

    model_config = ConfigDict(from_attributes=True)
