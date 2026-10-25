"""
Privacy-first request/response schemas for the SIH26237 API.

Rule: no response model in this file contains a recipient_id or a
recipient_commitment. Recipients are only ever referred to through a
watermark_id and a zero-knowledge proof.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# Only letters, digits and hyphens, max 64 chars (same rule as the file IDs).
FILE_ID_PATTERN = r"^[A-Za-z0-9-]{1,64}$"
# Watermark IDs are encoded digests, so allow URL-safe characters too.
WATERMARK_ID_PATTERN = r"^[A-Za-z0-9_\-=]{8,128}$"


class StrictModel(BaseModel):
    """Reject unexpected fields so clients cannot smuggle extra data in."""

    model_config = ConfigDict(extra="forbid")


# ---------- POST /encrypt ----------

class EncryptResponse(BaseModel):
    document_hash: str
    encrypted_file_id: str
    status: str


# ---------- POST /decrypt ----------

class DecryptRequest(StrictModel):
    encrypted_file_id: str = Field(pattern=FILE_ID_PATTERN)
    recipient_id: str = Field(min_length=1, max_length=128)
    private_key: str = Field(description="Base64-encoded ML-KEM private key")


class DecryptResponse(BaseModel):
    watermark_id: str
    zkp_proof: str
    timestamp: datetime
    # Base64 of the watermarked file.
    watermarked_file: str


# ---------- POST /extract-watermark ----------

class ExtractWatermarkResponse(BaseModel):
    watermark_id: str
    confidence: float = Field(ge=0.0, le=1.0)


# ---------- POST /attribute-with-zkp ----------

class AttributeRequest(StrictModel):
    watermark_id: str = Field(pattern=WATERMARK_ID_PATTERN)


class AttributeResponse(BaseModel):
    """Answers 'is this leak from an authorized recipient?' without a name."""

    is_authorized: bool
    zkp_verified: bool


# ---------- GET /ledger/{watermark_id} ----------

class LedgerProofResponse(BaseModel):
    watermark_id: str
    zkp_proof: str
    timestamp: datetime
    signature: str


# ---------- POST /batch-decrypt ----------

class BatchRecipient(StrictModel):
    recipient_id: str = Field(min_length=1, max_length=128)
    private_key: str = Field(description="Base64-encoded ML-KEM private key")


class BatchDecryptRequest(StrictModel):
    encrypted_file_id: str = Field(pattern=FILE_ID_PATTERN)
    recipients: list[BatchRecipient] = Field(min_length=1, max_length=100)


# ---------- POST /generate-attribution-report ----------

class ReportRequest(StrictModel):
    watermark_id: str = Field(pattern=WATERMARK_ID_PATTERN)


# ---------- key revocation ----------

class RevokeKeyRequest(StrictModel):
    recipient_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=255)


class RevokeKeyResponse(BaseModel):
    # Hash only; the raw recipient ID is never echoed back.
    recipient_id_hash: str
    revoked_at: datetime
    status: str