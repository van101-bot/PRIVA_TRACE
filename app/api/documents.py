
import hashlib
import hmac
import io
import logging
import zipfile
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.audit_log import AuditLog
from app.models.document import Document
from app.models.user import User
from app.services.encryption import encrypt_file, decrypt_file
from app.services.key_management import (
    wrap_document_key,
    unwrap_document_key,
)

router = APIRouter(prefix="/documents", tags=["Documents"])

STORAGE_DIR = Path("storage/encrypted")
MAX_FILE_SIZE = 50 * 1024 * 1024

logger = logging.getLogger(__name__)

CONTENT_TYPES = {
    ".pdf": "application/pdf",
    ".docx": (
        "application/vnd.openxmlformats-officedocument."
        "wordprocessingml.document"
    ),
    ".doc": "application/msword",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}

ALLOWED_EXTENSIONS = set(CONTENT_TYPES)


def validate_file_content(filename: str, content: bytes) -> bool:
    """Perform basic format/signature checks on supported files."""
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return False

    if extension == ".pdf":
        return content.startswith(b"%PDF-")

    if extension == ".png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")

    if extension in {".jpg", ".jpeg"}:
        return content.startswith(b"\xff\xd8\xff")

    if extension == ".doc":
        return content.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))

    if extension == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = archive.namelist()
                return (
                    archive.testzip() is None
                    and "word/document.xml" in names
                    and "[Content_Types].xml" in names
                )
        except (zipfile.BadZipFile, OSError):
            return False

    return False


@router.post("/upload", status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    storage_path = None

    try:
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="A filename is required",
            )

        filename = Path(file.filename.replace("\\", "/")).name
        extension = Path(filename).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=415,
                detail="Supported formats: PDF, DOC, DOCX, PNG, JPG, JPEG",
            )

        content = await file.read(MAX_FILE_SIZE + 1)

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File exceeds 50 MB limit",
            )

        if not content:
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty",
            )

        if not validate_file_content(filename, content):
            raise HTTPException(
                status_code=400,
                detail="File content does not match its file extension",
            )

        encrypted = encrypt_file(content)
        wrapped = wrap_document_key(encrypted["key"])
        file_hash = hashlib.sha256(content).hexdigest()

        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        storage_path = STORAGE_DIR / f"{uuid4().hex}.enc"
        storage_path.write_bytes(encrypted["ciphertext"])

        document = Document(
            filename=filename,
            status="encrypted",
            sha256=file_hash,
            encrypted_path=str(storage_path),
            nonce=encrypted["nonce"].hex(),
            wrapped_key=wrapped["wrapped_key"],
            key_nonce=wrapped["key_nonce"],
            owner_id=current_user.id,
        )

        db.add(document)
        db.commit()
        db.refresh(document)

        return {
            "document_id": document.id,
            "filename": document.filename,
            "file_type": extension,
            "sha256": file_hash,
            "status": document.status,
        }

    except HTTPException:
        raise

    except Exception:
        db.rollback()
        logger.exception("Document upload failed")

        if storage_path is not None:
            try:
                storage_path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Failed to remove encrypted file")

        raise HTTPException(
            status_code=500,
            detail="Document encryption or storage failed",
        )

    finally:
        await file.close()


@router.get("/")
def list_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    documents = (
        db.query(Document)
        .filter(Document.owner_id == current_user.id)
        .order_by(Document.id.desc())
        .all()
    )

    return [
        {
            "document_id": doc.id,
            "filename": doc.filename,
            "file_type": Path(doc.filename).suffix.lower(),
            "uploaded_at": doc.uploaded_at,
            "status": doc.status,
            "sha256": doc.sha256,
        }
        for doc in documents
    ]


@router.get("/audit")
def list_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return audit history for documents owned by the current user."""
    logs = (
        db.query(AuditLog)
        .join(Document, AuditLog.document_id == Document.id)
        .filter(
            AuditLog.user_id == current_user.id,
            Document.owner_id == current_user.id,
        )
        .order_by(AuditLog.id.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "audit_id": log.id,
            "document_id": log.document_id,
            "event": log.event,
            "outcome": log.outcome,
            "created_at": log.created_at,
        }
        for log in logs
    ]


@router.post("/{document_id}/decrypt")
def decrypt_document(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    document = (
        db.query(Document)
        .filter(
            Document.id == document_id,
            Document.owner_id == current_user.id,
        )
        .first()
    )

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    if not all([
        document.filename,
        document.encrypted_path,
        document.nonce,
        document.wrapped_key,
        document.key_nonce,
        document.sha256,
    ]):
        raise HTTPException(
            status_code=409,
            detail="Document is missing encryption metadata",
        )

    extension = Path(document.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail="Stored file type is not supported",
        )

    storage_path = Path(document.encrypted_path)

    if not storage_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Encrypted file not found",
        )

    try:
        ciphertext = storage_path.read_bytes()
        nonce = bytes.fromhex(document.nonce)

        if len(nonce) != 12:
            raise ValueError("Invalid encryption nonce")

        key = unwrap_document_key(
            document.wrapped_key,
            document.key_nonce,
        )

        if len(key) != 32:
            raise ValueError("Invalid document key")

        original_bytes = decrypt_file(
            ciphertext=ciphertext,
            key=key,
            nonce=nonce,
        )

        actual_hash = hashlib.sha256(original_bytes).hexdigest()

        if not hmac.compare_digest(actual_hash, document.sha256):
            raise HTTPException(
                status_code=422,
                detail="Decrypted file hash verification failed",
            )

        if not validate_file_content(document.filename, original_bytes):
            raise HTTPException(
                status_code=422,
                detail="Decrypted file content is invalid",
            )

    except HTTPException:
        raise

    except InvalidTag:
        raise HTTPException(
            status_code=422,
            detail="Decryption failed: key or encrypted data is invalid",
        )

    except (ValueError, TypeError):
        logger.exception(
            "Invalid encryption metadata for document %s",
            document_id,
        )
        raise HTTPException(
            status_code=422,
            detail="Document encryption metadata is invalid",
        )

    except OSError:
        logger.exception("Storage error for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Unable to read the encrypted document",
        )

    except Exception:
        logger.exception("Decryption failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Document decryption failed",
        )

    # Save an audit record before returning the decrypted file.
    try:
        db.add(
            AuditLog(
                document_id=document.id,
                user_id=current_user.id,
                event="document_decryption",
                outcome="success",
            )
        )
        db.commit()

    except Exception:
        db.rollback()
        logger.exception("Failed to save decryption audit record")

        raise HTTPException(
            status_code=500,
            detail="Decryption succeeded, but audit logging failed",
        )

    safe_filename = Path(document.filename).name

    return Response(
        content=original_bytes,
        media_type=CONTENT_TYPES[extension],
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )