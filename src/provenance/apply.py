"""
Single entry point for watermarking and reading watermarks.

Robust (survives re-save / screenshot / print-scan to a degree) - Member 2:
    .pdf  -> PDFWatermarker    (text-edge differential embedding)
    .png  -> ImageWatermarker  (DCT-domain embedding)
    watermark_id = SHA-256(ZKP proof), hex (64 chars)  <- matches the spec

Fragile metadata fallback (exact, but removed by any re-save):
    .jpg/.jpeg/.docx -> src.provenance.embed + ForensicWatermark
    watermark_id = ForensicWatermark ID (base64url, 43 chars)

Both ID formats pass WATERMARK_ID_PATTERN, so every endpoint accepts either.
"""

from __future__ import annotations

import hashlib
import io
import time
from dataclasses import dataclass

from src.provenance.embed import embed as embed_metadata
from src.provenance.embed import extract as extract_metadata
from src.provenance.watermark import ForensicWatermark

ROBUST_EXTENSIONS = {".pdf", ".png"}
METADATA_EXTENSIONS = {".jpg", ".jpeg", ".docx"}
SUPPORTED_EXTENSIONS = ROBUST_EXTENSIONS | METADATA_EXTENSIONS

# Measured on the image watermarker: the raw "confidence" it reports is NOT a
# detector (blank/smooth unmarked images score 0.92-1.0, and blurred marked
# images can score 0.97 with flipped bits). So an extracted robust ID is only
# a CANDIDATE. It counts as a detection only if it is within MAX_BIT_DISTANCE
# bits of an ID in the ledger. Random 256-bit IDs differ by ~128 +/- 8 bits
# (measured unmarked-vs-real: 129-143), so 60 is ~8 sigma from chance.
MAX_BIT_DISTANCE = 60


@dataclass(frozen=True)
class WatermarkResult:
    file_bytes: bytes
    watermark_id: str
    robust: bool


def watermark_id_for_proof(zkp_proof: str) -> str:
    """Spec rule: watermark_id = SHA256(ZKP_proof). Same as Member 2's code."""
    return hashlib.sha256(zkp_proof.encode("utf-8")).hexdigest()


# Lazy imports: pymupdf/numpy are only needed when a robust format is used.
def _pdf():
    from src.provenance.pdf_watermarker import PDFWatermarker

    return PDFWatermarker()


def _img():
    from src.provenance.image_watermarker import ImageWatermarker

    return ImageWatermarker()


def apply_watermark(
    content: bytes,
    extension: str,
    *,
    zkp_proof: str,
    document_id: str,
    document_hash: str,
) -> WatermarkResult:
    """
    Watermark one copy. Raises on any failure so the caller releases nothing.

    The recipient's identity is never passed in: the proof is the only link.
    """
    ext = extension.lower()

    if ext in ROBUST_EXTENSIONS:
        expected = watermark_id_for_proof(zkp_proof)

        if ext == ".pdf":
            marked = _pdf().embed_invisible_watermark(
                content, "", 0, zkp_proof=zkp_proof
            )
        else:
            from PIL import Image

            image = Image.open(io.BytesIO(content))
            marked_image, produced = _img().embed_watermark(
                image, "", 0, zkp_proof=zkp_proof
            )
            if produced != expected:
                raise RuntimeError("watermark ID mismatch while embedding")
            buffer = io.BytesIO()
            marked_image.save(buffer, format="PNG")  # lossless
            marked = buffer.getvalue()

        # Self-check: never release a copy we cannot read back.
        found_id, _ = read_watermark(marked, ext)
        if found_id != expected:
            raise RuntimeError("watermark failed its read-back check")

        return WatermarkResult(marked, expected, robust=True)

    if ext == ".docx":
        from src.provenance.docx_watermarker import (
            DocxCapacityError,
            embed_watermark_id,
        )

        expected = watermark_id_for_proof(zkp_proof)
        try:
            marked = embed_watermark_id(content, expected, int(time.time()))
        except Exception:  # too short or unreadable: use the metadata mark below
            marked = None  # too short for the spacing mark: use metadata below

        if marked is not None:
            # Self-check: never release a copy we cannot read back.
            found_id, _ = read_watermark(marked, ext)
            if found_id != expected:
                raise RuntimeError("watermark failed its read-back check")
            return WatermarkResult(marked, expected, robust=False)

    if ext in METADATA_EXTENSIONS:
        payload = ForensicWatermark.generate(
            document_id=document_id,
            document_hash=document_hash,
            recipient_commitment=watermark_id_for_proof(zkp_proof),
            session_id="zkp-v1",
        )
        marked = embed_metadata(content, ext, ForensicWatermark.serialize(payload))
        return WatermarkResult(marked, payload.watermark_id, robust=False)

    raise ValueError(f"unsupported file type: {ext}")


def read_watermark(content: bytes, extension: str) -> tuple[str, float]:
    """
    Return (watermark_id, raw_confidence in 0..1).
    For robust formats the ID is a CANDIDATE: confirm it with match_known().
    Raises ValueError when nothing usable is found.
    """
    ext = extension.lower()

    if ext in ROBUST_EXTENSIONS:
        if ext == ".pdf":
            result = _pdf().extract_watermark(content)
        else:
            from PIL import Image

            result = _img().extract_watermark(Image.open(io.BytesIO(content)))

        found_id = result.get("watermark_id")
        if not found_id:
            raise ValueError("no watermark found")
        return found_id, min(max(float(result.get("confidence") or 0.0), 0.0), 1.0)

    if ext == ".docx":
        from src.provenance.docx_watermarker import extract_watermark_id

        try:
            return extract_watermark_id(content)[0], 1.0
        except Exception:
            pass  # no spacing mark: try the metadata mark below

    if ext in METADATA_EXTENSIONS:
        payload = ForensicWatermark.deserialize(extract_metadata(content, ext))
        if not ForensicWatermark.verify(payload):
            raise ValueError("watermark failed its integrity check")
        return payload.watermark_id, 1.0

    raise ValueError(f"unsupported file type: {ext}")


def is_robust_id(watermark_id: str) -> bool:
    """Robust-format IDs are 64 hex chars (SHA-256 of the ZKP proof)."""
    return len(watermark_id) == 64 and all(
        c in "0123456789abcdef" for c in watermark_id
    )


def bit_distance(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def match_known(
    candidate_id: str, known_ids: list[str]
) -> tuple[str, float] | None:
    """
    Find the ledger ID closest to an extracted candidate.

    Returns (watermark_id, confidence) or None. confidence is 1.0 for an
    exact match, otherwise 1 - distance/128 (so 60 bits off -> ~0.53).
    Nothing is returned when the best match is farther than MAX_BIT_DISTANCE,
    i.e. when the file is unmarked, from another system, or too damaged.
    """
    if not is_robust_id(candidate_id):
        return None
    best_id, best = None, MAX_BIT_DISTANCE + 1
    for known in known_ids:
        if not is_robust_id(known):
            continue
        d = bit_distance(candidate_id, known)
        if d < best:
            best_id, best = known, d
            if d == 0:
                break
    if best_id is None:
        return None
    return best_id, (1.0 if best == 0 else max(0.0, 1.0 - best / 128.0))