"""Tests for src/provenance/apply.py (robust + metadata watermarking)."""

import io
import zipfile

import numpy as np
import pytest
from PIL import Image, ImageFilter

from src.provenance.apply import (
    MAX_BIT_DISTANCE,
    apply_watermark,
    bit_distance,
    match_known,
    read_watermark,
    watermark_id_for_proof,
)

PROOF_A = '{"recipient_commitment":"aa","proof":{"c":"1"},"document_binding":"00"}'
PROOF_B = '{"recipient_commitment":"bb","proof":{"c":"2"},"document_binding":"00"}'
HASH = "00" * 32


def _png(seed=1, size=(480, 640)) -> bytes:
    rng = np.random.default_rng(seed)
    arr = rng.normal(128, 40, size).clip(0, 255).astype(np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr).convert("RGB").save(buf, format="PNG")
    return buf.getvalue()


def _wm(content, ext, proof=PROOF_A):
    return apply_watermark(
        content, ext, zkp_proof=proof, document_id="doc-1", document_hash=HASH
    )


# ---------- robust PNG ----------

def test_png_id_is_sha256_of_proof():
    r = _wm(_png(), ".png")
    assert r.robust
    assert r.watermark_id == watermark_id_for_proof(PROOF_A)
    assert len(r.watermark_id) == 64


def test_png_round_trip_exact():
    r = _wm(_png(), ".png")
    found, _ = read_watermark(r.file_bytes, ".png")
    assert found == r.watermark_id


def test_png_survives_jpeg_q50_and_blur():
    r = _wm(_png(), ".png")
    marked = Image.open(io.BytesIO(r.file_bytes))
    buf = io.BytesIO()
    marked.convert("RGB").save(buf, format="JPEG", quality=50)
    found, _ = read_watermark(buf.getvalue(), ".png")
    assert bit_distance(found, r.watermark_id) <= 6

    blurred = io.BytesIO()
    marked.filter(ImageFilter.GaussianBlur(1.0)).save(blurred, format="PNG")
    found, _ = read_watermark(blurred.getvalue(), ".png")
    assert bit_distance(found, r.watermark_id) <= MAX_BIT_DISTANCE


def test_two_proofs_give_different_ids():
    a, b = _wm(_png(), ".png", PROOF_A), _wm(_png(), ".png", PROOF_B)
    assert a.watermark_id != b.watermark_id


# ---------- ledger matching (the real detector) ----------

def test_match_known_exact_and_noisy():
    a = watermark_id_for_proof(PROOF_A)
    b = watermark_id_for_proof(PROOF_B)
    assert match_known(a, [b, a]) == (a, 1.0)

    flipped = format(int(a, 16) ^ 0b1011, "064x")  # 3 bits wrong
    found, conf = match_known(flipped, [b, a])
    assert found == a and 0.9 < conf < 1.0


def test_match_known_rejects_unrelated_and_unmarked():
    a = watermark_id_for_proof(PROOF_A)
    unrelated = watermark_id_for_proof("something else entirely")
    assert match_known(unrelated, [a]) is None  # ~128 bits apart
    assert match_known("not-hex-metadata-id", [a]) is None


def test_unmarked_image_is_not_attributed():
    """An unmarked image still yields a candidate ID; the ledger rejects it."""
    known = [watermark_id_for_proof(PROOF_A)]
    candidate, _ = read_watermark(_png(seed=99), ".png")
    assert match_known(candidate, known) is None


# ---------- metadata fallback ----------

def test_jpeg_metadata_round_trip():
    buf = io.BytesIO()
    Image.fromarray(np.full((64, 64, 3), 120, np.uint8)).save(buf, format="JPEG")
    r = _wm(buf.getvalue(), ".jpg")
    assert not r.robust
    found, conf = read_watermark(r.file_bytes, ".jpg")
    assert found == r.watermark_id and conf == 1.0
    assert len(r.watermark_id) != 64  # base64url, not the hex scheme


def test_docx_metadata_round_trip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
    r = _wm(buf.getvalue(), ".docx")
    found, _ = read_watermark(r.file_bytes, ".docx")
    assert found == r.watermark_id


def test_unsupported_extension_raises():
    with pytest.raises(ValueError):
        _wm(b"x", ".txt")


# ---------- PDF (needs pymupdf) ----------

def test_pdf_round_trip():
    pymupdf = pytest.importorskip("pymupdf")
    doc = pymupdf.open()
    page = doc.new_page()
    for i in range(40):
        page.insert_text((60, 60 + i * 16), f"Confidential line {i} lorem ipsum dolor sit amet", fontsize=11)
    pdf = doc.tobytes()
    r = _wm(pdf, ".pdf")
    assert r.robust and r.watermark_id == watermark_id_for_proof(PROOF_A)
    found, _ = read_watermark(r.file_bytes, ".pdf")
    assert found == r.watermark_id