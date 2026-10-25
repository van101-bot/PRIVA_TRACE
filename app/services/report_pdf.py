"""
Builds the privacy-preserving attribution report PDF.

The report states WHAT was verified (ZKP proof, ledger signature) and WHICH
decryption event it belongs to. It never contains a recipient identity or the
recipient's public ZKP commitment.
"""

from __future__ import annotations

import hashlib
import io
import os
from datetime import datetime, timezone

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import os as _os

LEDGER_BACKEND_LABEL = (
    "Local signed ledger + Hyperledger Fabric (anchoring enabled)"
    if _os.getenv("FABRIC_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
    else "Local signed ledger (Hyperledger Fabric not connected)"
)


def ledger_backend_label() -> str:
    """Same switch the /fabric routes use (FABRIC_ENABLED=1)."""
    if os.environ.get("FABRIC_ENABLED", "0") == "1":
        return "Local signed ledger + Hyperledger Fabric (anchoring enabled)"
    return LEDGER_BACKEND_LABEL

COURT_ORDER_CLAUSE = (
    "This report proves that the leaked copy was produced by an authorized "
    "decryption event recorded on the ledger. It intentionally does not reveal "
    "who the recipient is: no recipient identity is stored in this report or "
    "in the ledger record. The identity behind this event may be disclosed "
    "only under a valid court order served on the document owner, who is the "
    "custodian of the recipient registry. Any such disclosure must itself be "
    "recorded in the audit log."
)

_styles = getSampleStyleSheet()
TITLE = ParagraphStyle("t", parent=_styles["Title"], fontSize=20, spaceAfter=2)
SUB = ParagraphStyle("s", parent=_styles["Normal"], fontSize=9,
                     textColor=colors.HexColor("#555555"), spaceAfter=10)
H2 = ParagraphStyle("h2", parent=_styles["Heading2"], fontSize=12,
                    spaceBefore=12, spaceAfter=4)
BODY = ParagraphStyle("b", parent=_styles["Normal"], fontSize=9.5, leading=13)
MONO = ParagraphStyle("m", parent=_styles["Normal"], fontName="Courier",
                      fontSize=8.5, leading=11)
LABEL = ParagraphStyle("l", parent=_styles["Normal"], fontSize=9,
                       textColor=colors.HexColor("#333333"))
SMALL = ParagraphStyle("sm", parent=_styles["Normal"], fontSize=8,
                       textColor=colors.HexColor("#666666"), leading=10)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _status(ok: bool) -> Paragraph:
    color = "#1a7f37" if ok else "#c62828"
    word = "VALID" if ok else "INVALID"
    return Paragraph(f'<font color="{color}"><b>{word}</b></font>', BODY)


def _qr(data: str, size: float = 34 * mm) -> Drawing:
    widget = QrCodeWidget(data)
    x1, y1, x2, y2 = widget.getBounds()
    drawing = Drawing(
        size, size,
        transform=[size / (x2 - x1), 0, 0, size / (y2 - y1), 0, 0],
    )
    drawing.add(widget)
    return drawing


def _kv_table(rows: list[tuple[str, object]]) -> Table:
    data = [
        [Paragraph(label, LABEL),
         value if not isinstance(value, str) else Paragraph(value, MONO)]
        for label, value in rows
    ]
    table = Table(data, colWidths=[42 * mm, 128 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def build_attribution_report(
    *,
    watermark_id: str,
    encrypted_file_id: str,
    document_hash: str,
    timestamp: datetime,
    zkp_valid: bool,
    signature_valid: bool,
    zkp_proof: str,
    signature: str | None,
    verify_url: str,
) -> bytes:
    confirmed = zkp_valid and signature_valid
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    event_time = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"SIH26237 Attribution Report - {watermark_id}",
        author="SIH26237 Backend",
    )

    outcome_color = "#1a7f37" if confirmed else "#c62828"
    outcome = (
        "Attribution to an authorized decryption event: CONFIRMED"
        if confirmed
        else "Attribution to an authorized decryption event: NOT CONFIRMED"
    )

    story = [
        Paragraph("Attribution Report", TITLE),
        Paragraph(f"Privacy-preserving provenance verification &middot; generated {generated}", SUB),
        Paragraph(f'<font color="{outcome_color}"><b>{outcome}</b></font>', _styles["Heading3"]),

        Paragraph("1. Leaked copy", H2),
        _kv_table([
            ("Watermark ID", watermark_id),
            ("Encrypted file ID", encrypted_file_id),
            ("Document hash (SHA-256)", document_hash),
            ("Decryption event time", event_time),
        ]),

        Paragraph("2. Verification results", H2),
        _kv_table([
            ("Zero-knowledge proof", _status(zkp_valid)),
            ("Ledger signature (ML-DSA-65)", _status(signature_valid)),
            ("Ledger backend", ledger_backend_label()),
        ]),

        Paragraph("3. Cryptographic evidence", H2),
        _kv_table([
            ("ZKP proof digest (SHA-256)", _sha256_hex(zkp_proof)),
            ("ZKP proof size", f"{len(zkp_proof)} bytes"),
            ("Signature digest (SHA-256)", _sha256_hex(signature) if signature else "none"),
        ]),
        Spacer(1, 4),
        Paragraph(
            "Anyone with access to the ledger record can recompute these digests "
            "and re-run both verifications independently.",
            SMALL,
        ),

        Paragraph("4. Ledger verification", H2),
        Table(
            [[
                _qr(verify_url),
                [
                    Paragraph("Scan to open the ledger record for this watermark.", BODY),
                    Spacer(1, 3),
                    Paragraph(verify_url, MONO),
                    Spacer(1, 3),
                    Paragraph("Access requires an authorized account.", SMALL),
                ],
            ]],
            colWidths=[40 * mm, 130 * mm],
            style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]),
        ),

        KeepTogether([
            Paragraph("5. Identity disclosure (court order required)", H2),
            Paragraph(COURT_ORDER_CLAUSE, BODY),
        ]),
    ]

    doc.build(story)
    return buffer.getvalue()