from __future__ import annotations

import io
import struct
import zipfile
import zlib

WATERMARK_KEY = "SIH26237-WATERMARK"


def _chunk(kind: bytes, data: bytes) -> bytes:
    raw = kind + data
    return (
        struct.pack(">I", len(data))
        + raw
        + struct.pack(">I", zlib.crc32(raw) & 0xFFFFFFFF)
    )


def embed_image(content: bytes, extension: str, payload: bytes) -> bytes:
    ext = extension.lower()

    if ext == ".png":
        signature = b"\x89PNG\r\n\x1a\n"
        if not content.startswith(signature):
            raise ValueError("invalid PNG")
        text = WATERMARK_KEY.encode() + b"\x00" + payload
        marker = _chunk(b"tEXt", text)
        return content[:8] + marker + content[8:]

    if ext in {".jpg", ".jpeg"}:
        if not content.startswith(b"\xff\xd8"):
            raise ValueError("invalid JPEG")
        data = WATERMARK_KEY.encode() + b"\x00" + payload
        if len(data) > 65533:
            raise ValueError("watermark payload too large")
        return (
            b"\xff\xd8\xff\xfe"
            + struct.pack(">H", len(data) + 2)
            + data
            + content[2:]
        )

    raise ValueError("image watermarking supports PNG and JPEG")


def extract_image(content: bytes, extension: str) -> bytes:
    ext = extension.lower()

    if ext == ".png":
        pos = 8
        while pos + 12 <= len(content):
            length = struct.unpack(">I", content[pos:pos + 4])[0]
            kind = content[pos + 4:pos + 8]
            data = content[pos + 8:pos + 8 + length]
            if kind == b"tEXt" and data.startswith(WATERMARK_KEY.encode() + b"\x00"):
                return data.split(b"\x00", 1)[1]
            pos += 12 + length
        raise ValueError("watermark not found")

    if ext in {".jpg", ".jpeg"}:
        pos = 2
        while pos + 4 <= len(content) and content[pos] == 0xFF:
            marker = content[pos + 1]
            if marker == 0xDA:
                break
            if marker in (0xD8, 0xD9):
                pos += 2
                continue
            length = struct.unpack(">H", content[pos + 2:pos + 4])[0]
            data = content[pos + 4:pos + 2 + length]
            if marker == 0xFE and data.startswith(WATERMARK_KEY.encode() + b"\x00"):
                return data.split(b"\x00", 1)[1]
            pos += 2 + length
        raise ValueError("watermark not found")

    raise ValueError("image watermarking supports PNG and JPEG")


def embed_docx(content: bytes, payload: bytes) -> bytes:
    source = io.BytesIO(content)
    output = io.BytesIO()
    with zipfile.ZipFile(source, "r") as zin, zipfile.ZipFile(output, "w") as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        zout.writestr("customXml/sih26237-watermark.json", payload)
    return output.getvalue()


def extract_docx(content: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
        return archive.read("customXml/sih26237-watermark.json")


def embed(content: bytes, extension: str, payload: bytes) -> bytes:
    ext = extension.lower()
    if ext in {".png", ".jpg", ".jpeg"}:
        return embed_image(content, ext, payload)
    if ext == ".docx":
        return embed_docx(content, payload)
    raise ValueError("supported embedded formats: PNG, JPEG, DOCX")


def extract(content: bytes, extension: str) -> bytes:
    ext = extension.lower()
    if ext in {".png", ".jpg", ".jpeg"}:
        return extract_image(content, ext)
    if ext == ".docx":
        return extract_docx(content)
    raise ValueError("supported embedded formats: PNG, JPEG, DOCX")