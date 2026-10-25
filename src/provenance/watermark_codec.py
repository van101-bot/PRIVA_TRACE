import base64
import json
from hashlib import sha256


DOMAIN = b"SIH26237-WATERMARK-CODEC-V1|"


def _canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def encode_watermark_payload(payload) -> bytes:
    """
    Convert WatermarkPayload into a deterministic authenticated
    byte representation suitable for the actual watermark layer.
    """

    data = {
        "version": payload.version,
        "watermark_id": payload.watermark_id,
        "document_id": payload.document_id,
        "document_hash": payload.document_hash,
        "recipient_commitment": payload.recipient_commitment,
        "session_id": payload.session_id,
        "nonce": payload.nonce,
    }

    canonical = _canonical_json(data)

    digest = sha256(
        DOMAIN + canonical
    ).digest()

    envelope = {
        "payload": base64.b64encode(canonical).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
    }

    return _canonical_json(envelope)


def decode_watermark_payload(data: bytes) -> dict:
    envelope = json.loads(data.decode("utf-8"))

    canonical = base64.b64decode(
        envelope["payload"]
    )

    expected = sha256(
        DOMAIN + canonical
    ).digest()

    actual = base64.b64decode(
        envelope["digest"]
    )

    if expected != actual:
        raise ValueError(
            "Watermark payload integrity check failed"
        )

    return json.loads(canonical.decode("utf-8"))