"""
ZKP helpers: turn a Schnorr attribution proof into text (for the database
and API responses) and verify it again later.

Convention used everywhere in the API:
  document_id       = encrypted_file_id
  provenance_digest = bytes of the document's SHA-256 hash
"""

from __future__ import annotations

import json

from src.zkp.attribution import (
    AttributionProof,
    AttributionProver,
    AttributionVerifier,
)
from src.zkp.schnorr import SchnorrProof


def provenance_digest_for(document_hash: str) -> bytes:
    return bytes.fromhex(document_hash)


def serialize_proof(proof: AttributionProof) -> str:
    return json.dumps(
        {
            "recipient_commitment": format(proof.recipient_commitment, "x"),
            "proof": {
                "commitment": format(proof.proof.commitment, "x"),
                "challenge": format(proof.proof.challenge, "x"),
                "response": format(proof.proof.response, "x"),
            },
            "document_binding": proof.document_binding.hex(),
        },
        separators=(",", ":"),
    )


def deserialize_proof(text: str) -> AttributionProof:
    data = json.loads(text)
    p = data["proof"]
    return AttributionProof(
        recipient_commitment=int(data["recipient_commitment"], 16),
        proof=SchnorrProof(
            commitment=int(p["commitment"], 16),
            challenge=int(p["challenge"], 16),
            response=int(p["response"], 16),
        ),
        document_binding=bytes.fromhex(data["document_binding"]),
    )


def create_zkp_proof(identity: str, document_id: str, document_hash: str) -> str:
    """Used at decrypt time. The identity is used inside and never stored."""
    credential = AttributionProver.create_credential(identity)
    proof = AttributionProver.create_proof(
        credential, document_id, provenance_digest_for(document_hash)
    )
    return serialize_proof(proof)


def verify_zkp_proof(zkp_proof: str, document_id: str, document_hash: str) -> bool:
    """Never raises: any malformed or tampered proof simply returns False."""
    try:
        proof = deserialize_proof(zkp_proof)
        return AttributionVerifier.verify(
            proof,
            document_id=document_id,
            provenance_digest=provenance_digest_for(document_hash),
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False