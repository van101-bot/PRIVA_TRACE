"""
API tests for the privacy-first backend.

Run:  python -m pytest tests/api/test_api.py -v
"""

import base64
import io
import json
import zipfile
from pathlib import Path

import pytest

from make_sample_files import real_pdf_bytes, real_png_bytes

PNG = real_png_bytes()          # a real picture (the watermark module opens it with Pillow)
UNKNOWN_ID = "DOESNOTEXIST123"


def _watermarked_bytes(result):
    return base64.b64decode(result["watermarked_file"])


def _watermark_ids_in_zip(client, headers, content):
    """Reads the watermark ID of every copy in a batch ZIP through the API itself."""
    ids = []
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for name in archive.namelist():
            if name.endswith(".json"):
                continue
            r = client.post("/extract-watermark", headers=headers,
                            files={"file": (Path(name).name, archive.read(name))})
            assert r.status_code == 200, f"{name}: {r.text}"
            ids.append(r.json()["watermark_id"])
    return ids


# ---------------------------------------------------------------- basics

def test_health(client):
    assert client.get("/health").status_code == 200


def test_request_id_header_is_set(client):
    assert len(client.get("/health").headers["x-request-id"]) == 32


def test_protected_route_needs_a_token(client):
    assert client.get("/access-log").status_code in (401, 403)


def test_login_with_wrong_password_is_rejected(client):
    username = "user_wrongpw"
    client.post("/auth/register", json={"username": username, "password": "Str0ng-Passw0rd!"})
    r = client.post("/auth/login", json={"username": username, "password": "not-the-password-1"})
    assert r.status_code == 401


def test_legacy_routes_are_gone(client, new_user):
    headers = new_user()
    assert client.post("/hybrid/decrypt/x", headers=headers).status_code == 404
    assert client.get("/batch/", headers=headers).status_code == 404
    assert client.get("/reports/", headers=headers).status_code == 404
    assert client.get("/attribution/", headers=headers).status_code == 404
    assert client.post("/watermark/extract", headers=headers).status_code == 404


# ---------------------------------------------------------------- decrypt + attribution loop

def test_decrypt_response_has_no_identity(scenario):
    assert set(scenario.result) == {"watermark_id", "zkp_proof", "timestamp", "watermarked_file"}
    assert "alice" not in json.dumps({k: v for k, v in scenario.result.items() if k != "watermarked_file"})


def test_full_attribution_loop(client, scenario):
    owner = scenario.owner
    wid = scenario.result["watermark_id"]
    leaked = _watermarked_bytes(scenario.result)

    # leaked file -> watermark_id and a confidence score (nothing else)
    r = client.post("/extract-watermark", headers=owner, files={"file": ("leak.png", leaked)})
    assert r.status_code == 200, r.text
    assert set(r.json()) == {"watermark_id", "confidence"}
    assert r.json()["watermark_id"] == wid
    assert 0 < r.json()["confidence"] <= 1

    # attribution without a name
    r = client.post("/attribute-with-zkp", headers=owner, json={"watermark_id": wid})
    assert r.status_code == 200, r.text
    assert r.json() == {"is_authorized": True, "zkp_verified": True}

    # signed ledger record
    r = client.get(f"/ledger/{wid}", headers=owner)
    assert r.status_code == 200, r.text
    assert set(r.json()) == {"watermark_id", "zkp_proof", "timestamp", "signature"}

    # provenance, by ID and from the leaked file
    r = client.get(f"/provenance/{wid}", headers=owner)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "confirmed"
    assert r.json()["zkp_verified"] is True and r.json()["signature_valid"] is True

    r = client.post("/provenance/trace", headers=owner, files={"file": ("leak.png", leaked)})
    assert r.status_code == 200, r.text
    assert r.json()["known"] is True and r.json()["status"] == "confirmed"

    # PDF report
    r = client.post("/generate-attribution-report", headers=owner, json={"watermark_id": wid})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/pdf")
    assert r.content.startswith(b"%PDF")


def test_file_without_watermark_is_not_attributed(client, scenario):
    r = client.post("/provenance/trace", headers=scenario.owner, files={"file": ("plain.png", PNG)})
    assert r.status_code in (404, 422) or (r.status_code == 200 and r.json()["known"] is False)


def test_each_decrypt_gets_its_own_watermark(scenario):
    again = scenario.decrypt_as(scenario.owner, "alice")
    assert again.status_code == 200
    assert again.json()["watermark_id"] != scenario.result["watermark_id"]


def test_pdf_round_trip(client, new_user, make_recipients, encrypt_doc):
    """PDF watermarking: skipped when the watermark module refuses PDF files."""
    owner = new_user()
    public, private = make_recipients(["alice"])
    file_id = encrypt_doc(owner, public, filename="doc.pdf", content=real_pdf_bytes())

    r = client.post("/decrypt", headers=owner, json={
        "encrypted_file_id": file_id, "recipient_id": "alice", "private_key": private["alice"]})
    if r.status_code == 415:
        pytest.skip("PDF watermarking is not enabled")
    assert r.status_code == 200, r.text

    wid = r.json()["watermark_id"]
    leaked = base64.b64decode(r.json()["watermarked_file"])
    assert leaked.startswith(b"%PDF")

    ex = client.post("/extract-watermark", headers=owner, files={"file": ("leak.pdf", leaked)})
    assert ex.status_code == 200, ex.text
    assert ex.json()["watermark_id"] == wid


# ---------------------------------------------------------------- ownership

def test_other_user_cannot_see_the_record(client, scenario, new_user):
    intruder = new_user()
    wid = scenario.result["watermark_id"]
    leaked = _watermarked_bytes(scenario.result)

    assert client.get(f"/ledger/{wid}", headers=intruder).status_code == 404
    assert client.get(f"/provenance/{wid}", headers=intruder).status_code == 404
    assert client.post("/attribute-with-zkp", headers=intruder, json={"watermark_id": wid}).status_code == 404
    assert client.post("/generate-attribution-report", headers=intruder, json={"watermark_id": wid}).status_code == 404

    r = client.post("/provenance/trace", headers=intruder, files={"file": ("leak.png", leaked)})
    # Robust marks are matched only against the caller's own ledger, so an
    # intruder gets 404 (no match) or known=false: either way, nothing leaks.
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert r.json()["known"] is False
        assert r.json()["encrypted_file_id"] is None and r.json()["document_hash"] is None
    assert wid not in r.text or r.status_code == 200


def test_other_user_cannot_decrypt_someone_elses_document(scenario, new_user):
    r = scenario.decrypt_as(new_user(), "alice")
    assert r.status_code in (403, 404)


def test_unknown_watermark_gives_404(client, new_user):
    headers = new_user()
    assert client.get(f"/ledger/{UNKNOWN_ID}", headers=headers).status_code == 404
    assert client.post("/attribute-with-zkp", headers=headers, json={"watermark_id": UNKNOWN_ID}).status_code == 404


# ---------------------------------------------------------------- tamper detection

def test_tampered_record_is_detected(client, scenario):
    from app.database.database import SessionLocal
    from app.models.decryption_record import DecryptionRecord

    wid = scenario.result["watermark_id"]
    with SessionLocal() as db:
        row = db.query(DecryptionRecord).filter(DecryptionRecord.watermark_id == wid).one()
        row.document_hash = "c" * 64
        db.commit()

    assert client.get(f"/ledger/{wid}", headers=scenario.owner).status_code == 409

    r = client.get(f"/provenance/{wid}", headers=scenario.owner)
    assert r.status_code == 200
    assert r.json()["status"] == "not_confirmed"

    r = client.post("/attribute-with-zkp", headers=scenario.owner, json={"watermark_id": wid})
    assert r.json() == {"is_authorized": False, "zkp_verified": False}


# ---------------------------------------------------------------- revocation

def test_revoked_recipient_is_blocked(client, scenario):
    owner = scenario.owner

    r = client.post("/keys/revoke", headers=owner, json={"recipient_id": "bob", "reason": "left project"})
    assert r.status_code == 201, r.text
    assert "bob" not in r.text

    again = client.post("/keys/revoke", headers=owner, json={"recipient_id": "bob", "reason": "left project"})
    assert again.status_code == 200
    assert again.json()["status"] == "already_revoked"

    listing = client.get("/keys/revoked", headers=owner)
    assert listing.status_code == 200 and len(listing.json()) == 1
    assert "bob" not in listing.text

    assert scenario.decrypt_as(owner, "bob").status_code == 403
    assert scenario.decrypt_as(owner, "alice").status_code == 200


def test_revocation_only_applies_to_the_owner_who_made_it(client, scenario, new_user):
    other_owner = new_user()
    client.post("/keys/revoke", headers=other_owner, json={"recipient_id": "bob", "reason": "unrelated"})
    assert scenario.decrypt_as(scenario.owner, "bob").status_code == 200


def test_generate_key_returns_a_usable_key_pair(client, new_user):
    r = client.post("/keys/generate", headers=new_user(), json={"recipient_id": "carol"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["algorithm"] == "ML-KEM-768"
    assert len(base64.b64decode(body["public_key"])) > 1000
    assert len(base64.b64decode(body["private_key"])) > 1000


# ---------------------------------------------------------------- batch

def _batch_body(file_id, public, private, wrong_key_for=None):
    names = [r["recipient_id"] for r in public]
    items = []
    for name in names:
        key = private[name]
        if name == wrong_key_for:
            key = private[next(n for n in names if n != name)]
        items.append({"recipient_id": name, "private_key": key})
    return {"encrypted_file_id": file_id, "recipients": items}


def test_batch_decrypt_gives_a_distinct_watermark_per_recipient(client, new_user, make_recipients, encrypt_doc):
    owner = new_user()
    public, private = make_recipients([f"user{n}" for n in range(1, 4)])
    file_id = encrypt_doc(owner, public)

    r = client.post("/batch-decrypt", headers=owner, json=_batch_body(file_id, public, private))
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    assert (r.headers["x-batch-requested"], r.headers["x-batch-succeeded"], r.headers["x-batch-failed"]) == ("3", "3", "0")

    with zipfile.ZipFile(io.BytesIO(r.content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert len(archive.namelist()) == 4          # 3 copies + manifest
    assert manifest["succeeded"] == 3
    assert "watermark" not in json.dumps(manifest)   # manifest never links recipient to watermark

    ids = _watermark_ids_in_zip(client, owner, r.content)
    assert len(ids) == 3 and len(set(ids)) == 3


def test_batch_reports_a_failed_recipient_and_keeps_the_rest(client, new_user, make_recipients, encrypt_doc):
    from app.database.database import SessionLocal
    from app.models.decryption_record import DecryptionRecord

    owner = new_user()
    public, private = make_recipients([f"user{n}" for n in range(1, 4)])
    file_id = encrypt_doc(owner, public)

    r = client.post("/batch-decrypt", headers=owner,
                    json=_batch_body(file_id, public, private, wrong_key_for="user3"))
    assert r.status_code == 200, r.text
    assert (r.headers["x-batch-succeeded"], r.headers["x-batch-failed"]) == ("2", "1")

    with zipfile.ZipFile(io.BytesIO(r.content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert [f["recipient_id"] for f in manifest["failures"]] == ["user3"]

    with SessionLocal() as db:
        saved = db.query(DecryptionRecord).filter(DecryptionRecord.encrypted_file_id == file_id).count()
    assert saved == 2                                # only successful copies are recorded


def test_batch_skips_revoked_recipients(client, new_user, make_recipients, encrypt_doc):
    owner = new_user()
    public, private = make_recipients([f"user{n}" for n in range(1, 4)])
    file_id = encrypt_doc(owner, public)
    client.post("/keys/revoke", headers=owner, json={"recipient_id": "user2", "reason": "left"})

    r = client.post("/batch-decrypt", headers=owner, json=_batch_body(file_id, public, private))
    assert r.status_code == 200, r.text
    assert (r.headers["x-batch-succeeded"], r.headers["x-batch-failed"]) == ("2", "1")
    with zipfile.ZipFile(io.BytesIO(r.content)) as archive:
        failure = json.loads(archive.read("manifest.json"))["failures"][0]
    assert failure["recipient_id"] == "user2" and "revoked" in failure["error"]


def test_batch_rejects_duplicate_recipient_ids(client, new_user, make_recipients, encrypt_doc):
    owner = new_user()
    public, private = make_recipients(["a1", "b1"])
    file_id = encrypt_doc(owner, public)
    body = _batch_body(file_id, public, private)
    body["recipients"].append(dict(body["recipients"][0]))
    assert client.post("/batch-decrypt", headers=owner, json=body).status_code == 422


def test_batch_needs_document_ownership(client, new_user, make_recipients, encrypt_doc):
    owner, stranger = new_user(), new_user()
    public, private = make_recipients(["a1", "b1"])
    file_id = encrypt_doc(owner, public)
    r = client.post("/batch-decrypt", headers=stranger, json=_batch_body(file_id, public, private))
    assert r.status_code == 403


# ---------------------------------------------------------------- never release an unmarked copy

def test_unsupported_format_is_refused_and_nothing_is_recorded(client, new_user, make_recipients):
    from app.database.database import SessionLocal
    from app.models.decryption_record import DecryptionRecord

    owner = new_user()
    public, private = make_recipients(["alice"])
    r = client.post("/encrypt", headers=owner, files={"file": ("notes.txt", b"plain text file")},
                    data={"recipients_json": json.dumps(public)})
    if r.status_code not in (200, 201):
        pytest.skip("/encrypt does not accept .txt files")
    file_id = r.json()["encrypted_file_id"]

    r = client.post("/decrypt", headers=owner, json={
        "encrypted_file_id": file_id, "recipient_id": "alice", "private_key": private["alice"]})
    assert r.status_code == 415
    assert "watermarked_file" not in r.text

    with SessionLocal() as db:
        assert db.query(DecryptionRecord).filter(DecryptionRecord.encrypted_file_id == file_id).count() == 0


# ---------------------------------------------------------------- errors, audit, rate limit

def test_validation_error_does_not_echo_the_input(client, new_user):
    r = client.post("/decrypt", headers=new_user(), json={"encrypted_file_id": "x", "private_key": "SECRET123"})
    assert r.status_code == 422
    assert "SECRET123" not in r.text
    assert set(r.json()) == {"detail", "request_id"}


def test_audit_log_records_failed_and_successful_requests(client, scenario):
    client.get(f"/ledger/{UNKNOWN_ID}", headers=scenario.owner)

    r = client.get("/access-log?limit=50", headers=scenario.owner)
    assert r.status_code == 200
    rows = r.json()

    missing = [x for x in rows if x["path"] == f"/ledger/{UNKNOWN_ID}"]
    assert missing and missing[0]["status_code"] == 404 and missing[0]["outcome"] == "rejected"

    decrypts = [x for x in rows if x["path"] == "/decrypt"]
    assert decrypts and decrypts[0]["resource"] == scenario.file_id and decrypts[0]["outcome"] == "success"

    assert "private_key" not in r.text and "alice" not in r.text


def test_access_log_only_shows_your_own_activity(client, scenario, new_user):
    other = new_user()
    client.get(f"/ledger/{UNKNOWN_ID}", headers=other)
    rows = client.get("/access-log?limit=50", headers=scenario.owner).json()
    assert all(x["path"] != f"/ledger/{UNKNOWN_ID}" for x in rows)


def test_rate_limit_returns_429_with_retry_after(client, monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_DISABLED")
    codes, last = [], None
    for _ in range(12):
        last = client.post("/auth/login", json={"username": "nobody_here", "password": "wrong-password-123"})
        codes.append(last.status_code)

    assert 429 in codes
    assert codes[0] != 429                      # the first attempts are not blocked
    assert int(last.headers["retry-after"]) >= 1