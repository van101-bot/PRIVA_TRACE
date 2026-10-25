"""
Fixtures for the API tests.

The environment variables are set at import time, before anything imports the
app, because the database engine is created when app.database.database loads.
Everything (database, keys, encrypted files) lives in a temporary folder, so
the real storage/ and the PostgreSQL database are never touched.
"""

import base64
import json
import os
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from make_sample_files import real_png_bytes

_TMP = Path(tempfile.mkdtemp(prefix="sih26237_tests_"))
os.environ["DATABASE_URL"] = "sqlite:///" + (_TMP / "test.db").as_posix()
os.environ["JWT_SECRET_KEY"] = "test-only-secret-" + "x" * 40
os.environ["RATE_LIMIT_DISABLED"] = "1"

PASSWORD = "Str0ng-Passw0rd!"
PNG = real_png_bytes()   # a real picture: the watermark module opens it with Pillow


@pytest.fixture(scope="session")
def client():
    import app.api.batch_decrypt as batch_mod
    import app.api.decrypt_watermarked as decrypt_mod
    import app.api.decryption as old_decrypt_mod
    import app.api.encryption as encrypt_mod
    import app.services.key_management as key_mod
    import app.services.ledger_signer as signer_mod

    storage = _TMP / "storage"
    encrypted = storage / "encrypted"
    metadata = storage / "metadata"
    sessions = storage / "keys" / "recipient_sessions"
    for folder in (encrypted, metadata, sessions):
        folder.mkdir(parents=True, exist_ok=True)

    mp = pytest.MonkeyPatch()
    for module in (encrypt_mod, old_decrypt_mod):
        mp.setattr(module, "ENCRYPTED_DIR", encrypted)
        mp.setattr(module, "METADATA_DIR", metadata)
        mp.setattr(module, "KEY_DIR", sessions)
    mp.setattr(batch_mod, "ENCRYPTED_DIR", encrypted)
    mp.setattr(batch_mod, "METADATA_DIR", metadata)
    mp.setattr(decrypt_mod, "METADATA_DIR", metadata)
    mp.setattr(key_mod, "KEY_DIR", storage / "keys")
    mp.setattr(key_mod, "KEY_FILE", storage / "keys" / "master.key")
    mp.setattr(signer_mod, "KEY_PATH", storage / "keys" / "ledger_signing.json")
    signer_mod._keys.cache_clear()

    from fastapi.testclient import TestClient

    from main import app

    yield TestClient(app)

    mp.undo()
    signer_mod._keys.cache_clear()


@pytest.fixture(autouse=True)
def _fresh_rate_limiter():
    from app.core.rate_limit import limiter

    limiter._hits.clear()
    yield
    limiter._hits.clear()


@pytest.fixture()
def new_user(client):
    def _make():
        username = "user_" + uuid.uuid4().hex[:10]
        r = client.post("/auth/register", json={"username": username, "password": PASSWORD})
        assert r.status_code in (200, 201), r.text
        r = client.post("/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    return _make


@pytest.fixture()
def make_recipients():
    from src.pqc.kem import MLKEM

    def _make(names):
        kem = MLKEM()
        public, private = [], {}
        for name in names:
            pair = kem.generate_keypair()
            public.append({
                "recipient_id": name,
                "public_key": base64.b64encode(pair.public_key).decode(),
            })
            private[name] = base64.b64encode(pair.private_key).decode()
        return public, private

    return _make


@pytest.fixture()
def encrypt_doc(client):
    def _encrypt(headers, public, filename="doc.png", content=PNG):
        r = client.post(
            "/encrypt",
            headers=headers,
            files={"file": (filename, content)},
            data={"recipients_json": json.dumps(public)},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["encrypted_file_id"]

    return _encrypt


@pytest.fixture()
def scenario(client, new_user, make_recipients, encrypt_doc):
    """An owner, a document for alice and bob, and alice's decryption already done."""
    owner = new_user()
    public, private = make_recipients(["alice", "bob"])
    file_id = encrypt_doc(owner, public)

    def decrypt_as(headers, recipient):
        return client.post(
            "/decrypt",
            headers=headers,
            json={
                "encrypted_file_id": file_id,
                "recipient_id": recipient,
                "private_key": private[recipient],
            },
        )

    first = decrypt_as(owner, "alice")
    assert first.status_code == 200, first.text
    return SimpleNamespace(
        owner=owner, file_id=file_id, private=private, public=public,
        decrypt_as=decrypt_as, result=first.json(),
    )