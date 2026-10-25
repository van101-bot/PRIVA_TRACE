"""
Fabric anchoring tests. No Fabric network is needed: Member 4's client is faked.

Run:  python -m pytest tests/api/test_fabric.py -v
"""

import json

import pytest


class FakeClient:
    """Same method names and error style as Member 4's FabricClient."""

    def __init__(self):
        self.chain = {}
        self.down = False

    def record_decryption(self, watermark_id, document_hash, timestamp, signature, zkp_proof):
        if self.down:
            raise RuntimeError("Fabric network is unavailable. Details: peer unreachable")
        if watermark_id in self.chain:
            raise RuntimeError(f"Fabric command failed: watermarkID {watermark_id} already exists")
        self.chain[watermark_id] = dict(watermark_id=watermark_id, document_hash=document_hash,
                                        timestamp=timestamp, signature=signature, zkp_proof=zkp_proof)
        return ""

    def verify(self, watermark_id, document_hash, timestamp, signature, zkp_proof):
        if self.down:
            raise RuntimeError("Fabric network is unavailable. Details: peer unreachable")
        local = dict(watermark_id=watermark_id, document_hash=document_hash,
                     timestamp=timestamp, signature=signature, zkp_proof=zkp_proof)
        chain = self.chain.get(watermark_id)
        return (chain is not None), (chain == local)


@pytest.fixture()
def fabric(client, monkeypatch):
    from app.api.fabric import get_client
    from main import app

    fake = FakeClient()
    monkeypatch.setenv("FABRIC_ENABLED", "1")
    app.dependency_overrides[get_client] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_client, None)


def test_status_reports_the_switch(client, new_user, monkeypatch):
    headers = new_user()
    monkeypatch.delenv("FABRIC_ENABLED", raising=False)
    assert client.get("/fabric/status", headers=headers).json() == {"enabled": False}
    monkeypatch.setenv("FABRIC_ENABLED", "1")
    assert client.get("/fabric/status", headers=headers).json() == {"enabled": True}


def test_disabled_integration_returns_503(client, scenario, monkeypatch):
    monkeypatch.delenv("FABRIC_ENABLED", raising=False)
    wid = scenario.result["watermark_id"]
    assert client.post("/fabric/anchor", headers=scenario.owner, json={"watermark_id": wid}).status_code == 503
    assert client.get(f"/fabric/verify/{wid}", headers=scenario.owner).status_code == 503


def test_anchor_and_verify_round_trip(client, scenario, fabric):
    wid = scenario.result["watermark_id"]

    r = client.post("/fabric/anchor", headers=scenario.owner, json={"watermark_id": wid})
    assert r.status_code == 200, r.text
    assert r.json() == {"watermark_id": wid, "anchored": True}

    r = client.get(f"/fabric/verify/{wid}", headers=scenario.owner)
    assert r.status_code == 200, r.text
    assert r.json() == {"watermark_id": wid, "on_chain": True, "matches_local": True}
    assert "alice" not in json.dumps(fabric.chain)


def test_anchoring_twice_gives_409(client, scenario, fabric):
    wid = scenario.result["watermark_id"]
    client.post("/fabric/anchor", headers=scenario.owner, json={"watermark_id": wid})
    again = client.post("/fabric/anchor", headers=scenario.owner, json={"watermark_id": wid})
    assert again.status_code == 409


def test_verify_before_anchoring_says_not_on_chain(client, scenario, fabric):
    wid = scenario.result["watermark_id"]
    r = client.get(f"/fabric/verify/{wid}", headers=scenario.owner)
    assert r.json()["on_chain"] is False and r.json()["matches_local"] is False


def test_other_user_cannot_anchor_or_verify(client, scenario, new_user, fabric):
    intruder = new_user()
    wid = scenario.result["watermark_id"]
    assert client.post("/fabric/anchor", headers=intruder, json={"watermark_id": wid}).status_code == 404
    assert client.get(f"/fabric/verify/{wid}", headers=intruder).status_code == 404
    assert fabric.chain == {}


def test_fabric_outage_gives_502_and_leaks_nothing(client, scenario, fabric):
    fabric.down = True
    wid = scenario.result["watermark_id"]
    r = client.post("/fabric/anchor", headers=scenario.owner, json={"watermark_id": wid})
    assert r.status_code == 502
    assert "peer unreachable" not in r.text and "Details" not in r.text


def test_tampered_local_record_is_not_anchored(client, scenario, fabric):
    from app.database.database import SessionLocal
    from app.models.decryption_record import DecryptionRecord

    wid = scenario.result["watermark_id"]
    with SessionLocal() as db:
        row = db.query(DecryptionRecord).filter(DecryptionRecord.watermark_id == wid).one()
        row.document_hash = "c" * 64
        db.commit()

    r = client.post("/fabric/anchor", headers=scenario.owner, json={"watermark_id": wid})
    assert r.status_code == 409
    assert fabric.chain == {}
