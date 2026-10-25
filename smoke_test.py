#!/usr/bin/env python3
"""
End-to-end smoke test of the integrated SIH26237 system (backend must be running).

Exercises exactly the calls the Electron frontend's api.ts makes, in the same order:
  register/login -> keys/generate -> encrypt -> decrypt (watermark + ZKP + signed record)
  -> provenance/trace (leak investigation) -> attribute-with-zkp -> ledger proof
  -> ledger-chain append + verify (local hash chain)  -> fabric status (optional)

Usage:
    pip install requests reportlab
    python smoke_test.py                                  # http://127.0.0.1:8001
    python smoke_test.py --base http://127.0.0.1:8001 --user KKK --password "a-12-char-password"
Exit code 0 = everything passed.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import sys
import time

import requests

GREEN, RED, END = "\033[92m", "\033[91m", "\033[0m"
failures: list[str] = []


def step(name: str, ok: bool, detail: str = "") -> None:
    print(f"{GREEN if ok else RED}{'PASS' if ok else 'FAIL'}{END}  {name}" + (f"  - {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def make_pdf() -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFont("Helvetica", 14)
    c.drawString(72, 780, "SIH26237 smoke-test document")
    for i in range(12):
        c.drawString(72, 740 - i * 22, f"Confidential line {i + 1}: the quick brown fox jumps over the lazy dog.")
    c.save()
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8001")
    ap.add_argument("--user", default="smoketest_user")
    ap.add_argument("--password", default="Smoke-Test-Passw0rd!")  # backend requires >= 12 chars
    a = ap.parse_args()
    base = a.base.rstrip("/")
    s = requests.Session()

    # ---- health -----------------------------------------------------------------------------
    try:
        r = s.get(base + "/health", timeout=10)
    except requests.RequestException as e:
        print(f"{RED}Backend not reachable at {base}: {e}{END}")
        return 2
    step("GET /health", r.ok and r.json().get("status") == "ok")

    # ---- auth -------------------------------------------------------------------------------
    r = s.post(base + "/auth/register", json={"username": a.user, "password": a.password}, timeout=20)
    step("POST /auth/register (201, or already exists)", r.status_code in (201, 400, 409), str(r.status_code))
    r = s.post(base + "/auth/login", json={"username": a.user, "password": a.password}, timeout=20)
    step("POST /auth/login", r.ok and "access_token" in r.json(), str(r.status_code))
    if not r.ok:
        return 1
    s.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    r = s.get(base + "/qkd/status", timeout=20)
    step("GET /qkd/status", r.ok, r.text[:80])

    # ---- keys + encrypt ---------------------------------------------------------------------
    rid = f"recipient-{int(time.time())}"
    r = s.post(base + "/keys/generate", json={"recipient_id": rid}, timeout=60)
    ok = r.status_code == 201 and {"public_key", "private_key"} <= set(r.json())
    step("POST /keys/generate (ML-KEM key pair)", ok, str(r.status_code))
    if not ok:
        return 1
    keys = r.json()

    pdf = make_pdf()
    r = s.post(
        base + "/encrypt",
        files={"file": ("smoke.pdf", pdf, "application/pdf")},
        data={"recipients_json": json.dumps([{"recipient_id": rid, "public_key": keys["public_key"]}])},
        timeout=120,
    )
    ok = r.ok and "encrypted_file_id" in r.json()
    step("POST /encrypt (ML-KEM-768 + QKD)", ok, str(r.status_code) if not ok else r.json()["status"])
    if not ok:
        print(r.text[:400])
        return 1
    enc = r.json()

    # ---- decrypt: watermark + ZKP + signed ledger record ------------------------------------
    r = s.post(
        base + "/decrypt",
        json={"encrypted_file_id": enc["encrypted_file_id"], "recipient_id": rid, "private_key": keys["private_key"]},
        timeout=180,
    )
    ok = r.ok and {"watermark_id", "zkp_proof", "watermarked_file"} <= set(r.json())
    step("POST /decrypt (watermark + ZKP + ML-DSA record)", ok, str(r.status_code) if not ok else "")
    if not ok:
        print(r.text[:400])
        return 1
    dec = r.json()
    wm = dec["watermark_id"]
    leaked = base64.b64decode(dec["watermarked_file"])
    step("watermarked PDF returned and differs from original", leaked[:4] == b"%PDF" and leaked != pdf, f"{len(leaked)} bytes")
    step("response leaks no recipient id", rid not in r.text)

    # ---- investigation ----------------------------------------------------------------------
    r = s.post(base + "/provenance/trace", files={"file": ("leaked.pdf", leaked, "application/pdf")}, timeout=180)
    step("POST /provenance/trace (leak -> watermark -> proof -> ledger)", r.ok, str(r.status_code))
    if r.ok:
        t = r.json()
        step("trace recovers the same watermark_id", json.dumps(t).find(wm) != -1)
        step("trace response contains no recipient id", rid not in json.dumps(t))

    r = s.post(base + "/attribute-with-zkp", json={"watermark_id": wm}, timeout=60)
    ok = r.ok and r.json().get("is_authorized") is True and r.json().get("zkp_verified") is True
    step("POST /attribute-with-zkp (authorized, proof verified, no name)", ok, r.text[:120] if not ok else "")

    r = s.get(f"{base}/ledger/{wm}", timeout=60)
    step("GET /ledger/{watermark_id} (signed record intact)", r.ok and "signature" in r.json(), str(r.status_code))

    r = s.get(f"{base}/provenance/{wm}", timeout=60)
    step("GET /provenance/{watermark_id}", r.ok, str(r.status_code))

    # ---- local hash-chain ledger (new) ------------------------------------------------------
    r = s.post(base + "/ledger-chain/append", json={"watermark_id": wm}, timeout=60)
    ok = r.status_code == 201 and r.json().get("status") == "recorded"
    step("POST /ledger-chain/append", ok, r.text[:120])
    r = s.get(base + "/ledger-chain/verify", timeout=60)
    ok = r.ok and r.json().get("valid") is True
    step("GET /ledger-chain/verify (chain valid)", ok, r.text[:160])

    # ---- dashboard feed + fabric (optional) -------------------------------------------------
    r = s.get(base + "/access-log?limit=5", timeout=30)
    step("GET /access-log (frontend ledger list)", r.ok and isinstance(r.json(), list))

    r = s.get(base + "/fabric/status", timeout=30)
    print(f"INFO  /fabric/status -> {r.status_code} {r.text[:100]}  (503 = FABRIC_ENABLED not set; that is fine)")

    # ---- CORS preflight the Electron renderer needs -----------------------------------------
    r = requests.options(
        base + "/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
        timeout=10,
    )
    step("CORS allows the Vite dev origin", r.headers.get("access-control-allow-origin") in ("http://localhost:5173", "*"))

    print()
    if failures:
        print(f"{RED}{len(failures)} check(s) failed:{END} " + "; ".join(failures))
        return 1
    print(f"{GREEN}All checks passed - backend, watermarking, ZKP, ledger and hash chain work together.{END}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
