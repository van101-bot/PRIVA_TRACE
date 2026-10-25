"""
QKDEncryptedAPI - chooses the TLS setup for the API server.

Two modes:
  * qkd-psk       TLS 1.2 with a pre-shared key taken from QKD (Python 3.13+,
                  opt-in with QKD_TLS=1). Meant for service-to-service links.
                  Browsers, curl and Swagger UI cannot speak TLS-PSK.
  * classical-tls normal certificate-based TLS (the demo default and the
                  automatic fallback when QKD is unavailable).

QKD source (QKD_MODE):
  off        no QKD (default)
  simulated  random 256-bit keys, no hardware (demo only: no client has them)
  hardware   ETSI GS QKD 014 REST API of a Key Management Entity (KME);
             needs QKD_KME_URL and QKD_SLAVE_SAE_ID. UNTESTED without hardware.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import urllib.request
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CERT = PROJECT_ROOT / "certs" / "dev_cert.pem"
DEFAULT_KEY = PROJECT_ROOT / "certs" / "dev_key.pem"

PSK_CIPHER = "PSK-AES256-GCM-SHA384"
PSK_HINT = "sih26237-qkd"


class QKDTLSNotSupported(RuntimeError):
    """QKD-keyed TLS cannot be set up on this Python/OpenSSL."""


@dataclass(frozen=True)
class QKDStatus:
    mode: str        # off | simulated | hardware
    available: bool
    detail: str


@dataclass(frozen=True)
class TLSSetup:
    context: ssl.SSLContext
    mode: str        # qkd-psk | classical-tls
    reason: str      # why this mode was chosen


class QKDEncryptedAPI:
    def __init__(self, cert_file: str | Path | None = None, key_file: str | Path | None = None):
        self.cert_file = Path(cert_file or os.getenv("TLS_CERT_FILE") or DEFAULT_CERT)
        self.key_file = Path(key_file or os.getenv("TLS_KEY_FILE") or DEFAULT_KEY)

    # ---------- QKD availability ----------

    @staticmethod
    def psk_supported() -> bool:
        return hasattr(ssl.SSLContext, "set_psk_server_callback")

    def status(self) -> QKDStatus:
        mode = os.getenv("QKD_MODE", "off").strip().lower()

        if mode == "simulated":
            return QKDStatus("simulated", True, "Simulated QKD source (no hardware)")

        if mode == "hardware":
            if not os.getenv("QKD_KME_URL") or not os.getenv("QKD_SLAVE_SAE_ID"):
                return QKDStatus("hardware", False, "QKD_KME_URL / QKD_SLAVE_SAE_ID not set")
            try:
                self._kme_get(f"/api/v1/keys/{os.environ['QKD_SLAVE_SAE_ID']}/status", timeout=2.0)
                return QKDStatus("hardware", True, "KME reachable")
            except Exception as exc:
                return QKDStatus("hardware", False, f"KME not reachable ({type(exc).__name__})")

        return QKDStatus("off", False, "QKD_MODE is not set")

    def is_qkd_available(self) -> bool:
        return self.status().available

    # ---------- QKD key source ----------

    def _kme_get(self, path: str, timeout: float = 5.0) -> dict:
        base = os.environ["QKD_KME_URL"].rstrip("/")
        context = ssl.create_default_context(cafile=os.getenv("QKD_CA_CERT") or None)
        client_cert = os.getenv("QKD_CLIENT_CERT")
        if client_cert:
            context.load_cert_chain(client_cert, os.getenv("QKD_CLIENT_KEY") or None)
        with urllib.request.urlopen(base + path, context=context, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def get_qkd_key(self) -> tuple[str, bytes]:
        """Returns (key_id, 32-byte key)."""
        status = self.status()
        if not status.available:
            raise RuntimeError(f"QKD not available: {status.detail}")

        if status.mode == "simulated":
            return "sim-" + secrets.token_hex(8), secrets.token_bytes(32)

        sae = os.environ["QKD_SLAVE_SAE_ID"]
        data = self._kme_get(f"/api/v1/keys/{sae}/enc_keys?number=1&size=256")
        item = data["keys"][0]
        return item["key_ID"], base64.b64decode(item["key"])

    # ---------- TLS contexts ----------

    def setup_https_with_qkd(self, qkd_key: bytes) -> ssl.SSLContext:
        """TLS 1.2 PSK context whose pre-shared key is the QKD key."""
        if not self.psk_supported():
            raise QKDTLSNotSupported(
                "This Python has no TLS-PSK support (needs Python 3.13+)"
            )
        if len(qkd_key) < 16:
            raise ValueError("QKD key is too short")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(PSK_CIPHER)
        context.set_psk_server_callback(lambda identity: qkd_key, identity_hint=PSK_HINT)
        return context

    def fallback_to_classical_tls(self) -> ssl.SSLContext:
        """Normal certificate-based TLS (1.2 or newer)."""
        if not self.cert_file.is_file() or not self.key_file.is_file():
            raise FileNotFoundError(
                f"TLS certificate not found ({self.cert_file}). Run: python make_dev_cert.py"
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_file), str(self.key_file))
        return context

    def create_tls_context(self, prefer_qkd: bool | None = None) -> TLSSetup:
        """
        QKD-keyed TLS only when explicitly requested (QKD_TLS=1) AND QKD is
        available AND Python supports it. Anything else falls back to classical TLS.
        """
        if prefer_qkd is None:
            prefer_qkd = os.getenv("QKD_TLS") == "1"

        if not prefer_qkd:
            return TLSSetup(
                self.fallback_to_classical_tls(),
                "classical-tls",
                "QKD_TLS is not 1 (browsers and curl cannot use QKD-PSK TLS)",
            )

        status = self.status()
        if not status.available:
            return TLSSetup(
                self.fallback_to_classical_tls(), "classical-tls",
                f"QKD unavailable: {status.detail}",
            )

        try:
            key_id, key = self.get_qkd_key()
            return TLSSetup(
                self.setup_https_with_qkd(key), "qkd-psk",
                f"{status.mode} QKD key {key_id}",
            )
        except Exception as exc:
            return TLSSetup(
                self.fallback_to_classical_tls(), "classical-tls",
                f"QKD-PSK failed: {exc}",
            )