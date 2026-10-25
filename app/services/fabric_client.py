"""Fabric CLI client for the SIH26237 provenance chaincode.

Runs peer CLI inside WSL via stdin (bash -s), with a 60-second command timeout.
Configuration is supplied through environment variables; see README.md.
"""

import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional


WATERMARK_RE = re.compile(r"^[A-Za-z0-9_\-=]{8,128}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class FabricClient:
    def __init__(self):
        self.network_dir = os.getenv(
            "FABRIC_NETWORK_DIR", "/mnt/c/fabric/fabric-samples/test-network"
        )
        self.fabric_cfg_path = os.getenv(
            "FABRIC_CFG_PATH", "/mnt/c/fabric/fabric-samples/config"
        )
        self.fabric_bin_dir = os.getenv(
            "FABRIC_BIN_DIR", "/home/geetanjali_pandey263639/fabric-bin/bin"
        )
        self.wsl_distro = os.getenv("FABRIC_WSL_DISTRO", "Ubuntu")
        self.channel = os.getenv("FABRIC_CHANNEL", "mychannel")
        self.chaincode = os.getenv("FABRIC_CHAINCODE", "provenance")
        self.timeout_seconds = 60

        # Avoid shell injection through configuration values too.
        for name, value in {
            "FABRIC_NETWORK_DIR": self.network_dir,
            "FABRIC_CFG_PATH": self.fabric_cfg_path,
            "FABRIC_BIN_DIR": self.fabric_bin_dir,
        }.items():
            if not value or "\x00" in value:
                raise ValueError(f"{name} must be a non-empty path")
        for name, value in {
            "FABRIC_WSL_DISTRO": self.wsl_distro,
            "FABRIC_CHANNEL": self.channel,
            "FABRIC_CHAINCODE": self.chaincode,
        }.items():
            if not value or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                raise ValueError(f"Invalid {name}: use letters, digits, dot, underscore or hyphen")

    @staticmethod
    def _quote(value: str) -> str:
        return shlex.quote(str(value))

    @staticmethod
    def _validate_watermark(watermark_id: str) -> None:
        if not isinstance(watermark_id, str) or not WATERMARK_RE.fullmatch(watermark_id):
            raise ValueError(
                "watermark_id must be 8-128 characters using only letters, digits, _, - or ="
            )

    @staticmethod
    def _validate_hash(document_hash: str) -> None:
        if not isinstance(document_hash, str) or not HASH_RE.fullmatch(document_hash):
            raise ValueError("document_hash must contain exactly 64 hexadecimal characters")

    def _run_peer(self, command: str) -> str:
        """Run a pre-quoted peer command in WSL; user values must be quoted by callers."""
        network_dir = self._quote(self.network_dir)
        cfg_path = self._quote(self.fabric_cfg_path)
        bin_dir = self._quote(self.fabric_bin_dir)
        script = "\n".join([
            "set -e",
            f"cd {network_dir} || {{ echo 'FABRIC_NETWORK_UNAVAILABLE: cannot access network directory' >&2; exit 20; }}",
            f"export FABRIC_CFG_PATH={cfg_path}",
            f"export PATH={bin_dir}:$PATH",
            "if [ ! -x \"$PATH/peer\" ] && [ ! -x " + self._quote(self.fabric_bin_dir.rstrip("/") + "/peer") + " ]; then echo 'FABRIC_PEER_NOT_FOUND: peer binary is missing' >&2; exit 21; fi",
            "if [ ! -f scripts/envVar.sh ]; then echo 'FABRIC_NETWORK_UNAVAILABLE: scripts/envVar.sh not found' >&2; exit 22; fi",
            "source scripts/envVar.sh",
            "setGlobals 1",
            # Re-assert paths after envVar.sh, which may adjust configuration.
            f"export FABRIC_CFG_PATH={cfg_path}",
            f"export PATH={bin_dir}:$PATH",
            command,
        ])
        try:
            result = subprocess.run(
                ["wsl", "-d", self.wsl_distro, "bash", "-s"],
                # bytes, not text: text mode turns "\n" into "\r\n" on Windows and breaks bash
                input=script.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Fabric command timed out after {self.timeout_seconds}s. Check that Docker Desktop, the Fabric network and the orderer/peers are running."
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError("WSL executable was not found. Install/enable WSL and check the Windows PATH.") from exc

        stdout = (result.stdout or b"").decode("utf-8", errors="replace").replace("\x00", "").strip()
        stderr = (result.stderr or b"").decode("utf-8", errors="replace").replace("\x00", "").strip()
        if result.returncode != 0:
            detail = stderr or stdout or f"process exited with code {result.returncode}"
            if "FABRIC_NETWORK_UNAVAILABLE" in detail or "connection refused" in detail.lower() or "failed to connect" in detail.lower():
                raise RuntimeError("Fabric network is unavailable. Start the test network and confirm the orderer and peers are healthy. Details: " + detail)
            raise RuntimeError("Fabric command failed: " + detail)
        return stdout

    def _payload(self, function_name: str, args: list[str]) -> str:
        return json.dumps({"function": function_name, "Args": args}, separators=(",", ":"))

    @staticmethod
    def _decode_output(output: str) -> Any:
        # The peer CLI prints noise before the JSON (e.g. "Using organization 1" from
        # setGlobals, wrapped in ANSI colour codes). Strip it, then parse.
        clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
        starts = [i for i in (clean.find("{"), clean.find("[")) if i != -1]
        candidates = [clean[min(starts):]] if starts else []
        lines = [ln for ln in clean.splitlines() if ln.strip()]
        if lines:
            candidates.append(lines[-1])
        candidates.append(clean)
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
        return output

    def _invoke(self, function_name: str, args: list[str]) -> str:
        payload = self._payload(function_name, args)
        peer = self._quote(self.fabric_bin_dir.rstrip("/") + "/peer")
        command = " ".join([
            peer, "chaincode invoke",
            "-o", self._quote("localhost:7050"),
            "--ordererTLSHostnameOverride", self._quote("orderer.example.com"),
            "--tls", "--cafile", '"$ORDERER_CA"',
            "-C", self._quote(self.channel), "-n", self._quote(self.chaincode),
            "--peerAddresses", self._quote("localhost:7051"),
            "--tlsRootCertFiles", '"$PEER0_ORG1_CA"',
            "--peerAddresses", self._quote("localhost:9051"),
            "--tlsRootCertFiles", '"$PEER0_ORG2_CA"',
            "--waitForEvent",
            "-c", self._quote(payload),
        ])
        return self._run_peer(command)

    def _query(self, function_name: str, args: list[str]) -> str:
        payload = self._payload(function_name, args)
        peer = self._quote(self.fabric_bin_dir.rstrip("/") + "/peer")
        command = " ".join([
            peer, "chaincode query", "-C", self._quote(self.channel),
            "-n", self._quote(self.chaincode), "-c", self._quote(payload),
        ])
        return self._run_peer(command)

    def record_decryption(
        self,
        watermark_id: str,
        document_hash: str,
        timestamp: str,
        signature: str,
        zkp_proof: str,
    ) -> str:
        """Store a privacy-preserving record without recipient identity fields."""
        self._validate_watermark(watermark_id)
        self._validate_hash(document_hash)
        if not timestamp:
            raise ValueError("timestamp is required")
        if not signature:
            raise ValueError("signature is required")
        if not zkp_proof:
            raise ValueError("zkp_proof is required when no recipient identity is stored")
        record = {
            "watermarkID": watermark_id,
            "documentHash": document_hash,
            "timestamp": timestamp,
            "dilithiumSig": signature,
            "zkpProof": zkp_proof,
        }
        return self._invoke("RecordDecryption", [json.dumps(record, separators=(",", ":"))])

    def query_by_watermark(self, watermark_id: str) -> Optional[dict[str, Any]]:
        self._validate_watermark(watermark_id)
        try:
            return self._decode_output(self._query("QueryByWatermark", [watermark_id]))
        except RuntimeError as exc:
            message = str(exc).lower()
            if "no decryption record found" in message or "watermark record not found" in message:
                return None
            raise

    def verify(
        self,
        watermark_id: str,
        document_hash: str,
        timestamp: str,
        signature: str,
        zkp_proof: str,
    ) -> tuple[bool, bool]:
        """Return (on_chain, matches_local). This compares fields; it does not verify cryptography."""
        self._validate_watermark(watermark_id)
        self._validate_hash(document_hash)
        record = self.query_by_watermark(watermark_id)
        if record is None:
            return (False, False)
        if isinstance(record, str):
            try:
                record = json.loads(record)
            except json.JSONDecodeError:
                return (True, False)
        on_chain = True
        matches_local = (
            record.get("watermarkID") == watermark_id
            and record.get("documentHash") == document_hash
            and record.get("timestamp") == timestamp
            and record.get("dilithiumSig") == signature
            and record.get("zkpProof") == zkp_proof
        )
        return (on_chain, matches_local)

    def record_key_revocation(
        self,
        recipient_id: str = "",
        key_id: str = "",
        reason: str = "",
        timestamp: Optional[str] = None,
        recipient_id_hash: str = "",
    ) -> str:
        if not key_id:
            raise ValueError("key_id is required")
        if not recipient_id and not recipient_id_hash:
            raise ValueError("recipient_id or recipient_id_hash is required")
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        revocation = {
            "recipientID": recipient_id,
            "recipientIDHash": recipient_id_hash,
            "keyID": key_id,
            "reason": reason,
            "timestamp": timestamp,
            "revoked": True,
        }
        return self._invoke("RecordKeyRevocation", [json.dumps(revocation, separators=(",", ":"))])

    def query_key_revocation(self, recipient_id_or_hash: str) -> Any:
        if not recipient_id_or_hash:
            raise ValueError("recipient_id_or_hash is required")
        try:
            return self._decode_output(self._query("QueryKeyRevocation", [recipient_id_or_hash]))
        except RuntimeError as exc:
            if "no revocation record found" in str(exc).lower():
                return None
            raise

    def check_revocation_status(self, recipient_id_or_hash: str) -> Any:
        return self.query_key_revocation(recipient_id_or_hash)

    def get_decryption_history(self, document_hash: str) -> Any:
        self._validate_hash(document_hash)
        return self._decode_output(self._query("GetDecryptionHistory", [document_hash]))

    def query_recent_decryptions(self, limit: int = 50) -> Any:
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        return self._decode_output(self._query("GetRecentDecryptions", [str(limit)]))

    def export_ledger(self) -> Any:
        return self.query_recent_decryptions(limit=1000)
