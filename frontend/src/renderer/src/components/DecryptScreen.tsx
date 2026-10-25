import { useState } from "react";
import {
  decryptDocument,
  getLastRecipient,
  getProvenance,
  saveBase64File,
} from "../services/api";

type Props = {
  documentId?: string | null;
  encryptedFileId?: string | null;
  fileName?: string | null;
  onDecrypted?: (watermarkId: string) => void;
};

type Flag = boolean | null;

function Status({ ok, yes, no }: { ok: Flag; yes: string; no: string }) {
  if (ok === null) {
    return <span style={{ opacity: 0.6 }}>● PENDING</span>;
  }
  if (ok) {
    return <span className="status-ok">● {yes}</span>;
  }
  return <span style={{ color: "#dc2626", fontWeight: 600 }}>● {no}</span>;
}

export default function DecryptScreen({ documentId, encryptedFileId, fileName, onDecrypted }: Props) {
  const [fileId, setFileId] = useState(encryptedFileId ?? documentId ?? "");
  const [recipientId, setRecipientId] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [watermarkId, setWatermarkId] = useState<string | null>(null);
  const [timestamp, setTimestamp] = useState<string | null>(null);
  const [fileBase64, setFileBase64] = useState<string | null>(null);
  const [decrypted, setDecrypted] = useState<Flag>(null);
  const [zkpOk, setZkpOk] = useState<Flag>(null);
  const [ledgerOk, setLedgerOk] = useState<Flag>(null);

  const useDemoRecipient = () => {
    const demo = getLastRecipient();
    if (!demo) {
      setError("No demo recipient yet. Encrypt a document on the Dashboard first.");
      return;
    }
    setError(null);
    setRecipientId(demo.recipient_id);
    setPrivateKey(demo.private_key);
  };

  const runDecrypt = async () => {
    setBusy(true);
    setError(null);
    setWatermarkId(null);
    setTimestamp(null);
    setFileBase64(null);
    setDecrypted(null);
    setZkpOk(null);
    setLedgerOk(null);

    try {
      const result = await decryptDocument(
        fileId.trim(),
        recipientId.trim(),
        privateKey.trim()
      );
      setWatermarkId(result.watermark_id);
      if (onDecrypted) {
        onDecrypted(result.watermark_id);
      }
      setTimestamp(result.timestamp);
      setFileBase64(result.watermarked_file);
      setDecrypted(true);

      try {
        const proof = await getProvenance(result.watermark_id);
        setZkpOk(proof.zkp_verified ?? false);
        setLedgerOk(proof.status === "confirmed" && proof.signature_valid === true);
      } catch {
        setZkpOk(false);
        setLedgerOk(false);
      }
    } catch (e) {
      setDecrypted(false);
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const download = () => {
    if (!fileBase64 || !watermarkId) {
      return;
    }
    saveBase64File(fileBase64, "watermarked_" + (fileName ?? "document-" + watermarkId.slice(0, 8)));
  };

  return (
    <section className="content-card large-card">
      <div className="card-title">
        <div>
          <h2>Secure Document Decryption</h2>
          <p>Verify authorization before decrypting a protected document.</p>
        </div>

        <span className={decrypted === false ? "badge badge-warning" : "badge badge-success"}>
          {decrypted === null ? "READY" : decrypted ? "AUTHORIZED" : "DENIED"}
        </span>
      </div>

      <div className="decrypt-grid">
        <div className="form-section">
          <label>Document / Encryption ID</label>
          <input
            className="text-input"
            placeholder="Enter document ID"
            value={fileId}
            onChange={(e) => setFileId(e.target.value)}
          />

          <label>Recipient ID</label>
          <input
            className="text-input"
            placeholder="Enter recipient ID"
            value={recipientId}
            onChange={(e) => setRecipientId(e.target.value)}
          />

          <label>Authorization Credential (recipient private key)</label>
          <input
            className="text-input"
            placeholder="Enter credential"
            type="password"
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
          />

          <button className="secondary-button" onClick={useDemoRecipient}>
            Use demo recipient
          </button>

          <button
            className="primary-button"
            onClick={runDecrypt}
            disabled={busy || !fileId.trim() || !recipientId.trim() || !privateKey.trim()}
          >
            {busy ? "Decrypting..." : "Decrypt Document"}
          </button>

          {error && <p style={{ color: "#dc2626", wordBreak: "break-word" }}>{error}</p>}
        </div>

        <div className="verification-card">
          <h3>Verification Status</h3>

          <div className="verification-row">
            <span>Recipient Authorization</span>
            <Status ok={decrypted} yes="VALID" no="DENIED" />
          </div>

          <div className="verification-row">
            <span>ZKP Proof</span>
            <Status ok={zkpOk} yes="VERIFIED" no="FAILED" />
          </div>

          <div className="verification-row">
            <span>Ledger Entry</span>
            <Status ok={ledgerOk} yes="CONFIRMED" no="NOT CONFIRMED" />
          </div>

          {watermarkId && (
            <>
              <div className="verification-row">
                <span>Watermark ID</span>
                <strong style={{ wordBreak: "break-all" }}>{watermarkId}</strong>
              </div>
              <div className="verification-row">
                <span>Time</span>
                <strong>{timestamp ? new Date(timestamp).toLocaleString() : ""}</strong>
              </div>
              <button className="secondary-button" onClick={download}>
                Download watermarked file
              </button>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
