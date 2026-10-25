import { useState } from "react";
import {
  getLastWatermarkId,
  getProvenance,
  investigateLeak,
} from "../services/api";
import type { ProvenanceResult } from "../services/api";

function yesNo(value: boolean | undefined): string {
  if (value === undefined) {
    return "not checked";
  }
  return value ? "passed" : "FAILED";
}

type Props = {
  watermarkId?: string;
  onWatermark?: (watermarkId: string) => void;
};

export default function InvestigationScreen({ watermarkId: sharedId, onWatermark }: Props) {
  const [localId, setLocalId] = useState(getLastWatermarkId());
  const watermarkId = sharedId || localId;
  const setWatermarkId = (value: string) => {
    setLocalId(value);
    if (onWatermark) {
      onWatermark(value);
    }
  };
  const [leakedFile, setLeakedFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ProvenanceResult | null>(null);

  const run = async (job: () => Promise<ProvenanceResult>) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await job());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const lookupById = () => run(() => getProvenance(watermarkId.trim()));
  const traceFile = () => {
    if (!leakedFile) {
      setError("Choose the leaked file first.");
      return Promise.resolve();
    }
    return run(() => investigateLeak(leakedFile));
  };

  const known = result?.known === true;

  return (
    <section className="content-card large-card">
      <div className="card-title">
        <div>
          <h2>Leak Investigation</h2>
          <p>Trace the cryptographic provenance of a leaked document.</p>
        </div>

        <span className="badge badge-warning">INVESTIGATION</span>
      </div>

      <div className="search-section">
        <input
          className="text-input"
          placeholder="Enter watermark ID"
          value={watermarkId}
          onChange={(e) => setWatermarkId(e.target.value)}
        />

        <button
          className="primary-button"
          onClick={lookupById}
          disabled={busy || !watermarkId.trim()}
        >
          {busy ? "Working..." : "Investigate"}
        </button>
      </div>

      <div className="search-section">
        <input
          type="file"
          className="text-input"
          accept=".pdf,.png,.jpg,.jpeg,.docx"
          onChange={(e) => setLeakedFile(e.target.files ? e.target.files[0] : null)}
        />

        <button className="secondary-button" onClick={traceFile} disabled={busy || !leakedFile}>
          Trace leaked file
        </button>
      </div>

      {error && <p style={{ color: "#dc2626", wordBreak: "break-word" }}>{error}</p>}

      {result && (
        <div className="investigation-result">
          <div className="result-header">
            <span>WATERMARK ID</span>
            <strong style={{ wordBreak: "break-all" }}>{result.watermark_id}</strong>
          </div>

          {!known && (
            <div className="privacy-notice">
              No record of this watermark for your account. It may not exist, or it belongs to
              another user.
            </div>
          )}

          {known && (
            <div className="timeline">
              <div className="timeline-item">
                <span className="timeline-dot"></span>
                <div>
                  <strong>Document encrypted</strong>
                  <p>File ID: {result.encrypted_file_id}</p>
                </div>
              </div>

              <div className="timeline-item">
                <span className="timeline-dot"></span>
                <div>
                  <strong>Decryption recorded</strong>
                  <p>
                    {result.decrypted_at ? new Date(result.decrypted_at).toLocaleString() : ""}
                    {result.ledger_backend ? " · " + result.ledger_backend : ""}
                  </p>
                </div>
              </div>

              <div className="timeline-item">
                <span className="timeline-dot"></span>
                <div>
                  <strong>ZKP verification {yesNo(result.zkp_verified)}</strong>
                  <p>Signed record: {yesNo(result.signature_valid)}</p>
                </div>
              </div>

              <div className="timeline-item">
                <span className="timeline-dot"></span>
                <div>
                  <strong>Overall: {result.status}</strong>
                  <p>
                    {typeof result.confidence === "number"
                      ? "Watermark match confidence " + Math.round(result.confidence * 100) + "%"
                      : "Looked up by watermark ID"}
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="privacy-notice">
            Recipient identity is protected by privacy-preserving attribution.
          </div>
        </div>
      )}
    </section>
  );
}
