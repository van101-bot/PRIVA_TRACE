import { useState } from "react";
import { getLastWatermarkId, verifyAttribution } from "../services/api";

type Answer = { is_authorized: boolean; zkp_verified: boolean };

type Props = {
  watermarkId?: string;
  onWatermark?: (watermarkId: string) => void;
};

export default function PrivacyAttributionScreen({ watermarkId: sharedId, onWatermark }: Props) {
  const [localId, setLocalId] = useState(getLastWatermarkId());
  const watermarkId = sharedId || localId;
  const setWatermarkId = (value: string) => {
    setLocalId(value);
    if (onWatermark) {
      onWatermark(value);
    }
  };
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [answer, setAnswer] = useState<Answer | null>(null);

  const check = async () => {
    setBusy(true);
    setError(null);
    setAnswer(null);
    try {
      setAnswer(await verifyAttribution(watermarkId.trim()));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const label = (value: boolean | undefined, yes: string, no: string) =>
    value === undefined ? "—" : value ? yes : no;

  return (
    <section className="content-card large-card">
      <div className="card-title">
        <div>
          <h2>Privacy-Preserving Attribution</h2>
          <p>Verify authorization without exposing recipient identity.</p>
        </div>

        <span className="badge badge-success">PRIVACY ON</span>
      </div>

      <div className="search-section">
        <input
          className="text-input"
          placeholder="Enter watermark ID"
          value={watermarkId}
          onChange={(e) => setWatermarkId(e.target.value)}
        />

        <button className="primary-button" onClick={check} disabled={busy || !watermarkId.trim()}>
          {busy ? "Verifying..." : "Verify attribution"}
        </button>
      </div>

      {error && <p style={{ color: "#dc2626", wordBreak: "break-word" }}>{error}</p>}

      <div className="privacy-grid">
        <div className="privacy-card">
          <span className="privacy-label">RECIPIENT STATUS</span>
          <h3>{label(answer?.is_authorized, "Authorized Recipient", "NOT authorized")}</h3>
          <p>Identity hidden by default.</p>
        </div>

        <div className="privacy-card">
          <span className="privacy-label">ZERO-KNOWLEDGE PROOF</span>
          <h3>{label(answer?.zkp_verified, "Proof verified", "Proof FAILED")}</h3>
          <p>No name, ID or commitment is ever returned.</p>
        </div>
      </div>

      <div className="privacy-notice">
        Attribution answers only "is this leak from an authorized recipient?". The recipient is
        never named.
      </div>
    </section>
  );
}
