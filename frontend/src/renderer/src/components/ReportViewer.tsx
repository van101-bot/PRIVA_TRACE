import { useState } from "react";
import {
  downloadAttributionReport,
  getLastWatermarkId,
  saveBlob,
} from "../services/api";

type Props = {
  watermarkId?: string;
  onWatermark?: (watermarkId: string) => void;
};

export default function ReportViewer({ watermarkId: sharedId, onWatermark }: Props) {
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
  const [done, setDone] = useState<string | null>(null);

  const generate = async () => {
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const id = watermarkId.trim();
      const pdf = await downloadAttributionReport(id);
      saveBlob(pdf, "attribution_report_" + id.slice(0, 12) + ".pdf");
      setDone("Report downloaded for " + id.slice(0, 12) + "...");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="content-card large-card">
      <div className="card-title">
        <div>
          <h2>Attribution Reports</h2>
          <p>Generate a signed attribution and provenance report (PDF).</p>
        </div>

        <span className="badge badge-success">SECURE</span>
      </div>

      <div className="search-section">
        <input
          className="text-input"
          placeholder="Enter watermark ID"
          value={watermarkId}
          onChange={(e) => setWatermarkId(e.target.value)}
        />

        <button className="primary-button" onClick={generate} disabled={busy || !watermarkId.trim()}>
          {busy ? "Generating..." : "Generate PDF report"}
        </button>
      </div>

      {error && <p style={{ color: "#dc2626", wordBreak: "break-word" }}>{error}</p>}
      {done && <p className="status-ok">{done}</p>}

      <div className="privacy-notice">
        Reports show the watermark, document hash, time, ZKP and signature checks. They never
        name the recipient. Only the user who created the decryption record can generate it.
      </div>
    </section>
  );
}
