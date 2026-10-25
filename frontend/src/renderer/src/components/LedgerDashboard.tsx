import { useEffect, useState } from "react";
import {
  anchorOnFabric,
  appendToHashChain,
  getFabricStatus,
  getLastWatermarkId,
  verifyHashChain,
  verifyOnFabric,
} from "../services/api";

// Panel placed inside the Ledger page (the event table above it is fed by App.tsx).
export default function LedgerDashboard() {
  const [watermarkId, setWatermarkId] = useState(getLastWatermarkId());
  const [busy, setBusy] = useState(false);
  const [fabric, setFabric] = useState("checking...");
  const [message, setMessage] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    getFabricStatus()
      .then((s) => setFabric(s.enabled ? "enabled" : "disabled"))
      .catch(() => setFabric("unavailable"));
  }, []);

  const run = async (label: string, job: () => Promise<unknown>) => {
    setBusy(true);
    setMessage(null);
    setFailed(false);
    try {
      const out = await job();
      setMessage(label + ": " + JSON.stringify(out));
    } catch (e) {
      setFailed(true);
      setMessage(label + " failed: " + (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const id = watermarkId.trim();

  return (
    <div className="privacy-card" style={{ margin: "16px 0" }}>
      <span className="privacy-label">LEDGER ACTIONS · Fabric: {fabric}</span>

      <input
        className="text-input"
        placeholder="Watermark ID"
        value={watermarkId}
        onChange={(e) => setWatermarkId(e.target.value)}
      />

      <div className="ledger-toolbar">
        <button
          className="secondary-button"
          disabled={busy || !id}
          onClick={() => run("Hash chain append", () => appendToHashChain(id))}
        >
          Add to hash chain
        </button>

        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => run("Hash chain check", () => verifyHashChain())}
        >
          Verify hash chain
        </button>

        <button
          className="secondary-button"
          disabled={busy || !id}
          onClick={() => run("Fabric anchor", () => anchorOnFabric(id))}
        >
          Anchor on Fabric
        </button>

        <button
          className="secondary-button"
          disabled={busy || !id}
          onClick={() => run("Fabric verify", () => verifyOnFabric(id))}
        >
          Verify on Fabric
        </button>
      </div>

      {message && (
        <p
          style={{
            color: failed ? "#dc2626" : undefined,
            wordBreak: "break-word",
            fontSize: "0.85rem",
          }}
        >
          {message}
        </p>
      )}
    </div>
  );
}
