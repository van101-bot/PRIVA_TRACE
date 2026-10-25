import { useEffect, useState } from "react";
import "../App.css";
import Dashboard from "./components/Dashboard";
import PeersScreen from "./components/PeersScreen";
import LedgerDashboard from "./components/LedgerDashboard";
import DecryptScreen from "./components/DecryptScreen";
import InvestigationScreen from "./components/InvestigationScreen";
import PrivacyAttributionScreen from "./components/PrivacyAttributionScreen";
import ReportViewer from "./components/ReportViewer";
import { encryptDocument, generateRecipientKey } from "./services/api";

type Page =
  | "Dashboard"
  | "Upload"
  | "Decrypt"
  | "Investigation"
  | "Privacy"
  | "Ledger"
  | "Peers"
  | "Reports";

function App() {
  const [activePage, setActivePage] = useState<Page>("Dashboard");
  const [darkMode, setDarkMode] = useState(true);
  const [privacyMode, setPrivacyMode] = useState(true);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [documentId, setDocumentId] = useState<string | null>(null);
  const [watermarkId, setWatermarkId] = useState("");

  // Keyboard shortcuts
  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if (!event.ctrlKey) return;

      const key = event.key.toLowerCase();

      if (event.shiftKey && key === "d") {
        event.preventDefault();
        setDarkMode((current) => !current);
        return;
      }

      if (event.shiftKey && key === "p") {
        event.preventDefault();
        setPrivacyMode((current) => !current);
        return;
      }

      if (!event.shiftKey && key === "e") {
        event.preventDefault();
        setActivePage("Upload");
        return;
      }

      if (!event.shiftKey && key === "d") {
        event.preventDefault();
        setActivePage("Decrypt");
        return;
      }

      if (!event.shiftKey && key === "l") {
        event.preventDefault();
        setActivePage("Investigation");
        return;
      }
    };

    window.addEventListener("keydown", handleShortcut);

    return () => {
      window.removeEventListener("keydown", handleShortcut);
    };
  }, []);

  const navigation: { name: Page; icon: string }[] = [
    { name: "Dashboard", icon: "⌂" },
    { name: "Upload", icon: "↑" },
    { name: "Decrypt", icon: "↓" },
    { name: "Investigation", icon: "⌕" },
    { name: "Privacy", icon: "◉" },
    { name: "Ledger", icon: "▣" },
    { name: "Peers", icon: "◈" },
    { name: "Reports", icon: "▤" },
  ];

  const selectPdf = () => {
    const input = document.createElement("input");

    input.type = "file";
    input.accept = ".pdf,application/pdf";

    input.onchange = (event) => {
      const target = event.target as HTMLInputElement;
      const file = target.files?.[0];

      if (file && file.type === "application/pdf") {
        setSelectedFile(file);
        setDocumentId(null);
      } else if (file) {
        alert("Please select a PDF file.");
      }
    };

    input.click();
  };

  const encryptAndDistribute = async () => {
    if (!selectedFile) {
      alert("Please select a PDF document first.");
      return;
    }

    try {
      // Demo recipient: the backend makes an ML-KEM key pair, then encrypts for it.
      const recipient = await generateRecipientKey("recipient-" + Date.now());
      const result = await encryptDocument(selectedFile, [
        { recipient_id: recipient.recipient_id, public_key: recipient.public_key },
      ]);
      setDocumentId(result.encrypted_file_id);
    } catch (error) {
      alert("Encryption failed: " + (error as Error).message);
    }
  };

  const pageContent = () => {
    if (activePage === "Dashboard") {
      return (
        <Dashboard
          onNavigate={(page) => setActivePage(page)}
        />
      );
    }

    switch (activePage) {
      case "Upload":
        return (
          <section className="content-card large-card">
            <div className="card-title">
              <div>
                <h2>Secure Document Upload</h2>
                <p>
                  Encrypt and distribute documents to
                  authorized recipients.
                </p>
              </div>

              <span className="badge badge-success">
                READY
              </span>
            </div>

            <div
              className="upload-zone"
              onDragOver={(event) => {
                event.preventDefault();
              }}
              onDrop={(event) => {
                event.preventDefault();

                const file = event.dataTransfer.files[0];

                if (file && file.type === "application/pdf") {
                  setSelectedFile(file);
                  setDocumentId(null);
                } else {
                  alert("Please select a PDF file.");
                }
              }}
            >
              <div className="upload-icon">↑</div>

              <h3>
                {selectedFile
                  ? "Document selected"
                  : "Drop PDF document here"}
              </h3>

              <p>
                {selectedFile
                  ? selectedFile.name
                  : "or select a PDF from your computer"}
              </p>

              {selectedFile && (
                <div className="selected-file">
                  <strong>Selected Document</strong>
                  <span>{selectedFile.name}</span>
                </div>
              )}

              <button
                className="primary-button"
                onClick={selectPdf}
              >
                {selectedFile
                  ? "Choose Another PDF"
                  : "Select Document"}
              </button>
            </div>

            {selectedFile && (
              <div className="encryption-panel">
                <div className="panel-header">
                  <div>
                    <h3>Distribution Configuration</h3>
                    <p>
                      Configure secure multi-recipient
                      distribution.
                    </p>
                  </div>

                  <span className="badge badge-warning">
                    DEMO MODE
                  </span>
                </div>

                <div className="info-grid">
                  <div className="info-box">
                    <span>DOCUMENT</span>
                    <strong>{selectedFile.name}</strong>
                  </div>

                  <div className="info-box">
                    <span>RECIPIENTS</span>
                    <strong>3 Authorized Peers</strong>
                  </div>

                  <div className="info-box">
                    <span>SECURITY</span>
                    <strong>Post-Quantum</strong>
                  </div>
                </div>

                <button
                  className="primary-button"
                  onClick={encryptAndDistribute}
                >
                  🔐 Encrypt &amp; Distribute
                </button>

                {documentId && (
                  <div className="privacy-notice">
                    <strong>
                      ✓ Encryption workflow completed
                    </strong>

                    <p>
                      Document ID:{" "}
                      <strong>{documentId}</strong>
                    </p>

                    <p>
                      Encrypted on the backend (ML-KEM-768).
                      Open the Decrypt page to continue.
                    </p>
                  </div>
                )}
              </div>
            )}

            <div className="info-grid">
              <div className="info-box">
                <span>ENCRYPTION</span>
                <strong>Post-Quantum Secure</strong>
              </div>

              <div className="info-box">
                <span>ATTRIBUTION</span>
                <strong>Cryptographic</strong>
              </div>

              <div className="info-box">
                <span>LEDGER</span>
                <strong>Immutable</strong>
              </div>
            </div>
          </section>
        );

      case "Decrypt":
        return (
          <DecryptScreen
            key={documentId ?? "none"}
            encryptedFileId={documentId}
            onDecrypted={setWatermarkId}
          />
        );

      case "Investigation":
        return (
          <InvestigationScreen
            watermarkId={watermarkId}
            onWatermark={setWatermarkId}
          />
        );

      case "Privacy":
        return (
          <PrivacyAttributionScreen
            watermarkId={watermarkId}
            onWatermark={setWatermarkId}
          />
        );

      case "Ledger":
        return <LedgerDashboard />;

      case "Peers":
        return <PeersScreen />;

      case "Reports":
        return (
          <ReportViewer
            watermarkId={watermarkId}
            onWatermark={setWatermarkId}
          />
        );

      default:
        return null;
    }
  };

  return (
    <div className={`app ${darkMode ? "dark-mode" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">◈</div>

          <div>
            <h1>DHWANICRYPT</h1>
            <span>SIH26237</span>
          </div>
        </div>

        <div className="sidebar-section">
          <span className="sidebar-label">
            OPERATIONS
          </span>

          {navigation.slice(0, 4).map((item) => (
            <button
              key={item.name}
              className={`nav-item ${
                activePage === item.name ? "active" : ""
              }`}
              onClick={() => setActivePage(item.name)}
            >
              <span className="nav-icon">
                {item.icon}
              </span>

              <span>{item.name}</span>
            </button>
          ))}
        </div>

        <div className="sidebar-section">
          <span className="sidebar-label">
            SECURITY
          </span>

          {navigation.slice(4).map((item) => (
            <button
              key={item.name}
              className={`nav-item ${
                activePage === item.name ? "active" : ""
              }`}
              onClick={() => setActivePage(item.name)}
            >
              <span className="nav-icon">
                {item.icon}
              </span>

              <span>{item.name}</span>
            </button>
          ))}
        </div>

        <div className="sidebar-bottom">
          <div className="qkd-mini-status">
            <span className="status-dot"></span>

            <div>
              <strong>QKD CHANNEL</strong>
              <small>Simulated</small>
            </div>
          </div>

          <div className="version">
            SIH 2026 • v1.0.0
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <span>SECURITY CONSOLE</span>
            <span>/</span>
            <strong>{activePage}</strong>
          </div>

          <div className="topbar-actions">
            <button
              className={`privacy-toggle ${
                privacyMode ? "enabled" : ""
              }`}
              onClick={() =>
                setPrivacyMode(!privacyMode)
              }
            >
              <span>◉</span>
              Privacy {privacyMode ? "ON" : "OFF"}
            </button>

            <button
              className="theme-toggle"
              onClick={() => setDarkMode(!darkMode)}
              title="Toggle dark mode"
            >
              {darkMode ? "☀" : "☾"}
            </button>

            <div className="operator-badge">
              <div className="operator-avatar">
                OP
              </div>

              <div>
                <strong>OPERATOR</strong>
                <small>Authorized</small>
              </div>
            </div>
          </div>
        </header>

        <div className="page-container">
          {pageContent()}
        </div>
      </main>
    </div>
  );
}

export default App;