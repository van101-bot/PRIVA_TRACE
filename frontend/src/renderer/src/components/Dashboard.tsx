import { KIND_ICON, NOISE, classify, timeAgo } from "./events";
import { useSystemStatus } from "./systemStatus";
import { short } from "./utils";

type DashboardPage =
  | "Upload"
  | "Decrypt"
  | "Investigation"
  | "Ledger";

interface DashboardProps {
  onNavigate: (page: DashboardPage) => void;
}

const colors = {
  bg: "#080d15",
  card: "#0d1621",
  card2: "#101b27",
  border: "#26394b",
  text: "#e8f0f6",
  muted: "#71869a",
  blue: "#52c5f2",
  green: "#55d994",
};

const cardStyle: React.CSSProperties = {
  background: "linear-gradient(145deg, #101b27, #0b141e)",
  border: `1px solid ${colors.border}`,
  borderRadius: "12px",
};

export default function Dashboard({ onNavigate }: DashboardProps) {
  const s = useSystemStatus();

  const events = s.rows
    .filter((r) => !NOISE.some((n) => r.path.startsWith(n)))
    .map((r) => ({ ...r, ...classify(r.path) }));
  const cutoff = Date.now() - 24 * 3600 * 1000;
  const last24 = events.filter((e) => new Date(e.created_at).getTime() >= cutoff);
  const checks = events.filter(
    (e) => e.kind === "decryption" || e.kind === "zkp" || e.kind === "investigation",
  );
  const okChecks = checks.filter((e) => e.status_code < 400).length;

  const serviceFlags = [s.backend === true, s.chain?.valid === true];
  if (s.fabric) serviceFlags.push(true);
  const online = serviceFlags.filter(Boolean).length;
  const allOk = s.backend === true && s.chain?.valid !== false;

  const qkdMode = s.qkd?.qkd_mode ?? "";
  const qkdValue = !s.qkd
    ? "—"
    : qkdMode === "off"
      ? "OFF"
      : qkdMode === "simulated"
        ? "SIMULATED"
        : s.qkd.qkd_available
          ? "SECURE"
          : "OFFLINE";

  const statCards = [
    {
      title: "SERVICES ONLINE",
      value: s.backend === null ? "…" : `${online}/${serviceFlags.length}`,
      sub: allOk ? "API and ledger healthy" : "Check the Peers page",
    },
    {
      title: "LEDGER EVENTS",
      value: s.rows.length >= 200 ? `${last24.length}+` : String(last24.length),
      sub: "Last 24 hours (your activity)",
    },
    {
      title: "VERIFICATIONS",
      value: checks.length ? `${Math.round((okChecks / checks.length) * 100)}%` : "—",
      sub: checks.length
        ? `${okChecks} of ${checks.length} checks succeeded`
        : "No checks run yet",
    },
    {
      title: "QKD STATUS",
      value: qkdValue,
      sub: s.qkd?.detail ?? "Status unavailable",
    },
  ];

  type Tone = "ok" | "warn" | "bad";
  const toneColor: Record<Tone, string> = {
    ok: colors.green,
    warn: "#dfb768",
    bad: "#ff6b81",
  };
  const apiTone: Tone = s.backend === null ? "warn" : s.backend ? "ok" : "bad";
  const apiText = s.backend === null ? "Checking" : s.backend ? "Operational" : "Offline";
  const systemRows: [string, string, Tone][] = [
    ["Encryption Service", apiText, apiTone],
    ["Attribution Engine", apiText, apiTone],
    ["ZKP Verification", apiText, apiTone],
    [
      "Immutable Ledger",
      s.chain
        ? s.chain.valid
          ? `Valid · ${s.chain.records_checked} records`
          : "Chain broken"
        : s.backend
          ? "Unknown"
          : "Offline",
      s.chain ? (s.chain.valid ? "ok" : "bad") : "warn",
    ],
    [
      "QKD Channel",
      s.qkd ? (qkdMode === "off" ? "Off" : qkdMode === "simulated" ? "Simulated" : s.qkd.qkd_available ? "Active" : "Not available") : "Unknown",
      s.qkd && s.qkd.qkd_available && qkdMode === "hardware" ? "ok" : "warn",
    ],
  ];

  const activities = events.slice(0, 4).map((e) => ({
    id: e.request_id,
    icon: KIND_ICON[e.kind],
    title: e.label,
    detail: e.resource ? short(e.resource, 8) : `${e.method} ${e.path}`,
    time: timeAgo(e.created_at),
  }));

  const actions = [
    {
      icon: "↑",
      title: "Encrypt & Distribute",
      description: "Secure a new document",
      page: "Upload" as DashboardPage,
      iconColor: "#58c8f3",
      iconBg: "#102a3a",
      iconBorder: "#285c78",
    },
    {
      icon: "↓",
      title: "Decrypt Document",
      description: "Access an authorized document",
      page: "Decrypt" as DashboardPage,
      iconColor: "#5cdb99",
      iconBg: "#10291f",
      iconBorder: "#286047",
    },
    {
      icon: "⌕",
      title: "Investigate Leak",
      description: "Trace document provenance",
      page: "Investigation" as DashboardPage,
      iconColor: "#dfb768",
      iconBg: "#2a2115",
      iconBorder: "#68532d",
    },
    {
      icon: "▣",
      title: "View Ledger",
      description: "Monitor immutable events",
      page: "Ledger" as DashboardPage,
      iconColor: "#b99cf3",
      iconBg: "#21192e",
      iconBorder: "#51406e",
    },
  ];

  return (
    <div
      style={{
        width: "100%",
        color: colors.text,
        fontFamily:
          '"Segoe UI", Inter, Arial, sans-serif',
      }}
    >
      {/* HEADER */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: "20px",
          marginBottom: "25px",
        }}
      >
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: "27px",
              fontWeight: 700,
              color: "#f1f6fa",
              letterSpacing: "-0.4px",
            }}
          >
            Security Operations Dashboard
          </h1>

          <p
            style={{
              margin: "7px 0 0",
              color: colors.muted,
              fontSize: "14px",
            }}
          >
            Cryptographic attribution & immutable
            decryption provenance
          </p>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            padding: "8px 12px",
            border: "1px solid #28553f",
            borderRadius: "7px",
            background: "rgba(55, 170, 105, 0.08)",
            color: colors.green,
            fontSize: "10px",
            fontWeight: 800,
            letterSpacing: "0.8px",
          }}
        >
          <span
            style={{
              width: "7px",
              height: "7px",
              borderRadius: "50%",
              background: colors.green,
              boxShadow:
                "0 0 10px rgba(85,217,148,.8)",
            }}
          />
          {allOk ? "SYSTEM OPERATIONAL" : "CHECK SERVICES"}
        </div>
      </div>

      {/* STAT CARDS */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(4, minmax(0, 1fr))",
          gap: "13px",
          marginBottom: "17px",
        }}
      >
        {statCards.map((stat) => (
          <div
            key={stat.title}
            style={{
              ...cardStyle,
              padding: "19px",
              minHeight: "120px",
            }}
          >
            <div
              style={{
                color: "#687e92",
                fontSize: "10px",
                fontWeight: 800,
                letterSpacing: "1px",
              }}
            >
              {stat.title}
            </div>

            <div
              style={{
                marginTop: "11px",
                color: "#edf4f8",
                fontSize: "23px",
                fontWeight: 700,
              }}
            >
              {stat.value}
            </div>

            <div
              style={{
                marginTop: "5px",
                color: "#72869a",
                fontSize: "11px",
              }}
            >
              {stat.sub}
            </div>
          </div>
        ))}
      </div>

      {/* TWO MAIN PANELS */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "minmax(0, 1fr) minmax(0, 1fr)",
          gap: "15px",
          marginBottom: "24px",
        }}
      >
        {/* SYSTEM STATUS */}
        <div
          style={{
            ...cardStyle,
            padding: "21px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              paddingBottom: "15px",
              borderBottom: "1px solid #1e2c39",
            }}
          >
            <h2
              style={{
                margin: 0,
                fontSize: "17px",
                color: "#e4edf4",
              }}
            >
              System Status
            </h2>

            <span
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                padding: "5px 9px",
                border: "1px solid #286040",
                borderRadius: "6px",
                color: colors.green,
                fontSize: "9px",
                fontWeight: 800,
              }}
            >
              <span
                style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: colors.green,
                }}
              />
              LIVE
            </span>
          </div>

          {systemRows.map(([name, status, tone]) => (
            <div
              key={name}
              style={{
                minHeight: "37px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "10px",
                borderBottom:
                  "1px solid rgba(31,44,57,.65)",
                fontSize: "12px",
              }}
            >
              <span style={{ color: "#9aabba" }}>
                {name}
              </span>

              <strong
                style={{
                  color: toneColor[tone],
                  fontSize: "11px",
                }}
              >
                ● {status}
              </strong>
            </div>
          ))}
        </div>

        {/* RECENT ACTIVITY */}
        <div
          style={{
            ...cardStyle,
            padding: "21px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              paddingBottom: "15px",
              borderBottom: "1px solid #1e2c39",
            }}
          >
            <h2
              style={{
                margin: 0,
                fontSize: "17px",
                color: "#e4edf4",
              }}
            >
              Recent Activity
            </h2>

            <span
              style={{
                color: colors.green,
                fontSize: "11px",
              }}
            >
              Live
            </span>
          </div>

          {activities.length === 0 && (
            <div style={{ padding: "18px 0", color: "#6b8094", fontSize: "12px" }}>
              No activity yet. Encrypt or decrypt a document to see it here.
            </div>
          )}

          {activities.map((activity) => (
            <div
              key={activity.id}
              style={{
                display: "grid",
                gridTemplateColumns:
                  "32px minmax(0,1fr) auto",
                alignItems: "center",
                gap: "11px",
                minHeight: "61px",
                borderBottom:
                  "1px solid rgba(31,44,57,.65)",
              }}
            >
              <div
                style={{
                  width: "30px",
                  height: "30px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: "1px solid #2b4d63",
                  borderRadius: "7px",
                  background: "#102130",
                  color: colors.blue,
                  fontSize: "11px",
                  fontWeight: 800,
                }}
              >
                {activity.icon}
              </div>

              <div>
                <strong
                  style={{
                    display: "block",
                    color: "#cbd8e3",
                    fontSize: "12px",
                  }}
                >
                  {activity.title}
                </strong>

                <small
                  style={{
                    display: "block",
                    marginTop: "4px",
                    color: "#6b8094",
                    fontSize: "10px",
                  }}
                >
                  {activity.detail}
                </small>
              </div>

              <span
                style={{
                  color: "#657a8e",
                  fontSize: "10px",
                }}
              >
                {activity.time}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* QUICK ACTIONS */}
      <div>
        <div style={{ marginBottom: "13px" }}>
          <h2
            style={{
              margin: 0,
              color: "#e4edf4",
              fontSize: "19px",
              fontWeight: 650,
            }}
          >
            Quick Actions
          </h2>

          <p
            style={{
              margin: "5px 0 0",
              color: "#718599",
              fontSize: "12px",
            }}
          >
            Frequently used security operations
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "repeat(4, minmax(0, 1fr))",
            gap: "12px",
          }}
        >
          {actions.map((action) => (
            <button
              key={action.title}
              onClick={() => onNavigate(action.page)}
              style={{
                minWidth: 0,
                minHeight: "105px",
                display: "flex",
                alignItems: "center",
                gap: "12px",
                padding: "16px",
                border:
                  "1px solid #263b4d",
                borderRadius: "10px",
                background:
                  "linear-gradient(145deg,#101b27,#0b141e)",
                color: "#dce6ee",
                fontFamily: "inherit",
                textAlign: "left",
                cursor: "pointer",
                outline: "none",
                transition:
                  "transform .2s ease, border-color .2s ease",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor =
                  "#3e667f";
                e.currentTarget.style.transform =
                  "translateY(-2px)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor =
                  "#263b4d";
                e.currentTarget.style.transform =
                  "translateY(0)";
              }}
            >
              <div
                style={{
                  width: "42px",
                  height: "42px",
                  minWidth: "42px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border:
                    `1px solid ${action.iconBorder}`,
                  borderRadius: "9px",
                  background: action.iconBg,
                  color: action.iconColor,
                  fontSize: "19px",
                  fontWeight: 700,
                }}
              >
                {action.icon}
              </div>

              <div
                style={{
                  minWidth: 0,
                  flex: 1,
                }}
              >
                <strong
                  style={{
                    display: "block",
                    color: "#dbe6ee",
                    fontSize: "12px",
                    fontWeight: 650,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {action.title}
                </strong>

                <span
                  style={{
                    display: "block",
                    marginTop: "5px",
                    color: "#687d91",
                    fontSize: "10px",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {action.description}
                </span>
              </div>

              <span
                style={{
                  color: "#526b7e",
                  fontSize: "17px",
                }}
              >
                →
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}