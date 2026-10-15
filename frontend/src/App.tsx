
import { useCallback, useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";

type Finding = {
  port?: number | string;
  service?: string;
  risk_level?: string;
  risk_score?: number;
  encrypted?: boolean;
  explanation?: string;
  remediation?: string;
  priority?: string;
  [key: string]: unknown;
};

type Scan = {
  id: number | string;
  target: string;
  findings: Finding[];
  created_at?: string;
  summary?: {
    total_findings?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
};

const colors = {
  background: "#0b1020",
  panel: "#121a2c",
  border: "#27344c",
  text: "#edf2ff",
  muted: "#9aa9c4",
  blue: "#7c9cff",
};

const panelStyle = {
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 14,
  padding: 20,
};

const buttonStyle = {
  border: `1px solid ${colors.border}`,
  borderRadius: 9,
  padding: "10px 15px",
  background: "#202d47",
  color: colors.text,
  cursor: "pointer",
  fontWeight: 600 as const,
};

function riskColor(level?: string) {
  switch ((level || "INFO").toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return "#ff8585";
    case "MEDIUM":
      return "#ffca75";
    case "LOW":
      return "#78dfb1";
    default:
      return "#9eb7ff";
  }
}

function priorityColor(priority?: string) {
  switch ((priority || "").toUpperCase()) {
    case "P1":
      return "#ff8585";
    case "P2":
      return "#ffca75";
    case "P3":
      return "#9eb7ff";
    default:
      return "#78dfb1";
  }
}

function displayDate(value?: string) {
  if (!value) return "Date unavailable";

  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}

function normalizeScans(data: unknown): Scan[] {
  if (Array.isArray(data)) return data as Scan[];

  if (
    data &&
    typeof data === "object" &&
    "scans" in data &&
    Array.isArray((data as { scans: unknown }).scans)
  ) {
    return (data as { scans: Scan[] }).scans;
  }

  return [];
}

function App() {
  const [target, setTarget] = useState("127.0.0.1");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [expanded, setExpanded] = useState(true);

  const loadScans = useCallback(async () => {
    setHistoryLoading(true);

    try {
      const response = await fetch(`${API}/scans`);

      if (!response.ok) {
        throw new Error(`Could not load scan history (${response.status}).`);
      }

      const data: unknown = await response.json();
      setScans(normalizeScans(data));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not connect to the backend."
      );
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadScans();
  }, [loadScans]);

  async function runAssessment(mode: "demo" | "real") {
    setLoading(true);
    setError("");
    setMessage("");

    try {
      const response = await fetch(`${API}/scans/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        ...(mode === "real"
          ? { body: JSON.stringify({ target }) }
          : {}),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || `Assessment failed (${response.status}).`
        );
      }

      const result = data as Scan;
      const resultFindings = Array.isArray(result.findings)
        ? result.findings
        : [];

      setFindings(resultFindings);
      setActiveScan(result);
      setExpanded(true);
      setMessage(
        `${mode === "demo" ? "Demo assessment" : "Local scan"} completed successfully.`
      );

      await loadScans();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "An unexpected error occurred."
      );
    } finally {
      setLoading(false);
    }
  }

  function openScan(scan: Scan) {
    setActiveScan(scan);
    setFindings(Array.isArray(scan.findings) ? scan.findings : []);
    setError("");
    setMessage(`Viewing assessment #${scan.id}.`);
    setExpanded(true);
  }

  const counts = {
    total: findings.length,
    high: findings.filter(
      (f) => ["HIGH", "CRITICAL"].includes(
        String(f.risk_level || "").toUpperCase()
      )
    ).length,
    medium: findings.filter(
      (f) => String(f.risk_level || "").toUpperCase() === "MEDIUM"
    ).length,
    low: findings.filter(
      (f) => String(f.risk_level || "").toUpperCase() === "LOW"
    ).length,
  };

  const apiFieldsAvailable = findings.some(
    (f) => f.explanation || f.remediation || f.priority
  );

  return (
    <main
      style={{
        minHeight: "100vh",
        background: colors.background,
        color: colors.text,
        fontFamily: "Inter, Segoe UI, Arial, sans-serif",
        padding: "28px 18px 50px",
      }}
    >
      <div style={{ maxWidth: 1150, margin: "0 auto" }}>
        <header
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 16,
            marginBottom: 28,
          }}
        >
          <div>
            <div
              style={{
                color: colors.blue,
                fontSize: 12,
                letterSpacing: 2,
                fontWeight: 800,
              }}
            >
              NETWORK SECURITY WORKSPACE
            </div>
            <h1 style={{ fontSize: 30, margin: "8px 0" }}>
              SecureScope AI
            </h1>
            <p style={{ color: colors.muted, margin: 0 }}>
              Network assessment, risk explanations and remediation guidance
            </p>
          </div>

          <div
            style={{
              border: `1px solid ${colors.border}`,
              borderRadius: 30,
              padding: "9px 13px",
              color: "#78dfb1",
              fontSize: 13,
            }}
          >
            ● Backend connection
          </div>
        </header>

        <section style={{ ...panelStyle, marginBottom: 20 }}>
          <h2 style={{ marginTop: 0, fontSize: 18 }}>
            Run a security assessment
          </h2>
          <p style={{ color: colors.muted, lineHeight: 1.6 }}>
            Use a sample assessment to explore the dashboard, or scan your own
            local machine. Real scans are restricted to loopback addresses.
          </p>

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              alignItems: "center",
            }}
          >
            <button
              style={{
                ...buttonStyle,
                background: "#526fe0",
                borderColor: "#526fe0",
              }}
              disabled={loading}
              onClick={() => void runAssessment("demo")}
            >
              {loading ? "Working..." : "Run Demo Scan"}
            </button>

            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              aria-label="Local scan target"
              style={{
                background: "#0b1020",
                border: `1px solid ${colors.border}`,
                borderRadius: 9,
                padding: "10px 12px",
                color: colors.text,
                minWidth: 180,
              }}
            />

            <button
              style={buttonStyle}
              disabled={loading}
              onClick={() => void runAssessment("real")}
            >
              Run Local Scan
            </button>
          </div>

          {message && (
            <p style={{ color: "#78dfb1", marginBottom: 0 }}>{message}</p>
          )}
          {error && (
            <p
              role="alert"
              style={{
                color: "#ff9999",
                background: "#351c2a",
                padding: 12,
                borderRadius: 8,
                overflowWrap: "anywhere",
              }}
            >
              {error}
            </p>
          )}
        </section>

        <section
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
            gap: 12,
            marginBottom: 20,
          }}
        >
          {[
            { label: "Total findings", value: counts.total, color: colors.text },
            { label: "High / Critical", value: counts.high, color: "#ff8585" },
            { label: "Medium", value: counts.medium, color: "#ffca75" },
            { label: "Low", value: counts.low, color: "#78dfb1" },
          ].map((item) => (
            <div key={item.label} style={panelStyle}>
              <div style={{ color: colors.muted, fontSize: 13 }}>
                {item.label}
              </div>
              <div
                style={{
                  fontSize: 30,
                  fontWeight: 800,
                  color: item.color,
                  marginTop: 8,
                }}
              >
                {item.value}
              </div>
            </div>
          ))}
        </section>

        <section style={{ ...panelStyle, marginBottom: 20 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 10,
            }}
          >
            <div>
              <h2 style={{ margin: "0 0 7px", fontSize: 20 }}>
                Security findings
              </h2>
              <div style={{ color: colors.muted, fontSize: 13 }}>
                {activeScan
                  ? `Assessment #${activeScan.id} · Target: ${activeScan.target}`
                  : "Run a demo or local scan to see findings."}
              </div>
            </div>

            <button
              style={buttonStyle}
              onClick={() => setExpanded((value) => !value)}
            >
              {expanded ? "Collapse" : "Show findings"}
            </button>
          </div>

          {!expanded ? null : findings.length === 0 ? (
            <p style={{ color: colors.muted, marginBottom: 0 }}>
              No findings to display for this assessment.
            </p>
          ) : (
            <div style={{ display: "grid", gap: 14, marginTop: 18 }}>
              {findings.map((finding, index) => (
                <article
                  key={`${finding.port ?? "port"}-${finding.service ?? "service"}-${index}`}
                  style={{
                    background: "#0d1424",
                    border: `1px solid ${colors.border}`,
                    borderRadius: 12,
                    padding: 16,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "flex-start",
                      flexWrap: "wrap",
                      gap: 12,
                    }}
                  >
                    <div>
                      <h3 style={{ margin: "0 0 7px", fontSize: 17 }}>
                        {String(finding.service || "Unknown service").toUpperCase()}
                        {" · Port "}
                        {finding.port ?? "Unknown"}
                      </h3>
                      <div style={{ color: colors.muted, fontSize: 13 }}>
                        Encryption:{" "}
                        {finding.encrypted === true
                          ? "Reported as encrypted"
                          : finding.encrypted === false
                            ? "Not encrypted"
                            : "Unknown"}
                        {typeof finding.risk_score === "number"
                          ? ` · Risk score: ${finding.risk_score}`
                          : ""}
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <span
                        style={{
                          border: `1px solid ${riskColor(finding.risk_level)}`,
                          color: riskColor(finding.risk_level),
                          padding: "5px 9px",
                          borderRadius: 7,
                          fontSize: 12,
                          fontWeight: 700,
                        }}
                      >
                        {(finding.risk_level || "INFO").toUpperCase()}
                      </span>
                      <span
                        style={{
                          border: `1px solid ${priorityColor(finding.priority)}`,
                          color: priorityColor(finding.priority),
                          padding: "5px 9px",
                          borderRadius: 7,
                          fontSize: 12,
                          fontWeight: 800,
                        }}
                      >
                        {finding.priority || "Priority unavailable"}
                      </span>
                    </div>
                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
                      gap: 12,
                      marginTop: 16,
                    }}
                  >
                    <div
                      style={{
                        background: colors.panel,
                        borderRadius: 9,
                        padding: 13,
                      }}
                    >
                      <h4 style={{ margin: "0 0 8px", color: colors.blue }}>
                        Risk explanation
                      </h4>
                      <p
                        style={{
                          margin: 0,
                          color: colors.text,
                          lineHeight: 1.65,
                          overflowWrap: "anywhere",
                        }}
                      >
                        {finding.explanation ||
                          "No explanation was provided by the API."}
                      </p>
                    </div>

                    <div
                      style={{
                        background: colors.panel,
                        borderRadius: 9,
                        padding: 13,
                      }}
                    >
                      <h4 style={{ margin: "0 0 8px", color: "#78dfb1" }}>
                        Recommended remediation
                      </h4>
                      <p
                        style={{
                          margin: 0,
                          color: colors.text,
                          lineHeight: 1.65,
                          overflowWrap: "anywhere",
                        }}
                      >
                        {finding.remediation ||
                          "No remediation guidance was provided by the API."}
                      </p>
                    </div>
                  </div>
                </article>
              ))}
            </div>
          )}

          {findings.length > 0 && !apiFieldsAvailable && (
            <p style={{ color: "#ffca75", fontSize: 13 }}>
              The API returned findings, but none contains explanation,
              remediation, or priority. Check the backend response.
            </p>
          )}
        </section>

        <section style={panelStyle}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <div>
              <h2 style={{ margin: "0 0 6px", fontSize: 20 }}>
                Recent assessments
              </h2>
              <p style={{ color: colors.muted, margin: 0, fontSize: 13 }}>
                Select a saved assessment to review its findings.
              </p>
            </div>
            <button
              style={buttonStyle}
              disabled={historyLoading}
              onClick={() => void loadScans()}
            >
              {historyLoading ? "Refreshing..." : "Refresh history"}
            </button>
          </div>

          {scans.length === 0 ? (
            <p style={{ color: colors.muted }}>
              {historyLoading ? "Loading history..." : "No saved assessments found."}
            </p>
          ) : (
            <div style={{ display: "grid", gap: 10, marginTop: 16 }}>
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: 12,
                    border: `1px solid ${colors.border}`,
                    borderRadius: 9,
                    padding: 12,
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 700 }}>
                      Assessment #{scan.id} · {scan.target}
                    </div>
                    <div
                      style={{
                        color: colors.muted,
                        fontSize: 12,
                        marginTop: 5,
                      }}
                    >
                      {displayDate(scan.created_at)} ·{" "}
                      {Array.isArray(scan.findings) ? scan.findings.length : 0} findings
                    </div>
                  </div>

                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <button
                      style={buttonStyle}
                      onClick={() => openScan(scan)}
                    >
                      View findings
                    </button>
                    <a
                      href={`${API}/scans/${encodeURIComponent(String(scan.id))}/report.csv`}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        ...buttonStyle,
                        textDecoration: "none",
                        display: "inline-flex",
                        alignItems: "center",
                      }}
                    >
                      CSV report
                    </a>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <footer
          style={{
            color: colors.muted,
            fontSize: 12,
            lineHeight: 1.7,
            marginTop: 20,
          }}
        >
          SecureScope AI provides rule-based assessment guidance. An open port
          or detected service does not by itself confirm a vulnerability.
          Review findings in context before taking remediation actions.
        </footer>
      </div>
    </main>
  );
}

export default App;
