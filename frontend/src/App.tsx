
import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

type Finding = {
  port: number;
  service: string;
  risk_level: string;
  risk_score: number;
  reasons: string[];
};

type Scan = {
  id: number;
  target: string;
  findings: Finding[];
  created_at?: string;
};

type AssessmentResponse = {
  message?: string;
  target?: string;
  scan_id?: number;
  total_findings?: number;
  findings?: Finding[];
  detail?: string;
};

function App() {
  const [target, setTarget] = useState("127.0.0.1");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(
    "Ready. Run a demo assessment or scan your local computer."
  );
  const [error, setError] = useState(false);

  async function loadScans() {
    try {
      const response = await fetch(`${API}/scans`);

      if (!response.ok) {
        throw new Error(`Failed to load history: ${response.status}`);
      }

      const data: unknown = await response.json();
      setScans(Array.isArray(data) ? (data as Scan[]) : []);
    } catch (err) {
      console.error("Could not load assessments:", err);
      setScans([]);
    }
  }

  useEffect(() => {
    void loadScans();
  }, []);

  async function runAssessment(mode: "demo" | "real") {
    setLoading(true);
    setError(false);
    setMessage(
      mode === "real"
        ? "Scanning your local computer. Please wait..."
        : "Running sample assessment..."
    );

    try {
      const endpoint =
        mode === "real" ? `${API}/scans/real` : `${API}/scans/demo`;

      const body =
        mode === "real" ? { target: "127.0.0.1" } : { target };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });

      const data: AssessmentResponse = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : `Assessment failed with status ${response.status}`
        );
      }

      const newFindings = Array.isArray(data.findings)
        ? data.findings
        : [];

      setFindings(newFindings);

      setMessage(
        `${mode === "real" ? "Local scan" : "Demo assessment"} completed. ` +
          `Target: ${data.target ?? target}. ` +
          `Findings: ${newFindings.length}.`
      );

      await loadScans();
    } catch (err) {
      setError(true);
      setMessage(
        err instanceof Error
          ? err.message
          : "Unable to complete the assessment."
      );
    } finally {
      setLoading(false);
    }
  }

  const high = findings.filter(
    (item) => item.risk_level === "HIGH"
  ).length;

  const medium = findings.filter(
    (item) => item.risk_level === "MEDIUM"
  ).length;

  const low = findings.filter(
    (item) => item.risk_level === "LOW"
  ).length;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo">S</span>
          <div>
            <strong>SecureScope AI</strong>
            <small>SECURITY CENTER</small>
          </div>
        </div>

        <p className="section-label">WORKSPACE</p>
        <div className="nav active">◈ &nbsp; Overview</div>
        <div className="nav">⌕ &nbsp; Assessments</div>
        <div className="nav">▤ &nbsp; Reports</div>

        <div className="sidebar-footer">
          <span className="dot" /> API-connected dashboard
        </div>
      </aside>

      <main className="main">
        <header className="header">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS / OVERVIEW</p>
            <h1>Network Security Dashboard</h1>
            <p className="muted">
              Review assessment results and potential network security risks.
            </p>
          </div>
          <span className="badge">LOCAL SCAN / DEMO</span>
        </header>

        <section className="notice">
          <strong>SecureScope AI Assessment</strong>
          <p>
            Demo mode uses sample findings. Local scan mode runs Nmap against
            your own computer at 127.0.0.1.
          </p>
        </section>

        <section className="panel">
          <h2>Assessment Center</h2>
          <p className="muted">
            Run a sample assessment or scan your own computer.
          </p>

          <form
            onSubmit={(event) => {
              event.preventDefault();
              void runAssessment("demo");
            }}
          >
            <label htmlFor="target">Target IP address (demo only)</label>
            <div className="scan-controls">
              <input
                id="target"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                required
              />
              <button type="submit" disabled={loading}>
                {loading ? "Working..." : "Run Demo Assessment"}
              </button>
            </div>
          </form>

          <div className="scan-controls" style={{ marginTop: "12px" }}>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void runAssessment("real")}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Run Local Scan"}
            </button>
          </div>

          {message && (
            <p
              className="message"
              role="status"
              style={{
                overflowWrap: "anywhere",
                color: error ? "#f87171" : undefined,
              }}
            >
              {message}
            </p>
          )}
        </section>

        <section className="metrics">
          <Metric title="Findings" value={findings.length} />
          <Metric title="High Risk" value={high} />
          <Metric title="Medium Risk" value={medium} />
          <Metric title="Low Risk" value={low} />
        </section>

        <section className="panel">
          <h2>Assessment Findings</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>PORT</th>
                  <th>SERVICE</th>
                  <th>RISK</th>
                  <th>SCORE</th>
                  <th>REASON</th>
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="empty">
                      Run an assessment to see findings.
                    </td>
                  </tr>
                ) : (
                  findings.map((item, index) => (
                    <tr key={`${item.port}-${index}`}>
                      <td>{item.port}</td>
                      <td>{item.service}</td>
                      <td>
                        <span
                          className={`risk ${
                            (item.risk_level || "info").toLowerCase()
                          }`}
                        >
                          {item.risk_level || "INFO"}
                        </span>
                      </td>
                      <td>{item.risk_score ?? 0}</td>
                      <td>{(item.reasons ?? []).join("; ")}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Recent Assessments</h2>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void loadScans()}
              disabled={loading}
            >
              Refresh
            </button>
          </div>

          {scans.length === 0 ? (
            <p className="empty">No saved assessments yet.</p>
          ) : (
            scans.map((scan) => (
              <div className="history-row" key={scan.id}>
                <div>
                  <strong>Assessment #{scan.id}</strong>
                  <span>
                    {scan.target} · {(scan.findings ?? []).length} findings
                  </span>
                </div>
                <a
                  href={`${API}/scans/${scan.id}/report.csv`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Download CSV
                </a>
              </div>
            ))
          )}
        </section>

        <footer>
          SecureScope AI · Educational security assessment platform
        </footer>
      </main>
    </div>
  );
}

function Metric({
  title,
  value,
}: {
  title: string;
  value: number;
}) {
  return (
    <article className="metric">
      <span>{title}</span>
      <strong>{value}</strong>
      <small>Current displayed assessment</small>
    </article>
  );
}

export default App;
