# SecureScope AI

**AI-Assisted Network Assessment and Security Reporting Platform**

SecureScope AI is an educational cybersecurity project that combines network port discovery, rule-based risk assessment, assessment history, and CSV reporting in a web dashboard.

## Features

- **Network scanning:** Integrates Nmap for limited TCP port discovery on an authorized target.
- **Risk assessment:** Assigns rule-based risk levels and scores to discovered services.
- **Dashboard:** React and TypeScript interface for viewing findings.
- **Assessment history:** Stores completed assessments in SQLite.
- **CSV reports:** Downloads assessment results for further review.
- **Demo mode:** Provides sample findings without scanning a real network.
- **Automated tests:** Tests API endpoints, database operations, input validation, and risk assessment.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Database | SQLite |
| Network scanning | Nmap |
| Testing | pytest, FastAPI TestClient |

## Project Structure

```text
securescope-ai/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   └── database.py
│   ├── scanner/
│   │   └── scanner.py
│   ├── risk_engine/
│   │   └── engine.py
│   └── reports/
│       └── report_generator.py
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── App.css
├── tests/
├── requirements.txt
├── .gitignore
└── README.md
```

## Prerequisites

- Python
- Node.js and npm
- Nmap installed and available to the backend

## Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd securescope-ai
```

### 2. Set up the Python backend

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the virtual environment's Python executable directly.

Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start the API from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

API documentation: http://127.0.0.1:8000/docs

### 3. Start the frontend

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite.

### 4. Run tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API welcome response |
| GET | `/health` | Health check |
| GET | `/scans` | List saved assessments |
| POST | `/scans/demo` | Generate sample findings |
| POST | `/scans/real` | Run the configured local Nmap assessment |
| GET | `/scans/{scan_id}/report.csv` | Download a CSV report |

## Security and Limitations

- Only scan systems you own or have explicit permission to assess.
- The initial real-scan endpoint is restricted to loopback addresses.
- Demo findings are sample data, not real vulnerability detections.
- Risk scoring is rule-based and should not be treated as a professional security audit.
- Port discovery alone does not establish that a system is vulnerable.
- AI-assisted explanations are a planned enhancement; do not interpret the current rule-based engine as an AI vulnerability detector.

## Future Improvements

- More detailed service detection and scan configuration.
- Additional risk rules and remediation guidance.
- Better scan status and error reporting.
- Expanded automated tests.
- AI-assisted security report summaries.

## Disclaimer

This project is intended for educational and authorized security assessment purposes only.
