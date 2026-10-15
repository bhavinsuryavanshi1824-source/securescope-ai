
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from backend.app.database import get_scans, save_scan
from backend.risk_engine.engine import assess_finding
from backend.risk_engine.explanations import explain_finding
from backend.scanner.scanner import validate_target, run_nmap_scan
from backend.reports.report_generator import generate_csv_report
from backend.reports.pdf_generator import generate_pdf_report


app = FastAPI(
    title="SecureScope AI",
    description=(
        "AI-Assisted Network Vulnerability Assessment "
        "and Security Reporting System"
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RealScanRequest(BaseModel):
    target: str


def enrich_finding(finding: dict) -> dict:
    """Add risk assessment, explanation, remediation, and priority."""
    assessed = assess_finding(finding)
    return explain_finding(assessed)


def get_loopback_target(target: str) -> str:
    """Restrict real scans to loopback addresses."""
    try:
        validated_target = validate_target(target)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target: {exc}",
        ) from exc

    if validated_target not in ("127.0.0.1", "::1"):
        raise HTTPException(
            status_code=403,
            detail="Real scans are restricted to 127.0.0.1 or ::1.",
        )

    return validated_target


def build_summary(findings: list[dict]) -> dict:
    """Count findings by risk level."""
    levels = [
        str(item.get("risk_level", "INFO")).upper()
        for item in findings
    ]

    return {
        "total_findings": len(findings),
        "high": sum(
            level in ("HIGH", "CRITICAL") for level in levels
        ),
        "medium": levels.count("MEDIUM"),
        "low": levels.count("LOW"),
        "info": sum(
            level in ("INFO", "INFORMATIONAL") for level in levels
        ),
    }


def save_and_return_scan(target: str, findings: list[dict]) -> dict:
    """Save scan results and return the scan details."""
    scan_id = save_scan(target, findings)

    return {
        "id": scan_id,
        "target": target,
        "findings": findings,
        "summary": build_summary(findings),
    }


def find_saved_scan(scan_id: int) -> dict:
    """Find a saved scan by ID."""
    scans = get_scans()

    selected_scan = next(
        (
            scan for scan in scans
            if str(scan.get("id")) == str(scan_id)
        ),
        None,
    )

    if selected_scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return selected_scan


@app.get("/")
def root():
    return {
        "project": "SecureScope AI",
        "message": (
            "AI-Assisted Network Vulnerability Assessment "
            "and Security Reporting System"
        ),
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/scans")
def scan_history():
    return get_scans()


@app.post("/scans/demo")
def demo_scan():
    """Create a sample assessment without running Nmap."""
    raw_findings = [
        {
            "port": 80,
            "service": "http",
            "encrypted": False,
        },
        {
            "port": 443,
            "service": "https",
            "encrypted": True,
        },
    ]

    findings = [
        enrich_finding(finding)
        for finding in raw_findings
    ]

    return save_and_return_scan("demo-target", findings)


@app.post("/scans/real")
def real_scan(request: RealScanRequest):
    """Run a scan against the local machine only."""
    target = get_loopback_target(request.target)

    try:
        raw_findings = run_nmap_scan(target)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="The scan timed out. Try again later.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {exc}",
        ) from exc

    findings = [
        enrich_finding(finding)
        for finding in raw_findings
    ]

    return save_and_return_scan(target, findings)


@app.get("/scans/{scan_id}/report.csv")
def download_scan_report(scan_id: int):
    """Generate a CSV report for a saved scan."""
    selected_scan = find_saved_scan(scan_id)

    try:
        return generate_csv_report(
            selected_scan["target"],
            selected_scan["findings"],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not generate CSV report: {exc}",
        ) from exc


@app.get("/scans/{scan_id}/report.pdf")
def download_scan_pdf(scan_id: int):
    """Generate and download a PDF report for a saved scan."""
    selected_scan = find_saved_scan(scan_id)

    try:
        pdf_bytes = generate_pdf_report(selected_scan)

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="securescope-report-{scan_id}.pdf"'
                )
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not generate PDF report: {exc}",
        ) from exc
