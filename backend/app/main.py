
import ipaddress

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from backend.app.database import get_scans, save_scan
from backend.risk_engine.engine import assess_finding
from backend.scanner.scanner import (
    validate_target,
    run_nmap_scan,
)
from backend.reports.report_generator import generate_csv_report


app = FastAPI(
    title="SecureScope AI",
    description=(
        "AI-assisted network assessment "
        "and security reporting system."
    ),
    version="1.0.0",
)


# Allow the local React frontend to communicate with the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RealScanRequest(BaseModel):
    target: str


@app.get("/")
def home():
    return {
        "project": "SecureScope AI",
        "message": "Welcome to SecureScope AI",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/scans")
def list_scans():
    """Return saved assessments."""
    return get_scans()


@app.post("/scans/demo")
def run_demo_assessment():
    """Create a demonstration assessment; no real scan is performed."""
    target = "demo.local"

    demo_findings = [
        {
            "port": 80,
            "service": "HTTP",
            "encrypted": False,
        },
        {
            "port": 443,
            "service": "HTTPS",
            "encrypted": True,
        },
    ]

    try:
        assessed_findings = [
            assess_finding(finding)
            for finding in demo_findings
        ]

        save_scan(
            target=target,
            findings=assessed_findings,
        )

        return {
            "message": "Demo assessment completed successfully",
            "target": target,
            "total_findings": len(assessed_findings),
            "findings": assessed_findings,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Demo assessment failed: {exc}",
        ) from exc


@app.post("/scans/real")
def run_real_assessment(request: RealScanRequest):
    """
    Perform a limited Nmap scan of the local computer only.
    """
    try:
        target = validate_target(request.target)
        parsed_ip = ipaddress.ip_address(target)

        # Restrict initial integration testing to loopback.
        if not parsed_ip.is_loopback:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Initial testing is limited to localhost "
                    "(127.0.0.1 or ::1)."
                ),
            )

        raw_findings = run_nmap_scan(target)

        assessed_findings = [
            assess_finding(finding)
            for finding in raw_findings
        ]

        save_scan(
            target=target,
            findings=assessed_findings,
        )

        return {
            "message": "Local assessment completed successfully",
            "target": target,
            "total_findings": len(assessed_findings),
            "findings": assessed_findings,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


@app.get("/scans/{scan_id}/report.csv")
def download_scan_report(scan_id: int):
    """Download a CSV report for a saved assessment."""
    scans = get_scans()

    selected_scan = next(
        (
            scan
            for scan in scans
            if int(scan.get("id", -1)) == scan_id
        ),
        None,
    )

    if selected_scan is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found",
        )

    csv_content = generate_csv_report(selected_scan)

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="securescope_scan_{scan_id}.csv"'
            )
        },
    )
