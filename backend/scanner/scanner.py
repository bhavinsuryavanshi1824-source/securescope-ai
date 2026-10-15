
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET


def validate_target(target: str) -> str:
    """Accept valid IPv4 or IPv6 addresses only."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise ValueError(
            "Target must be a valid IP address."
        ) from exc


def run_nmap_scan(target: str) -> list[dict]:
    """
    Run a limited TCP port scan against an explicitly authorized IP.

    Returns discovered ports and service information.
    """
    validated_target = validate_target(target)

    nmap_path = shutil.which("nmap")

    # Fallback for the standard Windows installation path.
    if nmap_path is None:
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"

    if not shutil.which("nmap") and nmap_path == "nmap":
        raise RuntimeError(
            "Nmap was not found. Install Nmap or configure its PATH."
        )

    command = [
        nmap_path,
        "-sT",
        "-T3",
        "--top-ports", "100",
        "-oX", "-",
        validated_target,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nmap scan timed out.") from exc
    except OSError as exc:
        raise RuntimeError(
            "Could not start Nmap. Check its installation path."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Nmap scan failed."
        )

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise RuntimeError(
            "Could not parse Nmap's XML output."
        ) from exc

    findings = []

    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            service_name = (
                service.get("name", "unknown")
                if service is not None
                else "unknown"
            )

            findings.append(
                {
                    "port": int(port.get("portid", "0")),
                    "service": service_name.upper(),
                    "encrypted": service_name.lower()
                    in {"https", "ssh", "imaps", "pop3s"},
                }
            )

    return findings


def build_scan_summary(target: str, findings: list[dict]) -> dict:
    """Build a compact summary from discovered findings."""
    return {
        "target": target,
        "total_findings": len(findings),
        "findings": findings,
    }
