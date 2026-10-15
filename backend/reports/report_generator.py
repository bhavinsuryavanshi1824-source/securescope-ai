import csv
import io
from typing import Any


def generate_csv_report(
    target: str,
    findings: list[dict[str, Any]],
) -> str:
    """Generate a CSV report from assessed security findings."""
    output = io.StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow([
        "Target",
        "Port",
        "Service",
        "Risk Level",
        "Risk Score",
        "Reasons",
    ])

    for finding in findings:
        writer.writerow([
            target,
            finding.get("port", ""),
            finding.get("service", "unknown"),
            finding.get("risk_level", "INFO"),
            finding.get("risk_score", 0),
            "; ".join(finding.get("reasons", [])),
        ])

    return output.getvalue()