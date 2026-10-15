from typing import Any


RISK_LEVELS = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def assess_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Classify a security finding using transparent rules.

    This is a preliminary triage score, not a confirmed
    vulnerability assessment.
    """
    port = finding.get("port")
    service = str(finding.get("service", "unknown")).lower()
    encrypted = finding.get("encrypted", False)

    reasons = []
    score = 0

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")

    if port in {21, 23, 445, 3389}:
        score += 2
        reasons.append("Service commonly requiring careful access controls")

    if service in {"telnet", "ftp"} and not encrypted:
        score += 2
        reasons.append("Service may transmit data without encryption")

    if port in {80, 8080} and not encrypted:
        score += 1
        reasons.append("Unencrypted web service may expose traffic")

    if score >= 3:
        level = "HIGH"
    elif score >= 2:
        level = "MEDIUM"
    elif score >= 1:
        level = "LOW"
    else:
        level = "INFO"

    return {
        "port": port,
        "service": service,
        "risk_level": level,
        "risk_score": score,
        "reasons": reasons or ["No risk condition matched the current rules"],
    }