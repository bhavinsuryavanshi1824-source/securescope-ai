
"""
Rule-based security explanations and remediation guidance.

This module explains assessment findings. It does not independently
confirm that a vulnerability exists.
"""


def explain_finding(finding: dict) -> dict:
    """
    Enrich a risk-engine finding with an explanation, remediation,
    and suggested remediation priority.

    The original finding fields are preserved.
    """
    result = dict(finding)

    port = result.get("port")
    service = str(result.get("service", "unknown")).strip().lower()
    risk_level = str(result.get("risk_level", "INFO")).upper()
    encrypted = bool(result.get("encrypted", False))

    # Service-specific rules.
    if port == 23 or service == "telnet":
        explanation = (
            "Telnet does not encrypt its session by default. "
            "Credentials and session data may be exposed to someone "
            "who can observe the network traffic."
        )
        remediation = (
            "Disable Telnet where it is not required. Use SSH for "
            "remote administration and restrict management access "
            "to trusted networks."
        )

    elif port == 21 or service == "ftp":
        explanation = (
            "Traditional FTP does not protect credentials and file "
            "contents with encryption by default."
        )
        remediation = (
            "Disable FTP if unnecessary. Prefer SFTP or another "
            "secure file-transfer method, and restrict access "
            "to trusted clients."
        )

    elif port == 445 or service in {"microsoft-ds", "smb"}:
        explanation = (
            "SMB provides file and printer sharing. If exposed to "
            "untrusted networks, it can increase the attack surface."
        )
        remediation = (
            "Block unnecessary SMB access at the firewall. Restrict "
            "port 445 to trusted internal networks and keep the "
            "operating system and SMB configuration updated."
        )

    elif port == 3389 or service in {"ms-wbt-server", "rdp"}:
        explanation = (
            "Remote Desktop enables remote access. An unnecessarily "
            "reachable RDP service may attract password attacks "
            "or exploitation attempts."
        )
        remediation = (
            "Restrict RDP to trusted addresses or a VPN, enable "
            "multi-factor authentication where available, use "
            "strong account protections, and keep the system updated."
        )

    elif port == 80 or service in {"http", "http-alt"}:
        if encrypted:
            explanation = (
                "The service is reported as encrypted, but its "
                "configuration and certificate have not been verified."
            )
            remediation = (
                "Verify the encryption configuration, certificate "
                "validity, and secure protocol settings."
            )
        else:
            explanation = (
                "HTTP traffic is generally unencrypted. Sensitive "
                "information sent over this connection may be exposed "
                "to parties able to observe the traffic."
            )
            remediation = (
                "Use HTTPS with a valid certificate. Redirect HTTP "
                "requests to HTTPS and avoid transmitting credentials "
                "or sensitive information over plaintext connections."
            )

    elif port == 443 or service == "https":
        explanation = (
            "HTTPS normally protects web traffic in transit. An open "
            "HTTPS port alone does not establish that the service is "
            "secure or vulnerable."
        )
        remediation = (
            "Verify the TLS configuration, certificate validity, "
            "supported protocol versions, and application updates."
        )

    elif port == 22 or service == "ssh":
        explanation = (
            "SSH is commonly used for secure remote administration. "
            "An exposed SSH service should be restricted and maintained."
        )
        remediation = (
            "Allow SSH only from trusted addresses where practical. "
            "Prefer key-based authentication, disable unused accounts, "
            "and keep the SSH server updated."
        )

    else:
        explanation = (
            f"Service '{service}' was identified on port {port}. "
            "Port discovery alone does not establish a vulnerability; "
            "the service and its configuration need further review."
        )
        remediation = (
            "Confirm that the service is required, restrict access "
            "to trusted systems, identify its software and version, "
            "and apply relevant security updates."
        )

    # Suggested remediation priority, based on the existing risk engine.
    # This is a workflow recommendation, not a formal severity standard.
    priority_by_risk = {
        "HIGH": "P1",
        "MEDIUM": "P2",
        "LOW": "P3",
        "INFO": "P4",
    }

    result["explanation"] = explanation
    result["remediation"] = remediation
    result["priority"] = priority_by_risk.get(risk_level, "P4")

    return result
