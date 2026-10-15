
from backend.risk_engine.explanations import explain_finding


def test_telnet_finding_includes_remediation():
    finding = {
        "port": 23,
        "service": "TELNET",
        "risk_level": "HIGH",
        "risk_score": 4,
        "reasons": ["Telnet is not encrypted"],
    }

    result = explain_finding(finding)

    assert "Telnet" in result["explanation"]
    assert "SSH" in result["remediation"]
    assert result["priority"] == "P1"


def test_http_finding_recommends_https():
    finding = {
        "port": 80,
        "service": "HTTP",
        "risk_level": "LOW",
        "risk_score": 1,
        "encrypted": False,
        "reasons": ["HTTP may be unencrypted"],
    }

    result = explain_finding(finding)

    assert "unencrypted" in result["explanation"]
    assert "HTTPS" in result["remediation"]
    assert result["priority"] == "P3"


def test_https_finding_recommends_configuration_review():
    finding = {
        "port": 443,
        "service": "HTTPS",
        "risk_level": "INFO",
        "risk_score": 0,
        "encrypted": True,
        "reasons": [],
    }

    result = explain_finding(finding)

    assert "certificate" in result["remediation"]
    assert result["priority"] == "P4"


def test_unknown_service_gets_generic_guidance():
    finding = {
        "port": 9000,
        "service": "unknown",
        "risk_level": "MEDIUM",
        "risk_score": 2,
        "reasons": [],
    }

    result = explain_finding(finding)

    assert "does not establish a vulnerability" in result["explanation"]
    assert "security updates" in result["remediation"]
    assert result["priority"] == "P2"


def test_original_finding_fields_are_preserved():
    finding = {
        "port": 3389,
        "service": "RDP",
        "risk_level": "HIGH",
        "risk_score": 3,
        "reasons": ["Remote administration service"],
    }

    result = explain_finding(finding)

    assert result["port"] == finding["port"]
    assert result["risk_score"] == finding["risk_score"]
    assert result["reasons"] == finding["reasons"]
    assert "explanation" in result
    assert "remediation" in result
    assert "priority" in result
