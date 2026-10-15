import pytest

from backend.risk_engine.engine import assess_finding


def test_telnet_without_encryption_is_high_risk():
    result = assess_finding({
        "port": 23,
        "service": "telnet",
        "encrypted": False,
    })

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] == 4


def test_http_without_encryption_is_low_risk():
    result = assess_finding({
        "port": 80,
        "service": "http",
        "encrypted": False,
    })

    assert result["risk_level"] == "LOW"


def test_unknown_service_has_informational_result():
    result = assess_finding({
        "port": 9000,
        "service": "unknown",
        "encrypted": True,
    })

    assert result["risk_level"] == "INFO"


def test_invalid_port_is_rejected():
    with pytest.raises(ValueError):
        assess_finding({
            "port": 70000,
            "service": "unknown",
        })