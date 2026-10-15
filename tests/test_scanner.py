import pytest

from backend.scanner.scanner import build_scan_summary, validate_target


def test_validate_ipv4_target():
    assert validate_target("192.168.1.10") == "192.168.1.10"


def test_validate_ipv6_target():
    assert validate_target("::1") == "::1"


def test_invalid_target_is_rejected():
    with pytest.raises(ValueError):
        validate_target("not-an-ip-address")


def test_scan_summary_counts_findings():
    result = build_scan_summary(
        "127.0.0.1",
        [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
        ],
    )

    assert result["target"] == "127.0.0.1"
    assert result["total_findings"] == 2



from unittest.mock import patch, MagicMock

import pytest

from backend.scanner.scanner import run_nmap_scan


def test_nmap_parses_open_port():
    fake_xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https"/>
          </port>
          <port protocol="tcp" portid="8080">
            <state state="closed"/>
            <service name="http-proxy"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = fake_xml
    fake_result.stderr = ""

    with patch(
        "backend.scanner.scanner.subprocess.run",
        return_value=fake_result,
    ):
        with patch(
            "backend.scanner.scanner.shutil.which",
            return_value=r"C:\Program Files (x86)\Nmap\nmap.exe",
        ):
            findings = run_nmap_scan("127.0.0.1")

    assert len(findings) == 1
    assert findings[0]["port"] == 443
    assert findings[0]["service"] == "HTTPS"


def test_nmap_rejects_invalid_target():
    with pytest.raises(ValueError):
        run_nmap_scan("not-an-ip-address")


def test_nmap_handles_timeout():
    import subprocess

    with patch(
        "backend.scanner.scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired("nmap", 90),
    ):
        with patch(
            "backend.scanner.scanner.shutil.which",
            return_value=r"C:\Program Files (x86)\Nmap\nmap.exe",
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                run_nmap_scan("127.0.0.1")
