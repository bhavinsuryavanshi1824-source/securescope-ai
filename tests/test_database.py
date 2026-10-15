from backend.app.database import get_scans, save_scan


def test_save_and_retrieve_scan(tmp_path):
    db_path = tmp_path / "test_scans.db"

    findings = [
        {
            "port": 80,
            "service": "http",
            "risk_level": "LOW",
        }
    ]

    scan_id = save_scan(
        "127.0.0.1",
        findings,
        db_path=db_path,
    )

    scans = get_scans(db_path=db_path)

    assert scan_id == 1
    assert len(scans) == 1
    assert scans[0]["target"] == "127.0.0.1"
    assert scans[0]["findings"] == findings


def test_empty_database_returns_empty_list(tmp_path):
    db_path = tmp_path / "empty_scans.db"

    scans = get_scans(db_path=db_path)

    assert scans == []