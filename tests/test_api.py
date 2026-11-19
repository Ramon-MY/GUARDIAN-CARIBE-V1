from datetime import UTC, datetime


def test_auth_lockout_and_logout_revocation(client, auth_headers):
    bad = client.post("/auth/login", json={"username": "testadmin", "password": "wrong-password"})
    assert bad.status_code == 401
    logout = client.post("/auth/logout", headers=auth_headers)
    assert logout.status_code == 204
    assert client.get("/events", headers=auth_headers).status_code == 401


def test_locked_login_attempts_do_not_extend_the_lock(client):
    for _ in range(5):
        response = client.post(
            "/auth/login", json={"username": "testadmin", "password": "wrong-password"}
        )
        assert response.status_code == 401
    response = client.post(
        "/auth/login", json={"username": "testadmin", "password": "test-admin-password-very-long"}
    )
    assert response.status_code == 401


def test_admin_can_create_user_and_viewer_cannot_ingest(client, auth_headers):
    created = client.post(
        "/users",
        headers=auth_headers,
        json={"username": "read_only", "password": "long-unique-password", "role": "viewer"},
    )
    assert created.status_code == 201
    assert "password" not in created.json()
    token = client.post(
        "/auth/login", json={"username": "read_only", "password": "long-unique-password"}
    ).json()["access_token"]
    event = client.post(
        "/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "event_type": "process_start",
            "source": "endpoint-01",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    assert event.status_code == 403


def test_ioc_match_creates_alert_and_filters_events(client, auth_headers):
    indicator = client.post(
        "/indicators",
        headers=auth_headers,
        json={
            "indicator_type": "ip",
            "value": "203.0.113.44",
            "source_name": "Lab feed",
            "confidence": 80,
        },
    )
    assert indicator.status_code == 201
    domain_indicator = client.post(
        "/indicators",
        headers=auth_headers,
        json={"indicator_type": "domain", "value": "example.org", "source_name": "Lab feed"},
    )
    assert domain_indicator.status_code == 201
    payload = {
        "event_type": "connection_observed",
        "source": "edge-firewall",
        "occurred_at": datetime.now(UTC).isoformat(),
        "source_ip": "203.0.113.44",
        "domain": "example.org",
        "severity": "medium",
    }
    ingested = client.post("/events", headers=auth_headers, json=payload)
    assert ingested.status_code == 201
    assert ingested.json()["source_ip"] == "203.0.113.44"
    alerts = client.get("/alerts", headers=auth_headers).json()
    assert len(alerts) == 2
    assert all(alert["rule_id"] == "ioc-match" for alert in alerts)
    filtered = client.get("/events?event_type=connection_observed", headers=auth_headers)
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1


def test_repeated_login_failures_raise_alert(client, auth_headers):
    for _ in range(5):
        event = client.post(
            "/events",
            headers=auth_headers,
            json={
                "event_type": "login_failed",
                "source": "auth-gateway",
                "occurred_at": datetime.now(UTC).isoformat(),
                "source_ip": "198.51.100.21",
            },
        )
        assert event.status_code == 201
    alerts = client.get("/alerts", headers=auth_headers).json()
    assert any(a["rule_id"] == "repeated-login-failures" for a in alerts)


def test_invalid_event_ip_is_rejected(client, auth_headers):
    response = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "connection_observed",
            "source": "edge-firewall",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source_ip": "999.2.3.4",
        },
    )
    assert response.status_code == 422


def test_event_does_not_accept_secret_fields(client, auth_headers):
    response = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "process_start",
            "source": "endpoint-01",
            "occurred_at": datetime.now(UTC).isoformat(),
            "details": {"api_token": "must-not-be-stored"},
        },
    )
    assert response.status_code == 422


def test_custom_rule_incident_notes_and_audit(client, auth_headers):
    rule = client.post(
        "/rules",
        headers=auth_headers,
        json={
            "name": "Suspicious activity",
            "description": "Flag suspicious activity events from endpoints.",
            "field_name": "event_type",
            "operator": "equals",
            "match_value": "suspicious_activity",
            "severity": "critical",
        },
    )
    assert rule.status_code == 201
    event = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "suspicious_activity",
            "source": "endpoint-01",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    assert event.status_code == 201
    alerts = client.get("/alerts", headers=auth_headers).json()
    assert alerts[0]["rule_id"] == f"rule-{rule.json()['id']}"
    incident = client.post(
        "/incidents",
        headers=auth_headers,
        json={
            "title": "Endpoint investigation",
            "description": "Investigate the endpoint activity and collect evidence.",
            "severity": "critical",
            "alert_id": alerts[0]["id"],
        },
    )
    assert incident.status_code == 201
    incident_id = incident.json()["id"]
    transition = client.patch(
        f"/incidents/{incident_id}", headers=auth_headers, json={"status": "investigating"}
    )
    assert transition.status_code == 200
    note = client.post(
        f"/incidents/{incident_id}/notes",
        headers=auth_headers,
        json={"note": "Host isolated in lab."},
    )
    assert note.status_code == 201
    details = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert details.json()["notes"][0]["note"] == "Host isolated in lab."
    assert client.get("/audit", headers=auth_headers).status_code == 200


def test_report_export_escapes_spreadsheet_formulas(client, auth_headers):
    client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "process_start",
            "source": "=SUM(1,1)",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    response = client.get("/reports/export?dataset=events&format=csv", headers=auth_headers)
    assert response.status_code == 200
    assert "'=SUM(1,1)" in response.text


def test_backup_endpoint_returns_a_consistent_sqlite_file(
    client, auth_headers, monkeypatch, tmp_path
):
    from guardian_caribe.main import settings

    monkeypatch.setattr(settings, "backup_directory", str(tmp_path))
    response = client.post("/maintenance/backups", headers=auth_headers)
    assert response.status_code == 200
    assert response.content.startswith(b"SQLite format 3\x00")
    backups = client.get("/maintenance/backups", headers=auth_headers)
    assert backups.status_code == 200
    assert len(backups.json()) == 1
