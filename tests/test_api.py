from datetime import UTC, datetime, timedelta


def test_auth_lockout_and_logout_revocation(client, auth_headers):
    bad = client.post("/auth/login", json={"username": "testadmin", "password": "wrong-password"})
    assert bad.status_code == 401
    logout = client.post("/auth/logout", headers=auth_headers)
    assert logout.status_code == 204
    assert client.get("/events", headers=auth_headers).status_code == 401


def test_locked_login_attempts_do_not_extend_the_lock(client, auth_headers):
    for _ in range(5):
        response = client.post(
            "/auth/login", json={"username": "testadmin", "password": "wrong-password"}
        )
        assert response.status_code == 401
    response = client.post(
        "/auth/login", json={"username": "testadmin", "password": "test-admin-password-very-long"}
    )
    assert response.status_code == 401
    failures = client.get("/events?event_type=login_failed", headers=auth_headers).json()
    assert len(failures) == 6
    assert all(event["source_ip"] == "198.51.100.21" for event in failures)
    alerts = client.get("/alerts?status=new", headers=auth_headers).json()
    assert any(alert["rule_id"] == "repeated-login-failures" for alert in alerts)


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


def test_rate_limit_denials_create_one_cooldown_alert(client, auth_headers, monkeypatch):
    from guardian_caribe.main import rate_limiter

    monkeypatch.setattr(rate_limiter, "limit", 2)
    assert client.get("/events").status_code == 401
    assert client.get("/events").status_code == 429
    assert client.get("/events").status_code == 429
    monkeypatch.setattr(rate_limiter, "limit", 100)
    alerts = client.get("/alerts", headers=auth_headers).json()
    rate_limit_alerts = [alert for alert in alerts if alert["rule_id"] == "request-rate-limit"]
    assert len(rate_limit_alerts) == 1


def test_event_detail_combined_filters_and_unknown_fields(client, auth_headers):
    event = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "web_request",
            "source": "reverse-proxy",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source_ip": "198.51.100.10",
            "destination_ip": "203.0.113.2",
            "domain": "EXAMPLE.org.",
            "url": "https://example.org/login",
            "file_hash": "a" * 64,
        },
    )
    assert event.status_code == 201
    event_id = event.json()["id"]
    assert client.get(f"/events/{event_id}", headers=auth_headers).json()["url"] == (
        "https://example.org/login"
    )
    filtered = client.get(
        "/events?source=reverse-proxy&source_ip=198.51.100.10&destination_ip=203.0.113.2"
        "&domain=example.org&url=https%3A%2F%2Fexample.org%2Flogin&file_hash=" + "a" * 64,
        headers=auth_headers,
    )
    assert filtered.status_code == 200
    assert [item["id"] for item in filtered.json()] == [event_id]
    assert client.get("/events/9999", headers=auth_headers).status_code == 404
    invalid = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "web_request",
            "source": "reverse-proxy",
            "occurred_at": datetime.now(UTC).isoformat(),
            "unmapped_field": "would otherwise be discarded",
        },
    )
    assert invalid.status_code == 422
    validation_logs = client.get("/operations/errors", headers=auth_headers)
    assert validation_logs.status_code == 200
    validation_entry = next(
        item for item in validation_logs.json() if item["details"].get("path") == "/events"
    )
    assert "body.unmapped_field" in validation_entry["details"]["fields"]


def test_url_ioc_exact_search_and_event_correlation(client, auth_headers):
    indicator = client.post(
        "/indicators",
        headers=auth_headers,
        json={
            "indicator_type": "url",
            "value": "https://BAD.example/Path",
            "source_name": "Curated lab list",
        },
    )
    assert indicator.status_code == 201
    found = client.get(
        "/indicators/search?indicator_type=url&value=https%3A%2F%2Fbad.example%2FPath",
        headers=auth_headers,
    )
    assert found.json()["found"] is True
    assert [item["id"] for item in found.json()["matches"]] == [indicator.json()["id"]]
    missing = client.get(
        "/indicators/search?indicator_type=domain&value=missing.example",
        headers=auth_headers,
    )
    assert missing.json()["found"] is False
    assert missing.json()["count"] == 0
    event = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "web_request",
            "source": "proxy",
            "occurred_at": datetime.now(UTC).isoformat(),
            "url": "https://BAD.EXAMPLE/Path",
        },
    )
    assert event.status_code == 201
    alerts = client.get("/alerts", headers=auth_headers).json()
    assert any(
        item["rule_id"] == "ioc-match" and item["event_id"] == event.json()["id"] for item in alerts
    )


def test_event_and_indicator_urls_reject_credential_query_parameters(client, auth_headers):
    event = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "web_request",
            "source": "proxy",
            "occurred_at": datetime.now(UTC).isoformat(),
            "url": "https://example.org/?access_token=secret-value",
        },
    )
    assert event.status_code == 422
    indicator = client.post(
        "/indicators",
        headers=auth_headers,
        json={
            "indicator_type": "url",
            "value": "https://example.org/?api_key=secret-value",
            "source_name": "Test feed",
        },
    )
    assert indicator.status_code == 422


def test_admin_can_change_user_role_and_cannot_remove_last_admin(client, auth_headers):
    created = client.post(
        "/users",
        headers=auth_headers,
        json={"username": "analyst_one", "password": "long-enough-password", "role": "analyst"},
    )
    assert created.status_code == 201
    user_id = created.json()["id"]
    changed = client.patch(f"/users/{user_id}", headers=auth_headers, json={"role": "viewer"})
    assert changed.status_code == 200
    assert changed.json()["role"] == "viewer"
    audit = client.get("/audit?action=user.role_change", headers=auth_headers)
    assert audit.status_code == 200
    assert audit.json()[0]["resource_id"] == str(user_id)
    admin_id = client.get("/users", headers=auth_headers).json()[0]["id"]
    response = client.patch(f"/users/{admin_id}", headers=auth_headers, json={"is_active": False})
    assert response.status_code == 409


def test_password_policy_and_runtime_config_are_admin_controlled(client, auth_headers):
    changed = client.put(
        "/system/config",
        headers=auth_headers,
        json={"password_min_length": 20, "rate_limit_per_minute": 50},
    )
    assert changed.status_code == 200
    assert changed.json()["password_min_length"] == 20
    assert (
        client.post(
            "/users",
            headers=auth_headers,
            json={"username": "short_pass", "password": "sixteen-char-pass", "role": "viewer"},
        ).status_code
        == 422
    )
    created = client.post(
        "/users",
        headers=auth_headers,
        json={"username": "long_pass", "password": "twenty-characters-pass", "role": "viewer"},
    )
    assert created.status_code == 201
    from guardian_caribe.main import rate_limiter

    assert rate_limiter.limit == 50
    reset = client.delete("/system/config/password_min_length", headers=auth_headers)
    assert reset.status_code == 200
    assert reset.json()["password_min_length"] == 12


def test_failed_logins_are_saved_without_credentials(client, auth_headers):
    response = client.post(
        "/auth/login", json={"username": "testadmin", "password": "wrong-secret-value"}
    )
    assert response.status_code == 401
    events = client.get("/events?event_type=login_failed", headers=auth_headers)
    assert events.status_code == 200
    assert len(events.json()) == 1
    assert "wrong-secret-value" not in events.text
    audit = client.get("/audit?action=auth.login_failed", headers=auth_headers)
    assert len(audit.json()) == 1


def test_identical_detection_alerts_are_deduplicated_with_linked_evidence(client, auth_headers):
    rule = client.post(
        "/rules",
        headers=auth_headers,
        json={
            "name": "Repeated suspicious probe",
            "description": "Detect a repeated suspicious probe from the same source.",
            "field_name": "event_type",
            "operator": "equals",
            "match_value": "suspicious_probe",
            "severity": "high",
        },
    )
    assert rule.status_code == 201
    payload = {
        "event_type": "suspicious_probe",
        "source": "edge-sensor",
        "occurred_at": datetime.now(UTC).isoformat(),
        "source_ip": "198.51.100.25",
    }
    first = client.post("/events", headers=auth_headers, json=payload)
    second = client.post("/events", headers=auth_headers, json=payload)
    assert first.status_code == second.status_code == 201
    alerts = client.get("/alerts", headers=auth_headers).json()
    matches = [item for item in alerts if item["rule_id"] == f"rule-{rule.json()['id']}"]
    assert len(matches) == 1
    detail = client.get(f"/alerts/{matches[0]['id']}", headers=auth_headers)
    assert {item["id"] for item in detail.json()["evidence_events"]} == {
        first.json()["id"],
        second.json()["id"],
    }
    distinct = {**payload, "source_ip": "198.51.100.26"}
    client.post("/events", headers=auth_headers, json=distinct)
    alerts = client.get("/alerts", headers=auth_headers).json()
    assert len([item for item in alerts if item["rule_id"] == f"rule-{rule.json()['id']}"]) == 2


def test_alert_transitions_and_severity_changes_are_audited(client, auth_headers):
    client.post(
        "/indicators",
        headers=auth_headers,
        json={"indicator_type": "ip", "value": "198.51.100.44", "source_name": "Test list"},
    )
    client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "login_failed",
            "source": "auth-gateway",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source_ip": "198.51.100.44",
        },
    )
    alert = client.get("/alerts", headers=auth_headers).json()[0]
    updated = client.patch(
        f"/alerts/{alert['id']}",
        headers=auth_headers,
        json={"status": "escalated", "severity": "critical"},
    )
    assert updated.status_code == 200
    assert updated.json()["severity"] == "critical"
    closed = client.patch(f"/alerts/{alert['id']}", headers=auth_headers, json={"status": "closed"})
    assert closed.status_code == 200
    invalid = client.patch(f"/alerts/{alert['id']}", headers=auth_headers, json={"status": "new"})
    assert invalid.status_code == 409
    history = client.get(
        f"/audit?resource_type=alert&resource_id={alert['id']}", headers=auth_headers
    )
    assert history.status_code == 200
    update_entry = next(
        entry
        for entry in history.json()
        if entry["action"] == "alert.update" and "severity" in entry["details"]["after"]
    )
    assert update_entry["details"]["after"]["severity"] == "critical"


def test_reports_accept_period_filters_and_return_filter_metadata(client, auth_headers):
    now = datetime.now(UTC)
    client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "period_test",
            "source": "period-probe",
            "occurred_at": now.isoformat(),
            "severity": "high",
        },
    )
    summary = client.get(
        f"/reports/summary?start={now.isoformat().replace('+', '%2B')}"
        f"&end={(now + timedelta(minutes=1)).isoformat().replace('+', '%2B')}",
        headers=auth_headers,
    )
    assert summary.status_code == 200
    assert summary.json()["events_received"] == 1
    assert "filters_applied" in summary.json()
    exported = client.get(
        f"/reports/export?dataset=events&format=json&start={now.isoformat().replace('+', '%2B')}"
        f"&end={(now + timedelta(minutes=1)).isoformat().replace('+', '%2B')}&severity=high",
        headers=auth_headers,
    )
    assert exported.status_code == 200
    assert exported.headers["x-report-generated-at"]
    assert '"severity": "high"' in exported.headers["x-report-filters"]
    assert len(exported.json()) == 1


def test_dashboard_window_and_alert_assignment_workflow(client, auth_headers):
    created_user = client.post(
        "/users",
        headers=auth_headers,
        json={"username": "on_call_analyst", "password": "long-enough-password", "role": "analyst"},
    )
    assert created_user.status_code == 201
    indicator = client.post(
        "/indicators",
        headers=auth_headers,
        json={"indicator_type": "ip", "value": "203.0.113.63", "source_name": "Lab list"},
    )
    assert indicator.status_code == 201
    event = client.post(
        "/events",
        headers=auth_headers,
        json={
            "event_type": "connection_observed",
            "source": "test-sensor",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source_ip": "203.0.113.63",
        },
    )
    assert event.status_code == 201
    alert = client.get("/alerts", headers=auth_headers).json()[0]
    assigned = client.patch(
        f"/alerts/{alert['id']}",
        headers=auth_headers,
        json={"assigned_to_id": created_user.json()["id"]},
    )
    assert assigned.status_code == 200
    assert assigned.json()["assigned_to_id"] == created_user.json()["id"]
    for status in ("investigating", "escalated", "closed"):
        response = client.patch(
            f"/alerts/{alert['id']}", headers=auth_headers, json={"status": status}
        )
        assert response.status_code == 200
    dashboard = client.get("/analytics/summary?hours=1", headers=auth_headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["window_hours"] == 1
    assert dashboard.json()["events_received"] >= 1


def test_normalized_batch_apis_ingest_events_and_threat_indicators(client, auth_headers):
    existing = client.post(
        "/indicators",
        headers=auth_headers,
        json={"indicator_type": "domain", "value": "feed.example", "source_name": "Batch feed"},
    )
    assert existing.status_code == 201
    indicators = client.post(
        "/integrations/indicators",
        headers=auth_headers,
        json={
            "indicators": [
                {
                    "indicator_type": "domain",
                    "value": "feed.example",
                    "source_name": "Batch feed",
                },
                {
                    "indicator_type": "url",
                    "value": "https://feed.example/path",
                    "source_name": "Batch feed",
                },
            ]
        },
    )
    assert indicators.status_code == 202
    assert indicators.json()["created_count"] == 1
    assert indicators.json()["skipped_existing_count"] == 1
    events = client.post(
        "/integrations/events",
        headers=auth_headers,
        json={
            "events": [
                {
                    "event_type": "web_request",
                    "source": "batch-sensor",
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "domain": "feed.example",
                    "url": "https://feed.example/path",
                },
                {
                    "event_type": "connection_observed",
                    "source": "batch-sensor",
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
            ]
        },
    )
    assert events.status_code == 202
    assert events.json()["accepted_count"] == 2
    assert all(item["id"] for item in events.json()["events"])
    alerts = client.get("/alerts", headers=auth_headers).json()
    assert any(alert["rule_id"] == "ioc-match" for alert in alerts)


def test_unhandled_errors_are_recorded_for_admin_review(client, auth_headers, monkeypatch):
    import guardian_caribe.main as main

    client.raise_server_exceptions = False
    monkeypatch.setattr(main, "decode_access_token", lambda *_args: 1 / 0)
    failed = client.get("/events", headers=auth_headers)
    assert failed.status_code == 500
    monkeypatch.undo()
    errors = client.get("/operations/errors", headers=auth_headers)
    assert errors.status_code == 200
    assert errors.json()[0]["details"]["error_type"] == "ZeroDivisionError"
    assert "authorization" not in errors.text.lower()
