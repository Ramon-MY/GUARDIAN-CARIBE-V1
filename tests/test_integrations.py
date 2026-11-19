import json

import pytest
from httpx import Client, MockTransport, Response

from guardian_caribe.config import Settings
from guardian_caribe.integrations import (
    IntegrationError,
    fetch_misp_indicators,
    fetch_taxii_indicators,
)


def make_settings(**overrides):
    return Settings(**overrides)


def test_misp_sync_maps_supported_attributes_and_skips_non_iocs():
    def handler(request):
        assert request.method == "POST"
        assert request.url == "https://misp.example.test/attributes/restSearch"
        assert request.headers["Authorization"] == "misp-test-key"
        payload = json.loads(request.content)
        assert payload["to_ids"] is True
        return Response(
            200,
            json={
                "response": [
                    {
                        "Attribute": {
                            "type": "ip-dst",
                            "value": "203.0.113.15",
                            "to_ids": True,
                            "timestamp": 1794787200,
                        }
                    },
                    {
                        "Attribute": {
                            "type": "domain",
                            "value": "Threat.Example",
                            "to_ids": True,
                        }
                    },
                    {
                        "Attribute": {
                            "type": "url",
                            "value": "https://example.test/CasePath",
                            "to_ids": False,
                        }
                    },
                    {
                        "Attribute": {
                            "type": "comment",
                            "value": "not an indicator",
                            "to_ids": True,
                        }
                    },
                ]
            },
        )

    settings = make_settings(
        MISP_URL="https://misp.example.test",
        MISP_API_KEY="misp-test-key",
        MISP_PAGE_SIZE=100,
        MISP_MAX_PAGES=2,
    )
    with Client(transport=MockTransport(handler)) as client:
        indicators = fetch_misp_indicators(settings, client)

    assert [(item.indicator_type, item.value) for item in indicators] == [
        ("ip", "203.0.113.15"),
        ("domain", "threat.example"),
    ]
    assert all(item.source_name == "MISP" for item in indicators)


def test_misp_rejects_http_endpoint_without_sending_credentials():
    settings = make_settings(MISP_URL="http://misp.example.test", MISP_API_KEY="secret")
    called = False

    def handler(request):
        nonlocal called
        called = True
        return Response(200, json={"response": []})

    with (
        Client(transport=MockTransport(handler)) as client,
        pytest.raises(IntegrationError, match="misp_invalid_url"),
    ):
        fetch_misp_indicators(settings, client)

    assert called is False


def test_misp_error_does_not_expose_api_key_or_response_body():
    settings = make_settings(MISP_URL="https://misp.example.test", MISP_API_KEY="secret-key")

    def handler(_request):
        return Response(401, text="secret-key is invalid")

    with (
        Client(transport=MockTransport(handler)) as client,
        pytest.raises(IntegrationError) as error,
    ):
        fetch_misp_indicators(settings, client)

    assert str(error.value) == "misp_http_401"
    assert "secret-key" not in str(error.value)


def test_taxii_sync_follows_pagination_and_maps_simple_stix_indicators():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Accept"] == "application/taxii+json;version=2.1"
        assert request.headers["Authorization"] == "Bearer taxii-test-token"
        if request.url.params.get("next") == "page-two":
            return Response(
                200,
                json={
                    "objects": [
                        {
                            "type": "indicator",
                            "pattern": "[domain-name:value = 'malware.example']",
                            "valid_from": "2026-11-01T00:00:00Z",
                            "valid_until": "2026-12-01T00:00:00Z",
                            "confidence": 85,
                        },
                        {
                            "type": "indicator",
                            "pattern": "[domain-name:value = 'unsupported.example'] AND "
                            "[ipv4-addr:value = '203.0.113.4']",
                        },
                    ],
                    "more": False,
                },
            )
        return Response(200, json={"objects": [], "more": True, "next": "page-two"})

    settings = make_settings(
        TAXII_API_ROOT="https://opencti.example.test/taxii2/root",
        TAXII_COLLECTION_ID="collection-123",
        TAXII_BEARER_TOKEN="taxii-test-token",
        TAXII_PAGE_SIZE=100,
        TAXII_MAX_PAGES=3,
    )
    with Client(transport=MockTransport(handler)) as client:
        indicators = fetch_taxii_indicators(settings, client)

    assert len(requests) == 2
    assert [request.url.params.get("next") for request in requests] == [None, "page-two"]
    assert [(item.indicator_type, item.value) for item in indicators] == [
        ("domain", "malware.example")
    ]
    assert indicators[0].confidence == 85
    assert indicators[0].source_name == "OpenCTI TAXII"


def test_taxii_rejects_missing_collection_without_network_request():
    settings = make_settings(TAXII_API_ROOT="https://opencti.example.test/taxii2/root")
    called = False

    def handler(request):
        nonlocal called
        called = True
        return Response(200, json={"objects": [], "more": False})

    with (
        Client(transport=MockTransport(handler)) as client,
        pytest.raises(IntegrationError, match="taxii_collection_not_configured"),
    ):
        fetch_taxii_indicators(settings, client)

    assert called is False


def test_taxii_stops_at_page_limit_instead_of_returning_partial_data():
    def handler(_request):
        return Response(200, json={"objects": [], "more": True, "next": "page-two"})

    settings = make_settings(
        TAXII_API_ROOT="https://opencti.example.test/taxii2/root",
        TAXII_COLLECTION_ID="collection-123",
        TAXII_MAX_PAGES=1,
    )
    with (
        Client(transport=MockTransport(handler)) as client,
        pytest.raises(IntegrationError, match="taxii_page_limit_reached"),
    ):
        fetch_taxii_indicators(settings, client)
