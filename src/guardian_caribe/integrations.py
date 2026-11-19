"""Read-only MISP and TAXII threat-intelligence ingestion."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import ValidationError

from guardian_caribe.config import Settings
from guardian_caribe.schemas import IndicatorCreate

MAX_RESPONSE_BYTES = 5_000_000
_TAXII_ACCEPT = "application/taxii+json;version=2.1"
_STIX_PATTERN = re.compile(
    r"""^\[\s*(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|"""
    r"""file:hashes\.'(?:MD5|SHA-1|SHA-256)'|file:hashes\.(?:'MD5'|'SHA-1'|'SHA-256'))"""
    r"""\s*=\s*'([^'\\]+)'\s*\]$""",
    re.IGNORECASE,
)


class IntegrationError(Exception):
    """Safe error code for an external integration failure; never contains response data."""


def _configured_https_url(value: str | None, name: str) -> str:
    if not value:
        raise IntegrationError(f"{name}_not_configured")
    try:
        parsed = urlsplit(value.strip())
        valid_port = parsed.port is None or 1 <= parsed.port <= 65535
    except ValueError:
        valid_port = False
        parsed = urlsplit("")
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not valid_port
    ):
        raise IntegrationError(f"{name}_invalid_url")
    return value.strip().rstrip("/")


def _timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            return datetime.fromtimestamp(float(value), UTC)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC)
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _make_indicator(
    indicator_type: str,
    value: str,
    source_name: str,
    source_url: str,
    confidence: Any = 50,
    first_seen: Any = None,
    expires_at: Any = None,
) -> IndicatorCreate | None:
    first = _timestamp(first_seen)
    expiry = _timestamp(expires_at)
    if first is not None and expiry is not None and expiry <= first:
        return None
    try:
        return IndicatorCreate.model_validate(
            {
                "indicator_type": indicator_type,
                "value": value,
                "source_name": source_name,
                "source_url": source_url,
                "confidence": confidence if isinstance(confidence, int) else 50,
                "first_seen": first,
                "expires_at": expiry,
            }
        )
    except (ValidationError, TypeError, ValueError):
        return None


def _request_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    provider: str,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    params: dict[str, str | int] | None = None,
) -> dict[str, Any]:
    try:
        with client.stream(
            method,
            url,
            headers=headers,
            json=json_body,
            params=params,
            follow_redirects=False,
        ) as response:
            if not 200 <= response.status_code < 300:
                raise IntegrationError(f"{provider}_http_{response.status_code}")
            content = bytearray()
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise IntegrationError(f"{provider}_response_too_large")
    except IntegrationError:
        raise
    except httpx.HTTPError:
        raise IntegrationError(f"{provider}_network_error") from None
    try:
        body = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError(f"{provider}_invalid_json") from None
    if not isinstance(body, dict):
        raise IntegrationError(f"{provider}_invalid_response")
    return body


def _new_client(settings: Settings) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(settings.integration_timeout_seconds),
        verify=True,
        follow_redirects=False,
        trust_env=False,
    )


def _misp_attributes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    response = payload.get("response", payload)
    if isinstance(response, dict):
        attributes = response.get("Attribute", response.get("attributes", []))
        if isinstance(attributes, dict):
            attributes = [attributes]
        return [item for item in attributes if isinstance(item, dict)]
    if isinstance(response, list):
        result = []
        for item in response:
            if not isinstance(item, dict):
                continue
            attribute = item.get("Attribute", item)
            if isinstance(attribute, dict):
                result.append(attribute)
        return result
    raise IntegrationError("misp_invalid_response")


def _from_misp(attribute: dict[str, Any], source_url: str) -> IndicatorCreate | None:
    if attribute.get("to_ids") in (False, 0, "0", "false", "False"):
        return None
    value = attribute.get("value")
    kind = str(attribute.get("type", "")).lower()
    type_map = {
        "ip-src": "ip",
        "ip-dst": "ip",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
    }
    indicator_type = type_map.get(kind)
    if not indicator_type or not isinstance(value, str):
        return None
    return _make_indicator(
        indicator_type,
        value,
        "MISP",
        source_url,
        confidence=attribute.get("confidence", 70),
        first_seen=attribute.get("first_seen") or attribute.get("timestamp"),
    )


def fetch_misp_indicators(
    settings: Settings, client: httpx.Client | None = None
) -> list[IndicatorCreate]:
    base_url = _configured_https_url(settings.misp_url, "misp")
    if not settings.misp_api_key or not settings.misp_api_key.get_secret_value():
        raise IntegrationError("misp_api_key_not_configured")
    endpoint = urljoin(base_url + "/", "attributes/restSearch")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": settings.misp_api_key.get_secret_value(),
    }
    owns_client = client is None
    active_client = client or _new_client(settings)
    results: list[IndicatorCreate] = []
    try:
        for page in range(1, settings.misp_max_pages + 1):
            payload = _request_json(
                active_client,
                "POST",
                endpoint,
                provider="misp",
                headers=headers,
                json_body={
                    "returnFormat": "json",
                    "type": ["ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha1", "sha256"],
                    "to_ids": True,
                    "limit": settings.misp_page_size,
                    "page": page,
                },
            )
            attributes = _misp_attributes(payload)
            results.extend(
                item
                for attribute in attributes
                if (item := _from_misp(attribute, base_url)) is not None
            )
            if len(attributes) < settings.misp_page_size:
                break
            if page == settings.misp_max_pages:
                raise IntegrationError("misp_page_limit_reached")
    finally:
        if owns_client:
            active_client.close()
    return results


def _from_stix(obj: dict[str, Any], source_url: str) -> IndicatorCreate | None:
    if obj.get("type") != "indicator":
        return None
    pattern = obj.get("pattern")
    if not isinstance(pattern, str):
        return None
    match = _STIX_PATTERN.fullmatch(pattern)
    if not match:
        return None
    path, value = match.groups()
    path = path.lower()
    if path.startswith(("ipv4-addr:", "ipv6-addr:")):
        indicator_type = "ip"
    elif path == "domain-name:value":
        indicator_type = "domain"
    elif path == "url:value":
        indicator_type = "url"
    else:
        indicator_type = "hash"
    return _make_indicator(
        indicator_type,
        value,
        "OpenCTI TAXII",
        source_url,
        confidence=obj.get("confidence", 50),
        first_seen=obj.get("valid_from"),
        expires_at=obj.get("valid_until"),
    )


def fetch_taxii_indicators(
    settings: Settings, client: httpx.Client | None = None
) -> list[IndicatorCreate]:
    root = _configured_https_url(settings.taxii_api_root, "taxii")
    collection_id = settings.taxii_collection_id
    if not collection_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", collection_id):
        raise IntegrationError("taxii_collection_not_configured")
    endpoint = urljoin(root + "/", f"collections/{collection_id}/objects/")
    headers = {"Accept": _TAXII_ACCEPT}
    if settings.taxii_bearer_token and settings.taxii_bearer_token.get_secret_value():
        headers["Authorization"] = f"Bearer {settings.taxii_bearer_token.get_secret_value()}"
    owns_client = client is None
    active_client = client or _new_client(settings)
    results: list[IndicatorCreate] = []
    next_token: str | None = None
    try:
        for page in range(settings.taxii_max_pages):
            params: dict[str, str | int] = {\n                "limit": settings.taxii_page_size,\n                "match[type]": "indicator",\n            }
            if next_token:
                params["next"] = next_token
            payload = _request_json(
                active_client,
                "GET",
                endpoint,
                provider="taxii",
                headers=headers,
                params=params,
            )
            objects = payload.get("objects")
            if not isinstance(objects, list):
                raise IntegrationError("taxii_invalid_response")
            results.extend(
                item
                for obj in objects
                if isinstance(obj, dict)
                if (item := _from_stix(obj, root)) is not None
            )
            if not payload.get("more"):
                break
            next_token = payload.get("next")
            if not isinstance(next_token, str) or not next_token or len(next_token) > 2048:
                raise IntegrationError("taxii_invalid_pagination")
            if page == settings.taxii_max_pages - 1:
                raise IntegrationError("taxii_page_limit_reached")
    finally:
        if owns_client:
            active_client.close()
    return results
