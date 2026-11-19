import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Literal
from urllib.parse import parse_qsl, urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardian_caribe.config import get_settings


def normalize_http_url(value: str, label: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not contain embedded credentials")
    if any(
        marker in key.lower()
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
        for marker in ("token", "secret", "password", "credential", "api_key", "authorization")
    ):
        raise ValueError(f"{label} must not contain credential query parameters")
    return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)
    role: Literal["admin", "analyst", "viewer"] = "analyst"

    @field_validator("password")
    @classmethod
    def validate_password_policy(cls, value: str) -> str:
        if len(value) < get_settings().password_min_length:
            raise ValueError(
                f"password must contain at least {get_settings().password_min_length} characters"
            )
        return value


class UserUpdate(BaseModel):
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None

    @field_validator("role", "is_active")
    @classmethod
    def require_a_change(cls, value):
        if value is None:
            raise ValueError("value cannot be null")
        return value


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime


class TokenRead(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    source: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    severity: Literal["low", "medium", "high", "critical"] = "low"
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = Field(default=None, max_length=253)
    url: str | None = Field(default=None, max_length=2048)
    file_hash: str | None = Field(default=None, max_length=128)
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict, max_length=40)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        return str(ip_address(value)) if value is not None else None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().rstrip(".").lower()
        if (
            not value
            or len(value) > 253
            or not re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                value,
            )
        ):
            raise ValueError("domain must be a valid hostname")
        return value

    @field_validator("file_hash")
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower()
        if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", normalized):
            raise ValueError("file_hash must be MD5, SHA-1, or SHA-256")
        return normalized

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_http_url(value, "url")

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("occurred_at cannot be more than five minutes in the future")
        return value

    @field_validator("details")
    @classmethod
    def reject_sensitive_detail_keys(cls, value: dict) -> dict:
        sensitive = (
            "password",
            "passwd",
            "token",
            "secret",
            "api_key",
            "private_key",
            "authorization",
            "credential",
        )
        if any(any(marker in key.lower() for marker in sensitive) for key in value):
            raise ValueError("details must not contain credentials or secrets")
        return value


class EventBatchCreate(BaseModel):
    events: list[EventCreate] = Field(min_length=1, max_length=500)


class EventRead(BaseModel):
    id: int
    event_type: str
    source: str
    occurred_at: datetime
    received_at: datetime
    severity: str
    source_ip: str | None
    destination_ip: str | None
    domain: str | None
    url: str | None
    file_hash: str | None
    details: dict


class IndicatorCreate(BaseModel):
    indicator_type: Literal["ip", "domain", "url", "hash"]
    value: str = Field(min_length=1, max_length=2048)
    source_name: str = Field(min_length=2, max_length=128)
    source_url: str | None = Field(default=None, max_length=512)
    confidence: int = Field(default=50, ge=0, le=100)
    first_seen: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info):
        kind = info.data.get("indicator_type")
        value = value.strip()
        if kind != "url":
            value = value.lower()
        if kind == "ip":
            return str(ip_address(value))
        if kind == "hash" and not re.fullmatch(
            r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value
        ):
            raise ValueError("hash indicator must be MD5, SHA-1, or SHA-256")
        if kind == "url":
            return normalize_http_url(value, "URL indicator")
        if kind == "domain" and not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            value,
        ):
            raise ValueError("domain indicator must be a valid hostname")
        return value

    @field_validator("source_url")
    @classmethod
    def require_https_source(cls, value: str | None) -> str | None:
        if value is not None and (
            urlparse(value).scheme != "https" or not urlparse(value).hostname
        ):
            raise ValueError("source_url must use HTTPS")
        return value


class IndicatorBatchCreate(BaseModel):
    indicators: list[IndicatorCreate] = Field(min_length=1, max_length=500)


class IndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    indicator_type: str
    value: str
    source_name: str
    source_url: str | None
    confidence: int
    first_seen: datetime | None
    expires_at: datetime | None


class AlertRead(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    rule_id: str
    event_id: int | None
    indicator_id: int | None
    assigned_to_id: int | None
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    status: Literal["new", "investigating", "escalated", "closed"] | None = None
    assigned_to_id: int | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None


class DetectionRuleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=8, max_length=1000)
    field_name: Literal[
        "event_type",
        "source",
        "severity",
        "source_ip",
        "destination_ip",
        "domain",
        "url",
        "file_hash",
    ]
    operator: Literal["equals", "contains"] = "equals"
    match_value: str = Field(min_length=1, max_length=256)
    severity: Literal["low", "medium", "high", "critical"] = "medium"

    @field_validator("name", "match_value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be empty")
        return value


class DetectionRuleUpdate(BaseModel):
    enabled: bool | None = None
    description: str | None = Field(default=None, min_length=8, max_length=1000)
    severity: Literal["low", "medium", "high", "critical"] | None = None


class DetectionRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    field_name: str
    operator: str
    match_value: str
    severity: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=8, max_length=4000)
    severity: Literal["low", "medium", "high", "critical"]
    alert_id: int | None = None


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved", "closed"] | None = None
    assigned_to_id: int | None = None


class IncidentNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


class IncidentNoteRead(BaseModel):
    id: int
    incident_id: int
    author_id: int
    author_username: str
    note: str
    created_at: datetime


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    description: str
    severity: str
    status: str
    alert_id: int | None
    created_by_id: int
    assigned_to_id: int | None
    created_at: datetime
    updated_at: datetime


class RuntimeConfigUpdate(BaseModel):
    password_min_length: int | None = Field(default=None, ge=12, le=128)
    max_login_attempts: int | None = Field(default=None, ge=3, le=20)
    login_lock_minutes: int | None = Field(default=None, ge=1, le=1440)
    brute_force_window_minutes: int | None = Field(default=None, ge=1, le=1440)
    brute_force_threshold: int | None = Field(default=None, ge=3, le=100)
    alert_dedupe_minutes: int | None = Field(default=None, ge=1, le=1440)
    rate_limit_per_minute: int | None = Field(default=None, ge=10, le=10000)

    @field_validator(
        "password_min_length",
        "max_login_attempts",
        "login_lock_minutes",
        "brute_force_window_minutes",
        "brute_force_threshold",
        "alert_dedupe_minutes",
        "rate_limit_per_minute",
    )
    @classmethod
    def reject_null_overrides(cls, value):
        if value is None:
            raise ValueError("configuration values cannot be null")
        return value
