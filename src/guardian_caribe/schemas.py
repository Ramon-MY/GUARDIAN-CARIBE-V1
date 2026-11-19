import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "analyst", "viewer"] = "analyst"


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
    event_type: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    source: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    severity: Literal["low", "medium", "high", "critical"] = "low"
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = Field(default=None, max_length=253)
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
    file_hash: str | None
    details: dict


class IndicatorCreate(BaseModel):
    indicator_type: Literal["ip", "domain", "hash"]
    value: str = Field(min_length=1, max_length=253)
    source_name: str = Field(min_length=2, max_length=128)
    source_url: str | None = Field(default=None, max_length=512)
    confidence: int = Field(default=50, ge=0, le=100)
    first_seen: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info):
        kind = info.data.get("indicator_type")
        value = value.strip().lower()
        if kind == "ip":
            return str(ip_address(value))
        if kind == "hash" and not re.fullmatch(
            r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value
        ):
            raise ValueError("hash indicator must be MD5, SHA-1, or SHA-256")
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
