import csv
import io
import json
import logging
import os
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import and_, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from guardian_caribe.config import get_settings
from guardian_caribe.db import Base, SessionLocal, engine, get_db
from guardian_caribe.models import (
    Alert,
    AuditLog,
    DetectionRule,
    Incident,
    IncidentNote,
    Indicator,
    RevokedToken,
    SecurityEvent,
    User,
    utcnow,
)
from guardian_caribe.schemas import (
    AlertRead,
    AlertUpdate,
    DetectionRuleCreate,
    DetectionRuleRead,
    DetectionRuleUpdate,
    EventCreate,
    EventRead,
    IncidentCreate,
    IncidentNoteCreate,
    IncidentNoteRead,
    IncidentRead,
    IncidentUpdate,
    IndicatorCreate,
    IndicatorRead,
    LoginRequest,
    TokenRead,
    UserCreate,
    UserRead,
)
from guardian_caribe.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    safe_compare_password,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("guardian_caribe")
settings = get_settings()
bearer = HTTPBearer(auto_error=False)


def _ensure_aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class LocalRateLimiter:
    """Per-process limiter for the single-instance prototype; use a shared store in production."""

    def __init__(self, limit: int):
        self.limit = limit
        self.requests: dict[str, deque[float]] = defaultdict(deque)
        self.reported: dict[str, float] = {}
        self.lock = threading.Lock()
        self.denials = 0

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            if key not in self.requests and len(self.requests) >= 10_000:
                stale_keys = [
                    ip
                    for ip, entries in self.requests.items()
                    if not entries or entries[-1] <= now - 60
                ]
                for stale_key in stale_keys:
                    del self.requests[stale_key]
                if len(self.requests) >= 10_000:
                    self.denials += 1
                    return False
            bucket = self.requests[key]
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                self.denials += 1
                return False
            bucket.append(now)
            return True

    def should_report(self, key: str, cooldown_seconds: int = 300) -> bool:
        now = time.monotonic()
        with self.lock:
            last = self.reported.get(key)
            if last is not None and now - last < cooldown_seconds:
                return False
            if key not in self.reported and len(self.reported) >= 10_000:
                stale_keys = [
                    address
                    for address, reported_at in self.reported.items()
                    if reported_at <= now - cooldown_seconds
                ]
                for stale_key in stale_keys:
                    del self.reported[stale_key]
                if len(self.reported) >= 10_000:
                    return False
            self.reported[key] = now
            return True


rate_limiter = LocalRateLimiter(settings.rate_limit_per_minute)


def create_app() -> FastAPI:
    def initialize() -> None:
        settings.validate_runtime()
        Base.metadata.create_all(bind=engine)
        if bool(settings.bootstrap_admin_username) != bool(settings.bootstrap_admin_password):
            raise RuntimeError(
                "Configura ambos valores BOOTSTRAP_ADMIN_USERNAME y BOOTSTRAP_ADMIN_PASSWORD."
            )
        with SessionLocal() as db:
            if settings.bootstrap_admin_username and settings.bootstrap_admin_password:
                exists = db.scalar(
                    select(User.id).where(User.username == settings.bootstrap_admin_username)
                )
                if exists is None:
                    db.add(
                        User(
                            username=settings.bootstrap_admin_username,
                            password_hash=hash_password(
                                settings.bootstrap_admin_password.get_secret_value()
                            ),
                            role="admin",
                        )
                    )
                    db.commit()
                    logger.info("Bootstrap admin created")
            admins = db.scalar(
                select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
            )
            if not admins:
                raise RuntimeError(
                    "No active administrator exists. Configure BOOTSTRAP_ADMIN_USERNAME and "
                    "BOOTSTRAP_ADMIN_PASSWORD for the first startup."
                )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        initialize()
        yield

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description=(
            "Prototipo defensivo de ingestión de telemetría, correlación de IoC "
            "y gestión de alertas."
        ),
        docs_url="/docs" if settings.app_env.lower() != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.app_env.lower() != "production" else None,
        lifespan=lifespan,
    )

    def record_rate_limit_breach(client_address: str) -> None:
        try:
            source_ip = str(ip_address(client_address))
        except ValueError:
            source_ip = None
        now = utcnow()
        try:
            with SessionLocal() as db:
                event = SecurityEvent(
                    event_type="request_rate_limited",
                    source="api-rate-limiter",
                    occurred_at=now,
                    severity="medium",
                    source_ip=source_ip,
                    details_json=json.dumps(
                        {"window_seconds": 60, "configured_limit": rate_limiter.limit}
                    ),
                    created_by_id=None,
                )
                db.add(event)
                db.flush()
                source_description = f" from {source_ip}" if source_ip else ""
                db.add(
                    Alert(
                        title="API request rate limit exceeded",
                        description=(
                            f"A client{source_description} exceeded the configured request "
                            "limit; repeated reports are aggregated for five minutes."
                        ),
                        severity="medium",
                        rule_id="request-rate-limit",
                        event_id=event.id,
                    )
                )
                db.add(
                    AuditLog(
                        actor_id=None,
                        action="request.rate_limited",
                        resource_type="security_event",
                        resource_id=str(event.id),
                    )
                )
                db.commit()
        except SQLAlchemyError:
            logger.error("Could not persist a rate-limit security event")

    @app.middleware("http")
    async def enforce_rate_limit(request: Request, call_next):
        request_id = uuid4().hex
        request.state.request_id = request_id
        if request.url.path == "/health":
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        key = request.client.host if request.client else "unknown"
        if not rate_limiter.allow(key):
            if rate_limiter.should_report(key):
                record_rate_limit_breach(key)
            return Response(
                status_code=429, headers={"Retry-After": "60"}, content="Rate limit exceeded"
            )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "unavailable")
        logger.error(
            "Unhandled application error type=%s request_id=%s path=%s",
            type(exc).__name__,
            request_id,
            request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
            headers={"X-Request-ID": request_id, "Cache-Control": "no-store"},
        )

    def audit(
        db: Session,
        actor_id: int | None,
        action: str,
        resource: str,
        resource_id: int | str | None = None,
    ) -> None:
        db.add(
            AuditLog(
                actor_id=actor_id,
                action=action,
                resource_type=resource,
                resource_id=str(resource_id) if resource_id is not None else None,
            )
        )

    def get_current_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
        db: Session = Depends(get_db),
    ) -> User:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"}
            )
        try:
            claims = decode_access_token(credentials.credentials, settings)
            if claims.get("typ") != "access":
                raise ValueError("wrong token type")
            if db.get(RevokedToken, claims["jti"]) is not None:
                raise ValueError("revoked token")
            user = db.get(User, int(claims["sub"]))
            if user is None or not user.is_active:
                raise ValueError("inactive user")
            return user
        except (jwt.PyJWTError, KeyError, ValueError, TypeError):
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None

    def require_roles(*roles: str):
        def dependency(user: User = Depends(get_current_user)) -> User:
            if user.role not in roles:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return user

        return dependency

    def serialize_event(event: SecurityEvent) -> dict:
        return {
            "id": event.id,
            "event_type": event.event_type,
            "source": event.source,
            "occurred_at": _ensure_aware(event.occurred_at),
            "received_at": _ensure_aware(event.received_at),
            "severity": event.severity,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "domain": event.domain,
            "file_hash": event.file_hash,
            "details": json.loads(event.details_json),
        }

    def maybe_alert_event(db: Session, event: SecurityEvent) -> None:
        now = utcnow()

        def add_indicator_alert(
            indicator: Indicator, title: str, description: str, severity: str
        ) -> None:
            prior = db.scalar(
                select(Alert.id).where(
                    Alert.event_id == event.id, Alert.indicator_id == indicator.id
                )
            )
            if prior is None:
                db.add(
                    Alert(
                        title=title,
                        description=description,
                        severity=severity,
                        rule_id="ioc-match",
                        event_id=event.id,
                        indicator_id=indicator.id,
                    )
                )

        if event.source_ip:
            indicator = db.scalar(
                select(Indicator).where(
                    Indicator.indicator_type == "ip",
                    Indicator.value == event.source_ip,
                    (Indicator.expires_at.is_(None)) | (Indicator.expires_at > now),
                )
            )
            if indicator:
                add_indicator_alert(
                    indicator,
                    f"Known malicious IP observed: {event.source_ip}",
                    "Event source matched an active threat-intelligence indicator.",
                    "high",
                )
        if event.domain:
            indicator = db.scalar(
                select(Indicator).where(
                    Indicator.indicator_type == "domain",
                    Indicator.value == event.domain,
                    (Indicator.expires_at.is_(None)) | (Indicator.expires_at > now),
                )
            )
            if indicator:
                add_indicator_alert(
                    indicator,
                    f"Known malicious domain observed: {event.domain}",
                    "Event domain matched an active threat-intelligence indicator.",
                    "high",
                )
        if event.file_hash:
            indicator = db.scalar(
                select(Indicator).where(
                    Indicator.indicator_type == "hash",
                    Indicator.value == event.file_hash,
                    (Indicator.expires_at.is_(None)) | (Indicator.expires_at > now),
                )
            )
            if indicator:
                add_indicator_alert(
                    indicator,
                    "Known malicious file hash observed",
                    "Event file hash matched an active threat-intelligence indicator.",
                    "critical",
                )

        for rule in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))):
            observed = getattr(event, rule.field_name, None)
            if observed is None:
                continue
            matched = (
                str(observed).lower() == rule.match_value.lower()
                if rule.operator == "equals"
                else rule.match_value.lower() in str(observed).lower()
            )
            rule_key = f"rule-{rule.id}"
            if (
                matched
                and db.scalar(
                    select(Alert.id).where(Alert.event_id == event.id, Alert.rule_id == rule_key)
                )
                is None
            ):
                db.add(
                    Alert(
                        title=rule.name,
                        description=f"{rule.description} (event #{event.id})",
                        severity=rule.severity,
                        rule_id=rule_key,
                        event_id=event.id,
                    )
                )

        if event.event_type == "login_failed" and event.source_ip:
            since = now - timedelta(minutes=settings.brute_force_window_minutes)
            count = (
                db.scalar(
                    select(func.count(SecurityEvent.id)).where(
                        SecurityEvent.event_type == "login_failed",
                        SecurityEvent.source_ip == event.source_ip,
                        SecurityEvent.occurred_at >= since,
                    )
                )
                or 0
            )
            exists = db.scalar(
                select(Alert.id).where(
                    Alert.rule_id == "repeated-login-failures",
                    Alert.status != "closed",
                    Alert.created_at >= since,
                    Alert.description.contains(event.source_ip),
                )
            )
            if count >= settings.brute_force_threshold and exists is None:
                db.add(
                    Alert(
                        title="Repeated authentication failures",
                        description=f"{count} failed logins from source {event.source_ip} within "
                        f"{settings.brute_force_window_minutes} minutes.",
                        severity="high",
                        rule_id="repeated-login-failures",
                        event_id=event.id,
                    )
                )

    @app.get("/health", tags=["operations"])
    def health():
        return {"status": "ok", "service": "guardian-caribe", "mode": settings.app_env}

    @app.post("/auth/login", response_model=TokenRead, tags=["authentication"])
    def login(payload: LoginRequest, db: Session = Depends(get_db)):
        user = db.scalar(select(User).where(User.username == payload.username))
        encoded = user.password_hash if user else None
        valid = safe_compare_password(payload.password, encoded)
        now = utcnow()
        locked_until = _ensure_aware(user.locked_until) if user else None
        is_locked = locked_until is not None and locked_until > now
        if user is None or not user.is_active or is_locked or not valid:
            if user and user.is_active and not is_locked and not valid:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.locked_until = now + timedelta(minutes=settings.login_lock_minutes)
                db.commit()
            raise HTTPException(status_code=401, detail="Invalid username or password")
        user.failed_login_attempts = 0
        user.locked_until = None
        db.query(RevokedToken).filter(RevokedToken.expires_at <= now).delete(
            synchronize_session=False
        )
        audit(db, user.id, "auth.login", "user", user.id)
        token, _jti, expiration = create_access_token(user, settings)
        db.commit()
        return TokenRead(access_token=token, expires_in=int((expiration - now).total_seconds()))

    @app.post("/auth/logout", status_code=204, tags=["authentication"])
    def logout(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        assert credentials is not None
        claims = decode_access_token(credentials.credentials, settings)
        db.add(
            RevokedToken(jti=claims["jti"], expires_at=datetime.fromtimestamp(claims["exp"], UTC))
        )
        audit(db, user.id, "auth.logout", "user", user.id)
        db.commit()
        return Response(status_code=204)

    @app.post("/users", response_model=UserRead, status_code=201, tags=["administration"])
    def create_user(
        payload: UserCreate,
        user: User = Depends(require_roles("admin")),
        db: Session = Depends(get_db),
    ):
        if db.scalar(select(User.id).where(User.username == payload.username)) is not None:
            raise HTTPException(status_code=409, detail="Username already exists")
        created = User(
            username=payload.username,
            password_hash=hash_password(payload.password),
            role=payload.role,
        )
        db.add(created)
        db.flush()
        audit(db, user.id, "user.create", "user", created.id)
        db.commit()
        db.refresh(created)
        return created

    @app.get("/users", response_model=list[UserRead], tags=["administration"])
    def list_users(_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
        return db.scalars(select(User).order_by(User.id)).all()

    @app.delete("/users/{user_id}", status_code=204, tags=["administration"])
    def deactivate_user(
        user_id: int, actor: User = Depends(require_roles("admin")), db: Session = Depends(get_db)
    ):
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")
        if target.id == actor.id:
            raise HTTPException(
                status_code=400, detail="Administrators cannot deactivate themselves"
            )
        target.is_active = False
        audit(db, actor.id, "user.deactivate", "user", target.id)
        db.commit()
        return Response(status_code=204)

    @app.post("/events", response_model=EventRead, status_code=201, tags=["events"])
    def ingest_event(
        payload: EventCreate,
        user: User = Depends(require_roles("admin", "analyst")),
        db: Session = Depends(get_db),
    ):
        event = SecurityEvent(
            event_type=payload.event_type,
            source=payload.source,
            occurred_at=payload.occurred_at,
            severity=payload.severity,
            source_ip=payload.source_ip,
            destination_ip=payload.destination_ip,
            domain=payload.domain,
            file_hash=payload.file_hash,
            details_json=json.dumps(payload.details, separators=(",", ":"), ensure_ascii=False),
            created_by_id=user.id,
        )
        db.add(event)
        db.flush()
        maybe_alert_event(db, event)
        audit(db, user.id, "event.ingest", "security_event", event.id)
        db.commit()
        db.refresh(event)
        return serialize_event(event)

    @app.get("/events", response_model=list[EventRead], tags=["events"])
    def list_events(
        event_type: str | None = None,
        severity: str | None = Query(default=None),
        source_ip: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        filters = []
        if event_type:
            filters.append(SecurityEvent.event_type == event_type)
        if severity:
            filters.append(SecurityEvent.severity == severity)
        if source_ip:
            filters.append(SecurityEvent.source_ip == source_ip)
        if start:
            filters.append(SecurityEvent.occurred_at >= start)
        if end:
            filters.append(SecurityEvent.occurred_at <= end)
        events = db.scalars(
            select(SecurityEvent)
            .where(and_(*filters))
            .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return [serialize_event(event) for event in events]

    @app.post(
        "/indicators", response_model=IndicatorRead, status_code=201, tags=["threat-intelligence"]
    )
    def create_indicator(
        payload: IndicatorCreate,
        user: User = Depends(require_roles("admin")),
        db: Session = Depends(get_db),
    ):
        if (
            db.scalar(
                select(Indicator.id).where(
                    Indicator.indicator_type == payload.indicator_type,
                    Indicator.value == payload.value,
                )
            )
            is not None
        ):
            raise HTTPException(status_code=409, detail="Indicator already exists")
        for timestamp in (payload.first_seen, payload.expires_at):
            if timestamp and (timestamp.tzinfo is None or timestamp.utcoffset() is None):
                raise HTTPException(
                    status_code=422, detail="Indicator timestamps must include a timezone"
                )
        if payload.expires_at and payload.first_seen and payload.expires_at <= payload.first_seen:
            raise HTTPException(status_code=422, detail="expires_at must be after first_seen")
        indicator = Indicator(**payload.model_dump(), created_by_id=user.id)
        db.add(indicator)
        db.flush()
        audit(db, user.id, "indicator.create", "indicator", indicator.id)
        db.commit()
        db.refresh(indicator)
        return indicator

    @app.get("/indicators", response_model=list[IndicatorRead], tags=["threat-intelligence"])
    def list_indicators(
        indicator_type: str | None = None,
        active_only: bool = True,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        filters = []
        now = utcnow()
        if indicator_type:
            filters.append(Indicator.indicator_type == indicator_type)
        if active_only:
            filters.append((Indicator.expires_at.is_(None)) | (Indicator.expires_at > now))
        return db.scalars(
            select(Indicator)
            .where(and_(*filters))
            .order_by(Indicator.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()

    @app.get("/alerts", response_model=list[AlertRead], tags=["alerts"])
    def list_alerts(
        alert_status: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        query = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())
        if alert_status:
            if alert_status not in {"new", "investigating", "escalated", "closed"}:
                raise HTTPException(status_code=422, detail="Invalid alert status")
            query = query.where(Alert.status == alert_status)
        return db.scalars(query.limit(limit).offset(offset)).all()

    @app.patch("/alerts/{alert_id}", response_model=AlertRead, tags=["alerts"])
    def update_alert(
        alert_id: int,
        payload: AlertUpdate,
        user: User = Depends(require_roles("admin", "analyst")),
        db: Session = Depends(get_db),
    ):
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        changes = payload.model_dump(exclude_unset=True)
        if "assigned_to_id" in changes and changes["assigned_to_id"] is not None:
            assignee = db.get(User, changes["assigned_to_id"])
            if assignee is None or not assignee.is_active:
                raise HTTPException(status_code=422, detail="Assignee must be an active user")
        for field, value in changes.items():
            setattr(alert, field, value)
        alert.updated_at = utcnow()
        audit(db, user.id, "alert.update", "alert", alert.id)
        db.commit()
        db.refresh(alert)
        return alert

    @app.get("/alerts/{alert_id}", tags=["alerts"])
    def get_alert(
        alert_id: int,
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        event_data = serialize_event(alert.event) if alert.event else None
        indicator = db.get(Indicator, alert.indicator_id) if alert.indicator_id else None
        return {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "status": alert.status,
            "rule_id": alert.rule_id,
            "event": event_data,
            "indicator": IndicatorRead.model_validate(indicator) if indicator else None,
            "assigned_to_id": alert.assigned_to_id,
            "created_at": _ensure_aware(alert.created_at),
            "updated_at": _ensure_aware(alert.updated_at),
        }

    @app.post("/rules", response_model=DetectionRuleRead, status_code=201, tags=["detections"])
    def create_rule(
        payload: DetectionRuleCreate,
        user: User = Depends(require_roles("admin")),
        db: Session = Depends(get_db),
    ):
        if (
            db.scalar(select(DetectionRule.id).where(DetectionRule.name == payload.name))
            is not None
        ):
            raise HTTPException(status_code=409, detail="Rule name already exists")
        rule = DetectionRule(**payload.model_dump(), created_by_id=user.id)
        db.add(rule)
        db.flush()
        audit(db, user.id, "detection_rule.create", "detection_rule", rule.id)
        db.commit()
        db.refresh(rule)
        return rule

    @app.get("/rules", response_model=list[DetectionRuleRead], tags=["detections"])
    def list_rules(
        enabled: bool | None = None,
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        query = select(DetectionRule).order_by(DetectionRule.id)
        if enabled is not None:
            query = query.where(DetectionRule.enabled.is_(enabled))
        return db.scalars(query).all()

    @app.patch("/rules/{rule_id}", response_model=DetectionRuleRead, tags=["detections"])
    def update_rule(
        rule_id: int,
        payload: DetectionRuleUpdate,
        user: User = Depends(require_roles("admin")),
        db: Session = Depends(get_db),
    ):
        rule = db.get(DetectionRule, rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        for field, value in payload.model_dump(exclude_unset=True).items():
            setattr(rule, field, value)
        rule.updated_at = utcnow()
        audit(db, user.id, "detection_rule.update", "detection_rule", rule.id)
        db.commit()
        db.refresh(rule)
        return rule

    @app.post("/incidents", response_model=IncidentRead, status_code=201, tags=["incidents"])
    def create_incident(
        payload: IncidentCreate,
        user: User = Depends(require_roles("admin", "analyst")),
        db: Session = Depends(get_db),
    ):
        if payload.alert_id is not None:
            alert = db.get(Alert, payload.alert_id)
            if alert is None:
                raise HTTPException(status_code=404, detail="Alert not found")
            if (
                db.scalar(select(Incident.id).where(Incident.alert_id == payload.alert_id))
                is not None
            ):
                raise HTTPException(status_code=409, detail="Alert already belongs to an incident")
        incident = Incident(**payload.model_dump(), created_by_id=user.id)
        db.add(incident)
        db.flush()
        audit(db, user.id, "incident.create", "incident", incident.id)
        db.commit()
        db.refresh(incident)
        return incident

    @app.get("/incidents", response_model=list[IncidentRead], tags=["incidents"])
    def list_incidents(
        incident_status: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        query = select(Incident).order_by(Incident.created_at.desc(), Incident.id.desc())
        if incident_status is not None:
            if incident_status not in {"open", "investigating", "contained", "resolved", "closed"}:
                raise HTTPException(status_code=422, detail="Invalid incident status")
            query = query.where(Incident.status == incident_status)
        return db.scalars(query.limit(limit).offset(offset)).all()

    @app.get("/incidents/{incident_id}", tags=["incidents"])
    def get_incident(
        incident_id: int,
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        notes = db.execute(
            select(IncidentNote, User.username)
            .join(User, User.id == IncidentNote.author_id)
            .where(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at, IncidentNote.id)
        ).all()
        return {
            **IncidentRead.model_validate(incident).model_dump(),
            "notes": [
                {
                    "id": note.id,
                    "incident_id": note.incident_id,
                    "author_id": note.author_id,
                    "author_username": username,
                    "note": note.note,
                    "created_at": _ensure_aware(note.created_at),
                }
                for note, username in notes
            ],
        }

    @app.patch("/incidents/{incident_id}", response_model=IncidentRead, tags=["incidents"])
    def update_incident(
        incident_id: int,
        payload: IncidentUpdate,
        user: User = Depends(require_roles("admin", "analyst")),
        db: Session = Depends(get_db),
    ):
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        changes = payload.model_dump(exclude_unset=True)
        new_status = changes.get("status")
        allowed = {
            "open": {"investigating", "contained", "resolved", "closed"},
            "investigating": {"contained", "resolved", "closed"},
            "contained": {"investigating", "resolved", "closed"},
            "resolved": {"investigating", "closed"},
            "closed": set(),
        }
        if (
            new_status is not None
            and new_status != incident.status
            and new_status not in allowed[incident.status]
        ):
            raise HTTPException(status_code=409, detail="Invalid incident status transition")
        if "assigned_to_id" in changes and changes["assigned_to_id"] is not None:
            assignee = db.get(User, changes["assigned_to_id"])
            if assignee is None or not assignee.is_active:
                raise HTTPException(status_code=422, detail="Assignee must be an active user")
        for field, value in changes.items():
            setattr(incident, field, value)
        incident.updated_at = utcnow()
        audit(db, user.id, "incident.update", "incident", incident.id)
        db.commit()
        db.refresh(incident)
        return incident

    @app.post(
        "/incidents/{incident_id}/notes",
        response_model=IncidentNoteRead,
        status_code=201,
        tags=["incidents"],
    )
    def add_incident_note(
        incident_id: int,
        payload: IncidentNoteCreate,
        user: User = Depends(require_roles("admin", "analyst")),
        db: Session = Depends(get_db),
    ):
        if db.get(Incident, incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        note = IncidentNote(incident_id=incident_id, author_id=user.id, note=payload.note)
        db.add(note)
        db.flush()
        audit(db, user.id, "incident.note.create", "incident", incident_id)
        db.commit()
        db.refresh(note)
        return {
            "id": note.id,
            "incident_id": incident_id,
            "author_id": user.id,
            "author_username": user.username,
            "note": note.note,
            "created_at": _ensure_aware(note.created_at),
        }

    @app.get("/audit", tags=["administration"])
    def list_audit(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _user: User = Depends(require_roles("admin")),
        db: Session = Depends(get_db),
    ):
        entries = db.scalars(
            select(AuditLog)
            .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return [
            {
                "id": entry.id,
                "actor_id": entry.actor_id,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "occurred_at": _ensure_aware(entry.occurred_at),
            }
            for entry in entries
        ]

    @app.get("/system/config", tags=["administration"])
    def read_safe_configuration(_user: User = Depends(require_roles("admin"))):
        return {
            "app_name": settings.app_name,
            "app_env": settings.app_env,
            "database_type": "sqlite"
            if settings.database_url.startswith("sqlite:")
            else "postgresql",
            "access_token_minutes": settings.access_token_minutes,
            "max_login_attempts": settings.max_login_attempts,
            "login_lock_minutes": settings.login_lock_minutes,
            "brute_force_window_minutes": settings.brute_force_window_minutes,
            "brute_force_threshold": settings.brute_force_threshold,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
        }

    @app.get("/maintenance/backups", tags=["maintenance"])
    def list_backups(_user: User = Depends(require_roles("admin"))):
        if engine.url.get_backend_name() != "sqlite":
            raise HTTPException(status_code=501, detail="Backup API currently supports SQLite only")
        backup_dir = Path(settings.backup_directory).resolve()
        if not backup_dir.exists():
            return []
        return [
            {
                "backup_id": path.stem.removeprefix("guardian-"),
                "size_bytes": path.stat().st_size,
                "created_at": datetime.fromtimestamp(path.stat().st_mtime, UTC),
            }
            for path in sorted(
                backup_dir.glob("guardian-*.sqlite3"),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )
        ]

    @app.post("/maintenance/backups", tags=["maintenance"])
    def create_backup(user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
        if engine.url.get_backend_name() != "sqlite" or engine.url.database in {None, ":memory:"}:
            raise HTTPException(
                status_code=501, detail="Backup API currently supports file-based SQLite only"
            )
        backup_dir = Path(settings.backup_directory).resolve()
        backup_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            backup_dir.chmod(0o700)
        backup_id = uuid4().hex
        target = backup_dir / f"guardian-{backup_id}.sqlite3"
        audit(db, user.id, "backup.create", "backup", backup_id)
        db.commit()
        source_connection = engine.raw_connection()
        destination = sqlite3.connect(target)
        try:
            source_connection.driver_connection.backup(destination)
            result = destination.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                target.unlink(missing_ok=True)
                raise HTTPException(status_code=500, detail="SQLite backup integrity check failed")
            if os.name != "nt":
                target.chmod(0o600)
        finally:
            destination.close()
            source_connection.close()
        return FileResponse(
            target,
            media_type="application/vnd.sqlite3",
            filename=target.name,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/reports/summary", tags=["reports"])
    def report_summary(
        days: int = Query(default=30, ge=1, le=365),
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        since = utcnow() - timedelta(days=days)
        events = (
            db.scalar(
                select(func.count(SecurityEvent.id)).where(SecurityEvent.received_at >= since)
            )
            or 0
        )
        alerts = db.scalar(select(func.count(Alert.id)).where(Alert.created_at >= since)) or 0
        incidents = (
            db.scalar(select(func.count(Incident.id)).where(Incident.created_at >= since)) or 0
        )
        severity_counts = db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(Alert.severity)
        ).all()
        return {
            "period_days": days,
            "events_received": events,
            "alerts_created": alerts,
            "incidents_created": incidents,
            "alerts_by_severity": {severity: count for severity, count in severity_counts},
        }

    @app.get("/reports/export", tags=["reports"])
    def export_report(
        dataset: str = Query(pattern="^(events|alerts|incidents)$"),
        format: str = Query(default="csv", pattern="^(csv|json)$"),
        limit: int = Query(default=1000, ge=1, le=5000),
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        if dataset == "events":
            items = [
                serialize_event(item)
                for item in db.scalars(
                    select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit)
                ).all()
            ]
        elif dataset == "alerts":
            items = [
                {
                    "id": item.id,
                    "title": item.title,
                    "description": item.description,
                    "severity": item.severity,
                    "status": item.status,
                    "rule_id": item.rule_id,
                    "event_id": item.event_id,
                    "indicator_id": item.indicator_id,
                    "created_at": _ensure_aware(item.created_at),
                }
                for item in db.scalars(select(Alert).order_by(Alert.id.desc()).limit(limit)).all()
            ]
        else:
            items = [
                {
                    "id": item.id,
                    "title": item.title,
                    "description": item.description,
                    "severity": item.severity,
                    "status": item.status,
                    "alert_id": item.alert_id,
                    "assigned_to_id": item.assigned_to_id,
                    "created_at": _ensure_aware(item.created_at),
                }
                for item in db.scalars(
                    select(Incident).order_by(Incident.id.desc()).limit(limit)
                ).all()
            ]
        normalized = [
            {
                key: value.isoformat() if isinstance(value, datetime) else value
                for key, value in item.items()
            }
            for item in items
        ]
        if format == "json":
            return normalized
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(normalized[0]) if normalized else ["id"])
        writer.writeheader()
        for item in normalized:
            writer.writerow(
                {
                    key: (
                        "'" + value
                        if isinstance(value, str)
                        and value.lstrip().startswith(("=", "+", "-", "@"))
                        else value
                    )
                    for key, value in item.items()
                }
            )
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=guardian-{dataset}.csv"},
        )

    @app.get("/analytics/summary", tags=["analytics"])
    def analytics_summary(
        _user: User = Depends(require_roles("admin", "analyst", "viewer")),
        db: Session = Depends(get_db),
    ):
        since = utcnow() - timedelta(hours=24)
        event_count = (
            db.scalar(
                select(func.count(SecurityEvent.id)).where(SecurityEvent.received_at >= since)
            )
            or 0
        )
        active_alert_count = (
            db.scalar(select(func.count(Alert.id)).where(Alert.status != "closed")) or 0
        )
        by_severity = db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.status != "closed")
            .group_by(Alert.severity)
        ).all()
        return {
            "window_hours": 24,
            "events_received": event_count,
            "active_alerts": active_alert_count,
            "active_alerts_by_severity": {severity: count for severity, count in by_severity},
            "rate_limit_denials_since_process_start": rate_limiter.denials,
        }

    return app


app = create_app()
