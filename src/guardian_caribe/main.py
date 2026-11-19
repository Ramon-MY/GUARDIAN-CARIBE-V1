import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from guardian_caribe.config import get_settings
from guardian_caribe.db import Base, SessionLocal, engine, get_db
from guardian_caribe.models import (
    Alert,
    AuditLog,
    Indicator,
    RevokedToken,
    SecurityEvent,
    User,
    utcnow,
)
from guardian_caribe.schemas import (
    AlertRead,
    AlertUpdate,
    EventCreate,
    EventRead,
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
        self.lock = threading.Lock()

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
                    return False
            bucket = self.requests[key]
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


rate_limiter = LocalRateLimiter(settings.rate_limit_per_minute)


def create_app() -> FastAPI:
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
    )

    @app.on_event("startup")
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

    @app.middleware("http")
    async def enforce_rate_limit(request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        key = request.client.host if request.client else "unknown"
        if not rate_limiter.allow(key):
            return Response(
                status_code=429, headers={"Retry-After": "60"}, content="Rate limit exceeded"
            )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

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
        }

    return app


app = create_app()
