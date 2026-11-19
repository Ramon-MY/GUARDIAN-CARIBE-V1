import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_guardian_caribe.db")
os.environ.setdefault("JWT_SECRET", "test-only-secret-with-at-least-32-characters-long")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "testadmin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password-very-long")

import pytest
from fastapi.testclient import TestClient

from guardian_caribe.db import Base, engine
from guardian_caribe.main import DEFAULT_RUNTIME_CONFIG, app, rate_limiter, settings


@pytest.fixture()
def client():
    for key, value in DEFAULT_RUNTIME_CONFIG.items():
        setattr(settings, key, value)
    rate_limiter.limit = settings.rate_limit_per_minute
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(
        app,
        base_url="http://198.51.100.21",
        client=("198.51.100.21", 50000),
        raise_server_exceptions=False,
    ) as test_client:
        yield test_client
    rate_limiter.requests.clear()
    rate_limiter.reported.clear()
    rate_limiter.denials = 0
    for key, value in DEFAULT_RUNTIME_CONFIG.items():
        setattr(settings, key, value)
    rate_limiter.limit = settings.rate_limit_per_minute


@pytest.fixture()
def admin_token(client):
    response = client.post(
        "/auth/login", json={"username": "testadmin", "password": "test-admin-password-very-long"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture()
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
