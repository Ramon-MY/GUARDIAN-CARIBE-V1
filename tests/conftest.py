import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_guardian_caribe.db")
os.environ.setdefault("JWT_SECRET", "test-only-secret-with-at-least-32-characters-long")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "testadmin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password-very-long")

import pytest
from fastapi.testclient import TestClient

from guardian_caribe.db import Base, engine
from guardian_caribe.main import app, rate_limiter


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    rate_limiter.requests.clear()


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
