from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from pwdlib import PasswordHash
from pwdlib.exceptions import HashVerificationError

from guardian_caribe.config import Settings
from guardian_caribe.models import User

password_hasher = PasswordHash.recommended()
_DUMMY_PASSWORD_HASH = password_hasher.hash("guardian-caribe timing calibration")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hasher.verify(password, encoded)
    except (HashVerificationError, TypeError, ValueError):
        return False


def create_access_token(user: User, settings: Settings) -> tuple[str, str, datetime]:
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=settings.access_token_minutes)
    jti = str(uuid4())
    claims = {
        "sub": str(user.id),
        "role": user.role,
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": expires,
        "jti": jti,
        "typ": "access",
    }
    secret = settings.jwt_secret.get_secret_value()
    return jwt.encode(claims, secret, algorithm="HS256"), jti, expires


def decode_access_token(token: str, settings: Settings) -> dict:
    secret = settings.jwt_secret.get_secret_value()
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=settings.jwt_issuer,
        options={"require": ["sub", "exp", "iat", "jti", "iss", "typ"]},
    )


def safe_compare_password(candidate: str, encoded: str | None) -> bool:
    """Use a dummy Argon2 hash on missing accounts to reduce username timing leaks."""
    return verify_password(candidate, encoded or _DUMMY_PASSWORD_HASH)
