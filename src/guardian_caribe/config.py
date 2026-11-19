from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "GUARDIÁN CARIBE"
    app_env: str = "development"
    database_url: str = "sqlite:///./guardian_caribe.db"
    jwt_secret: SecretStr = Field(default=SecretStr(""), alias="JWT_SECRET")
    jwt_issuer: str = "guardian-caribe"
    access_token_minutes: int = Field(default=30, ge=5, le=1440)
    max_login_attempts: int = Field(default=5, ge=3, le=20)
    login_lock_minutes: int = Field(default=15, ge=1, le=1440)
    brute_force_window_minutes: int = Field(default=10, ge=1, le=1440)
    brute_force_threshold: int = Field(default=5, ge=3, le=100)
    rate_limit_per_minute: int = Field(default=120, ge=10, le=10000)
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: SecretStr | None = None

    def validate_runtime(self) -> None:
        secret = self.jwt_secret.get_secret_value()
        if len(secret) < 32 or secret.lower().startswith(("replace-with", "change-me")):
            raise ValueError("JWT_SECRET debe ser una clave aleatoria de al menos 32 caracteres.")
        bootstrap_password = (
            self.bootstrap_admin_password.get_secret_value()
            if self.bootstrap_admin_password
            else None
        )
        if bootstrap_password and (
            len(bootstrap_password) < 12
            or bootstrap_password.lower().startswith(("replace-with", "change-me"))
        ):
            raise ValueError(
                "BOOTSTRAP_ADMIN_PASSWORD requiere 12+ caracteres y no puede ser placeholder."
            )
        if self.app_env.lower() == "production":
            raise ValueError(
                "Production todavía no está soportado: faltan migraciones y controles operativos."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
