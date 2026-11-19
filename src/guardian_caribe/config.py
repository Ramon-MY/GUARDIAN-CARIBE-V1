from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "GUARDIÁN CARIBE"
    app_env: str = "development"
    database_url: str = "sqlite:///./guardian_caribe.db"
    backup_directory: str = "./backups"
    jwt_secret: SecretStr = Field(default=SecretStr(""), alias="JWT_SECRET")
    jwt_issuer: str = "guardian-caribe"
    access_token_minutes: int = Field(default=30, ge=5, le=1440)
    max_login_attempts: int = Field(default=5, ge=3, le=20)
    login_lock_minutes: int = Field(default=15, ge=1, le=1440)
    password_min_length: int = Field(default=12, ge=12, le=128)
    brute_force_window_minutes: int = Field(default=10, ge=1, le=1440)
    brute_force_threshold: int = Field(default=5, ge=3, le=100)
    alert_dedupe_minutes: int = Field(default=5, ge=1, le=1440)
    rate_limit_per_minute: int = Field(default=120, ge=10, le=10000)
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: SecretStr | None = None

    integration_timeout_seconds: float = Field(default=15, gt=0, le=120)
    misp_url: str | None = Field(default=None, max_length=512, alias="MISP_URL")
    misp_api_key: SecretStr | None = Field(default=None, alias="MISP_API_KEY")
    misp_page_size: int = Field(default=100, ge=1, le=500)
    misp_max_pages: int = Field(default=5, ge=1, le=20)
    taxii_api_root: str | None = Field(default=None, max_length=512, alias="TAXII_API_ROOT")
    taxii_collection_id: str | None = Field(
        default=None, max_length=128, alias="TAXII_COLLECTION_ID"
    )
    taxii_bearer_token: SecretStr | None = Field(default=None, alias="TAXII_BEARER_TOKEN")
    taxii_page_size: int = Field(default=100, ge=1, le=500)
    taxii_max_pages: int = Field(default=5, ge=1, le=20)

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
            len(bootstrap_password) < self.password_min_length
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
