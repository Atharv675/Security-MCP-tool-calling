"""Environment configuration for the MCP security toolkit server."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    nvd_api_key: str = ""
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_auth_token: str = ""


settings = Settings()
