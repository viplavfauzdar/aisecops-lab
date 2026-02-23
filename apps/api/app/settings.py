from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    LLM_PROVIDER: str = "ollama"  # ollama | openai | anthropic

    # Ollama
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434"
    OLLAMA_MODEL: str = "llama3.1:8b"

    # OpenAI
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"

    # Anthropic
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-latest"

    APP_ENV: str = "dev"
    AUDIT_LOG_PATH: str = "/app/audit/audit.jsonl"
    POLICY_PATH: str = "/app/config/policy.yaml"

    # AISecOps Mode
    # insecure = baseline (no enforcement)
    # secure   = enforce policy controls
    AISECOPS_MODE: str = "insecure"

    # Tool Gateway Enforcement
    # False = bypass policy validation
    # True  = enforce allowlist + param validation + deny rules
    TOOL_GATEWAY_ENFORCE: bool = False

    DATABASE_URL: str = "postgresql+psycopg://aisecops:aisecops@db:5432/aisecops"
