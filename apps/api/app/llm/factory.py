from app.settings import Settings
from app.llm.ollama import OllamaClient
from app.llm.openai_client import OpenAIClient
from app.llm.anthropic_client import AnthropicClient

def get_llm_client(settings: Settings):
    provider = (settings.LLM_PROVIDER or "ollama").lower()
    if provider == "ollama":
        return OllamaClient(
            settings.OLLAMA_BASE_URL,
            settings.OLLAMA_CHAT_MODEL,
            settings.OLLAMA_TIMEOUT_SECONDS,
        )
    if provider == "openai":
        return OpenAIClient(settings.OPENAI_API_KEY, settings.OPENAI_MODEL)
    if provider == "anthropic":
        return AnthropicClient(settings.ANTHROPIC_API_KEY, settings.ANTHROPIC_MODEL)
    raise ValueError(f"Unsupported LLM_PROVIDER: {settings.LLM_PROVIDER}")
