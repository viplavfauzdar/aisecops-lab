import httpx
from app.llm.base import LLMClient

class OllamaClient(LLMClient):
    def __init__(self, base_url: str, model: str, timeout_seconds: int = 60):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    async def chat(self, message: str) -> str:
        # Ollama generate endpoint
        url = f"{self.base_url}/api/generate"
        payload = {"model": self.model, "prompt": message, "stream": False}
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            return data.get("response", "").strip()
