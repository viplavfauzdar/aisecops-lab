import httpx
from app.llm.base import LLMClient

class OllamaClient(LLMClient):
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def chat(self, message: str) -> str:
        # Ollama generate endpoint
        url = f"{self.base_url}/api/generate"
        payload = {"model": self.model, "prompt": message, "stream": False}
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            return data.get("response", "").strip()
