import httpx
from app.llm.base import LLMClient

class OpenAIClient(LLMClient):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    async def chat(self, message: str) -> str:
        # Minimal REST call to OpenAI Chat Completions endpoint (no SDK dependency).
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set")
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": message}],
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
            return (data["choices"][0]["message"]["content"] or "").strip()
