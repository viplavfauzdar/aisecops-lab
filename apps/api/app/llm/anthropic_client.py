import httpx
from app.llm.base import LLMClient

class AnthropicClient(LLMClient):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    async def chat(self, message: str) -> str:
        # Minimal REST call to Anthropic Messages endpoint (no SDK dependency).
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 500,
            "temperature": 0.2,
            "messages": [{"role": "user", "content": message}],
        }
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
            # content is list of blocks
            blocks = data.get("content", [])
            text = ""
            for b in blocks:
                if b.get("type") == "text":
                    text += b.get("text", "")
            return text.strip()
