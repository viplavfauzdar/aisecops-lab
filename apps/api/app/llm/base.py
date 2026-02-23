from abc import ABC, abstractmethod

class LLMClient(ABC):
    @abstractmethod
    async def chat(self, message: str) -> str:
        ...
