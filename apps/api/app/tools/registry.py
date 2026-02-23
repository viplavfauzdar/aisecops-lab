from __future__ import annotations
from typing import Any, Awaitable, Callable, Dict, Optional
from app.tools.tools import http_get, echo

ToolFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolFn] = {
            "http_get": http_get,
            "echo": echo,
        }

    def get(self, name: str) -> Optional[ToolFn]:
        return self._tools.get(name)
