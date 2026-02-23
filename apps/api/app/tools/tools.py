from __future__ import annotations
from typing import Any, Dict
import httpx

async def echo(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"echo": params}

async def http_get(params: Dict[str, Any]) -> Dict[str, Any]:
    url = params.get("url")
    if not url:
        raise ValueError("url is required")
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url)
        return {"status_code": r.status_code, "text_head": r.text[:500]}
