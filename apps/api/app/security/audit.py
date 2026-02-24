import json
import os
import time
from typing import Any, Dict, Optional

from datetime import datetime, timezone

import contextvars
import uuid

_request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("aisecops_request_id", default=None)


def new_request_id() -> str:
    return uuid.uuid4().hex


def set_request_id(request_id: Optional[str]) -> None:
    _request_id_var.set(request_id)


def get_request_id() -> Optional[str]:
    return _request_id_var.get()


class AuditLogger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        severity: str = "info",
        request_id: Optional[str] = None,
    ):
        rid = request_id or get_request_id()
        rec = {
            "ts": time.time(),
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "ts_local": datetime.now().astimezone().isoformat(),
            "event": event_type,
            "severity": severity,
            "request_id": rid,
            "payload": payload,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
