import json
import os
import time
from typing import Any, Dict

class AuditLogger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def event(self, event_type: str, payload: Dict[str, Any]):
        rec = {
            "ts": time.time(),
            "event": event_type,
            "payload": payload,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
