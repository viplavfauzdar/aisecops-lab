from __future__ import annotations
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.security.policy import PolicyEngine
from app.security.audit import AuditLogger
from app.tools.registry import ToolRegistry

class ToolRequest(BaseModel):
    tool: str = Field(..., description="Tool name")
    params: Dict[str, Any] = Field(default_factory=dict)

class ToolGateway:
    def __init__(self, policy: PolicyEngine, audit: AuditLogger, enforce: bool = True):
        self.policy = policy
        self.audit = audit
        self.enforce = enforce
        self.registry = ToolRegistry()

    async def execute(self, req: ToolRequest) -> Dict[str, Any]:
        self.audit.event("tool_request", {"tool": req.tool, "params_keys": list(req.params.keys())})

        if self.enforce:
            if not self.policy.is_tool_allowed(req.tool):
                self.audit.event("tool_denied", {"tool": req.tool, "reason": "not_allowed"})
                return {"ok": False, "error": "Tool not allowed by policy"}

            errs = self.policy.validate_tool_params(req.tool, req.params)
            if errs:
                self.audit.event("tool_denied", {"tool": req.tool, "reason": "param_validation", "errors": errs})
                return {"ok": False, "error": "Param validation failed", "details": errs}
        else:
            # Baseline mode: no enforcement, but we still log what would have been checked.
            self.audit.event("tool_enforcement_bypassed", {"tool": req.tool})

        tool_fn = self.registry.get(req.tool)
        if tool_fn is None:
            self.audit.event("tool_denied", {"tool": req.tool, "reason": "unknown_tool"})
            return {"ok": False, "error": "Unknown tool"}

        try:
            out = await tool_fn(req.params)
            self.audit.event("tool_result", {"tool": req.tool, "ok": True})
            return {"ok": True, "tool": req.tool, "result": out}
        except Exception as e:
            self.audit.event("tool_result", {"tool": req.tool, "ok": False, "error": str(e)})
            return {"ok": False, "error": "Tool execution failed"}
