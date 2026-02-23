from app.security.policy import PolicyEngine
from app.security.audit import AuditLogger
from app.tools.gateway import ToolGateway, ToolRequest
import tempfile
import os
import yaml
import pytest
import asyncio

@pytest.mark.asyncio
async def test_unknown_tool_denied():
    cfg = {"tools": [{"name":"echo","allow": True, "allowed_params": ["text"]}]}
    with tempfile.TemporaryDirectory() as td:
        policy_path = os.path.join(td, "policy.yaml")
        with open(policy_path, "w") as f:
            yaml.safe_dump(cfg, f)
        audit_path = os.path.join(td, "audit.jsonl")
        policy = PolicyEngine.from_file(policy_path)
        audit = AuditLogger(audit_path)
        gw = ToolGateway(policy, audit)
        res = await gw.execute(ToolRequest(tool="does_not_exist", params={}))
        assert res["ok"] is False

@pytest.mark.asyncio
async def test_ssrf_block():
    cfg = {
        "tools": [{
            "name":"http_get",
            "allow": True,
            "allowed_params": ["url"],
            "deny_patterns": {"url": "^(https?://)?(localhost|127\.0\.0\.1|169\.254\.169\.254)([:/]|$)"}
        }]
    }
    with tempfile.TemporaryDirectory() as td:
        policy_path = os.path.join(td, "policy.yaml")
        with open(policy_path, "w") as f:
            yaml.safe_dump(cfg, f)
        audit_path = os.path.join(td, "audit.jsonl")
        policy = PolicyEngine.from_file(policy_path)
        audit = AuditLogger(audit_path)
        gw = ToolGateway(policy, audit)
        res = await gw.execute(ToolRequest(tool="http_get", params={"url":"http://localhost:8000/health"}))
        assert res["ok"] is False
