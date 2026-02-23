from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.settings import Settings
from app.llm.factory import get_llm_client
from app.security.policy import PolicyEngine
from app.security.audit import AuditLogger
from app.tools.gateway import ToolGateway, ToolRequest

app = FastAPI(title="AISecOps Lab API", version="0.1.0")

settings = Settings()
policy = PolicyEngine.from_file(settings.POLICY_PATH)
audit = AuditLogger(settings.AUDIT_LOG_PATH)
llm = get_llm_client(settings)

gateway = ToolGateway(policy=policy, audit=audit)

class ChatRequest(BaseModel):
    message: str

@app.get("/health")
def health():
    return {"status": "ok", "provider": settings.LLM_PROVIDER}

@app.post("/chat")
async def chat(req: ChatRequest):
    # Minimal: demonstrate policy-driven prompt hygiene hook.
    # (You will expand with RAG + memory + sanitization.)
    sanitized = policy.sanitize_user_text(req.message)
    audit.event("chat_request", {"raw_len": len(req.message), "sanitized_len": len(sanitized)})

    try:
        resp = await llm.chat(sanitized)
    except Exception as e:
        audit.event("chat_error", {"error": str(e)})
        raise HTTPException(status_code=500, detail="LLM call failed")

    audit.event("chat_response", {"out_len": len(resp)})
    return {"reply": resp, "provider": settings.LLM_PROVIDER}

@app.post("/tools/execute")
async def execute_tool(req: ToolRequest):
    # Demonstrates tool containment as the AISecOps signature.
    result = await gateway.execute(req)
    return result
