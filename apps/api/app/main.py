from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from app.settings import Settings
from app.llm.factory import get_llm_client
from app.security.policy import PolicyEngine
from app.security.audit import AuditLogger
from app.tools.gateway import ToolGateway, ToolRequest

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

app = FastAPI(title="AISecOps Lab API", version="0.1.0")

settings = Settings()
engine: Engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
policy = PolicyEngine.from_file(settings.POLICY_PATH)
audit = AuditLogger(settings.AUDIT_LOG_PATH)
llm = get_llm_client(settings)

gateway = ToolGateway(policy=policy, audit=audit, enforce=settings.TOOL_GATEWAY_ENFORCE)

class ChatRequest(BaseModel):
    message: str

class RAGIngestRequest(BaseModel):
    tenant_id: str = Field(default="default")
    content: str = Field(..., min_length=1)

class RAGQueryRequest(BaseModel):
    tenant_id: str = Field(default="default")
    query: str = Field(..., min_length=1)
    top_k: int = Field(default=5, ge=1, le=20)

def _chunk_text(text_in: str, chunk_size: int = 800, overlap: int = 100) -> list[str]:
    text_in = (text_in or "").strip()
    if not text_in:
        return []
    chunks: list[str] = []
    i = 0
    n = len(text_in)
    while i < n:
        j = min(n, i + chunk_size)
        chunks.append(text_in[i:j])
        if j == n:
            break
        i = max(0, j - overlap)
    return chunks

async def _embed_texts(texts: list[str]) -> list[list[float]]:
    # Placeholder embeddings for RAG v0.
    # Next step: replace with real embeddings via Ollama/OpenAI/Anthropic adapters.
    # For now, deterministic pseudo-embeddings to validate pgvector plumbing.
    out: list[list[float]] = []
    for t in texts:
        # Produce a small stable vector based on character codes, then pad to 1536.
        base = [(ord(c) % 97) / 97.0 for c in t[:64]]
        if not base:
            base = [0.0]
        vec = (base * (1536 // len(base) + 1))[:1536]
        out.append(vec)
    return out

@app.get("/health")
def health():
    return {"status": "ok", "provider": settings.LLM_PROVIDER, "aisecops_mode": settings.AISECOPS_MODE, "tool_gateway_enforce": settings.TOOL_GATEWAY_ENFORCE}

@app.post("/chat")
async def chat(req: ChatRequest):
    # Minimal: demonstrate policy-driven prompt hygiene hook.
    # (You will expand with RAG + memory + sanitization.)
    sanitized = req.message if settings.AISECOPS_MODE.lower() == "insecure" else policy.sanitize_user_text(req.message)
    audit.event("chat_request", {"raw_len": len(req.message), "sanitized_len": len(sanitized)})

    try:
        resp = await llm.chat(sanitized)
    except Exception as e:
        audit.event("chat_error", {"error": str(e)})
        raise HTTPException(status_code=500, detail="LLM call failed")

    audit.event("chat_response", {"out_len": len(resp)})
    return {"reply": resp, "provider": settings.LLM_PROVIDER}


@app.post("/rag/ingest")
async def rag_ingest(req: RAGIngestRequest):
    tenant_id = req.tenant_id or "default"
    content = req.content
    # RAG v0: no sanitization yet. (We will harden later.)
    chunks = _chunk_text(content)
    if not chunks:
        raise HTTPException(status_code=400, detail="No content to ingest")

    embeddings = await _embed_texts(chunks)

    try:
        with engine.begin() as conn:
            doc_id = conn.execute(
                text("INSERT INTO documents (tenant_id, content) VALUES (:tenant_id, :content) RETURNING id"),
                {"tenant_id": tenant_id, "content": content},
            ).scalar_one()

            for chunk_text, emb in zip(chunks, embeddings):
                conn.execute(
                    text(
                        "INSERT INTO chunks (document_id, tenant_id, content, embedding) "
                        "VALUES (:document_id, :tenant_id, :content, (:embedding)::vector)"
                    ),
                    {
                        "document_id": doc_id,
                        "tenant_id": tenant_id,
                        "content": chunk_text,
                        "embedding": "[" + ",".join(f"{x:.6f}" for x in emb) + "]",
                    },
                )
    except Exception as e:
        audit.event("rag_ingest_error", {"error": str(e)})
        raise HTTPException(status_code=500, detail="RAG ingest failed")

    audit.event("rag_ingest", {"tenant_id": tenant_id, "doc_id": int(doc_id), "chunks": len(chunks)})
    return {"ok": True, "tenant_id": tenant_id, "document_id": int(doc_id), "chunks": len(chunks)}


@app.post("/rag/query")
async def rag_query(req: RAGQueryRequest):
    tenant_id = req.tenant_id or "default"
    query = req.query
    top_k = req.top_k

    q_emb = (await _embed_texts([query]))[0]
    q_emb_lit = "[" + ",".join(f"{x:.6f}" for x in q_emb) + "]"

    try:
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT id, document_id, content "
                    "FROM chunks "
                    "WHERE tenant_id = :tenant_id AND embedding IS NOT NULL "
                    "ORDER BY embedding <-> (:q_emb)::vector "
                    "LIMIT :top_k"
                ),
                {"tenant_id": tenant_id, "q_emb": q_emb_lit, "top_k": top_k},
            ).mappings().all()
    except Exception as e:
        audit.event("rag_query_error", {"error": str(e)})
        raise HTTPException(status_code=500, detail="RAG query failed")

    results = [{"chunk_id": r["id"], "document_id": r["document_id"], "content": r["content"]} for r in rows]
    audit.event("rag_query", {"tenant_id": tenant_id, "top_k": top_k, "returned": len(results)})
    return {"ok": True, "tenant_id": tenant_id, "results": results}

@app.post("/tools/execute")
async def execute_tool(req: ToolRequest):
    # Demonstrates tool containment as the AISecOps signature.
    result = await gateway.execute(req)
    return result
