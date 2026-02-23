# AISecOps Lab (Reference Implementation v1)

A starter repo to build an **AISecOps** reference system: a deliberately vulnerable AI app that you progressively harden with:
- tool containment (Tool Gateway + policy engine)
- secure RAG (pgvector + sanitization hooks)
- output validation
- audit logging
- red-team regression tests
- CI gates

## Quickstart (local)

### 1) Copy env
```bash
cp .env.example .env
```

### 2) Start infra (Postgres + pgvector) + API
```bash
docker compose up --build
```

API: http://localhost:8000  
Health: http://localhost:8000/health

### 3) Try chat
```bash
curl -s http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello. Summarize AISecOps in one sentence."}' | jq
```

## Provider switch (Ollama / OpenAI / Anthropic)

Set in `.env`:
- `LLM_PROVIDER=ollama` (default)
- `LLM_PROVIDER=openai`
- `LLM_PROVIDER=anthropic`

### Ollama
- Run Ollama locally (e.g. `ollama serve`)
- Set:
  - `OLLAMA_BASE_URL=http://host.docker.internal:11434`
  - `OLLAMA_MODEL=llama3.1:8b` (or whatever you have)

### OpenAI
- Set:
  - `OPENAI_API_KEY=...`
  - `OPENAI_MODEL=gpt-4o-mini` (example)

### Anthropic
- Set:
  - `ANTHROPIC_API_KEY=...`
  - `ANTHROPIC_MODEL=claude-3-5-sonnet-latest` (example)

## What’s included

- FastAPI app with:
  - `/chat` endpoint
  - `/tools/execute` endpoint (Tool Gateway)
- Minimal AISecOps policy engine (YAML-driven)
- Tool allowlisting + parameter validation + deny rules
- Audit event logging (JSONL)
- Postgres + pgvector in Docker Compose
- GitHub Actions CI: unit + security tests

## Next steps (you’ll implement incrementally)
1. Add RAG ingestion + retrieval (pgvector)
2. Add retrieval sanitization (strip instructions)
3. Add output schema validation and policy checks
4. Add red-team test harness and regression gates
