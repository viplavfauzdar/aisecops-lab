# Contributing

Thanks for contributing to AISecOps Lab. This guide explains the expected workflow for changes.

## Where This File Is Used

GitHub automatically recognizes `CONTRIBUTING.md` when it is placed in:
- the repository root
- `.github/`
- `docs/`

When present, GitHub shows contributors a link to this guide during pull request and contribution flows.

## Prerequisites

- Docker + Docker Compose
- Python 3.11+ (for local test runs outside Docker)
- An LLM provider available for integration tests (typically Ollama on host)

## Local Setup

1. Create local env file:
```bash
cp .env.example .env
```

2. Recommended secure defaults in `.env`:
```bash
AISECOPS_MODE=secure
TOOL_GATEWAY_ENFORCE=true
EMBED_DIM=768
```

3. Start services:
```bash
docker compose up --build
```

## Running Tests

Run from `apps/api`:

1. Unit/security tests (no live LLM):
```bash
pytest -q tests/security -m "not integration"
```

2. Integration tests (requires running stack and provider):
```bash
pytest -q -m "integration" -W ignore::pytest.PytestUnknownMarkWarning
```

## What to Include in a PR

- Clear problem statement and scope
- Summary of code changes
- Test evidence (commands + results)
- Any config/env or policy changes
- Notes about security implications for:
  - tool execution paths
  - retrieval sanitization
  - output validation
  - audit logging/metrics

## Style and Scope Guidelines

- Keep changes focused and minimal.
- Prefer policy/config changes over hardcoding where possible.
- Preserve secure defaults and avoid bypassing gateway/policy checks.
- If adding endpoints, include audit events and metrics where relevant.
- If behavior changes, update `README.md` and tests in the same PR.

## Security Reporting

If you discover a security issue, avoid posting exploit details publicly in issues. Share details privately with maintainers first.
