# AGENTS.md — sovereign-vault

## Project Overview
sovereign-vault is a Python library for reversible PII tokenization in LLM pipelines.
It replaces sensitive values with HMAC-bound placeholder tokens so cloud AI can reason
about cross-entity relationships without seeing real data.

## Architecture
- **Language:** Python 3.10+
- **Package manager:** pip / setuptools
- **Test framework:** pytest
- **CI:** GitHub Actions (.github/workflows/ci.yml)

## Build & Test Commands
```bash
pip install -e .[all]        # Install with all extras
pytest tests/ -v --tb=short  # Run test suite
ruff check sovereign_vault/  # Lint
```

## Directory Structure
```
sovereign_vault/     # Core library
  __init__.py        # Public API re-exports
  types.py           # Enums, exceptions, dataclasses
  patterns.py        # Regex patterns, constants
  detection.py       # 3-layer detection engine (Regex, GLiNER, Ollama)
  tokens.py          # HMAC token generation, verification, reconstruction
  session.py         # VaultSession class, session registry
tests/               # pytest test suite
examples/            # Integration examples (OpenAI, Claude, MCP, FastAPI)
docs/                # Architecture, threat model, compliance docs
```

## Critical Boundaries — DO NOT MODIFY WITHOUT HUMAN REVIEW
- **HMAC key derivation** in `tokens.py` — session-unique 32-byte secret generation
- **Memory wipe logic** in `session.py` — `destroy()` method overwrites before clearing
- **Vault token regex** (`_VAULT_TOKEN_RE`) — injection prevention gate
- **AES-256-GCM encryption wrappers** — if added in future versions
- **sodium_malloc / mlock integration** — if added in future versions

## Code Style
- Type hints on all public methods
- Docstrings on all public classes and functions
- No global mutable state except `_sessions` registry
- All detection layers must degrade gracefully (never crash on missing optional deps)

## Testing Requirements
- All PRs must pass `pytest tests/ -v`
- Cryptographic logic changes require dedicated security test coverage
- GLiNER/Ollama tests should be skippable when deps are not installed
