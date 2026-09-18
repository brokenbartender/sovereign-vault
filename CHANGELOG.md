# Changelog

All notable changes to sovereign-vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Codex maintainer automation: AI PR review, issue triage, and release-notes workflows
  (advisory-only; a human decides — see `.github/workflows/codex-*.yml`)
- `CODE_OF_CONDUCT.md`, `CODEOWNERS`, issue templates, and a pull-request template
- Dependabot config for GitHub Actions and pip updates
- `py.typed` marker (PEP 561) so type checkers pick up the library's type hints

### Changed
- Consolidated the two overlapping PyPI publish workflows into one canonical
  release-triggered workflow using PyPI Trusted Publishing (OIDC — no stored token)

## [1.1.0] - 2026-09-18

### Added
- `VaultProxy` — MCP middleware that transparently tokenizes PII in JSON-RPC 2.0
  payloads between an MCP client and server, before data reaches the LLM context
- `sovereign-vault` command-line interface (`tokenize`, `diff`, stdin/file input)
- Split into focused modules (`session`, `proxy`, `cli`, `patterns`, `types`)
- Provider examples: OpenAI, Anthropic, FastAPI middleware, MCP tool server
- Gradio web demo (`demo/`), architecture / compliance / threat-model docs
- Expanded test suite (detection, proxy, security) — 53 tests

## [1.0.1] - 2025-09-15

### Fixed
- Corrected PyPI metadata and classifiers
- Fixed badge URLs in README

## [1.0.0] - 2025-09-14

### Added
- Initial release of sovereign-vault
- Three-layer PII detection pipeline (Regex, GLiNER, Ollama)
- HMAC-bound reversible tokenization with session-scoped secrets
- `VaultSession` context manager with automatic memory wipe on exit
- STRICT and LENIENT reconstruction modes
- SEALED execution mode for abstract-only output
- Coverage report API for detection quality assessment
- Module-level session registry (`new_session`, `get_session`, `drop_session`)
- Injection prevention via vault token pre-screening
- Entropy leak detection on cloud output
- PyPI package: `pip install sovereign-vault`
- CI pipeline with GitHub Actions
- `llms.txt` for AI-native documentation
- `CITATION.cff` for academic citation
- `SECURITY.md` for responsible disclosure
