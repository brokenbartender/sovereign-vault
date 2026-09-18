# Changelog

All notable changes to sovereign-vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
