# Contributing to sovereign-vault

Thank you for your interest in contributing! sovereign-vault is a security-critical library,
so we have specific guidelines to ensure the integrity of the tokenization pipeline.

## Getting Started

```bash
git clone https://github.com/brokenbartender/sovereign-vault.git
cd sovereign-vault
pip install -e .[all]
pytest tests/ -v
```

## Development Guidelines

### Code Quality
- All public functions and classes must have type hints and docstrings
- Run `ruff check sovereign_vault/` before submitting a PR
- Follow existing code style (dataclasses, enums, explicit error handling)

### Testing
- Every new feature must include tests in `tests/`
- Tests for optional dependencies (GLiNER, Ollama) must skip gracefully:
  ```python
  @pytest.mark.skipif(not _GLINER_AVAILABLE, reason="GLiNER not installed")
  ```
- Security-related changes require adversarial test cases

### Security Boundaries

> ⚠️ **Critical:** The following components require explicit maintainer review and must
> never be modified in a drive-by PR:

- HMAC key derivation and token generation logic
- Memory wipe / `destroy()` implementation
- Vault token regex pattern (`_VAULT_TOKEN_RE`)
- Input validation and injection prevention gates

### Pull Request Process

1. Fork the repository and create a feature branch
2. Write tests for your changes
3. Ensure all tests pass: `pytest tests/ -v`
4. Ensure linting passes: `ruff check sovereign_vault/`
5. Submit a PR with a clear description of what and why

### Reporting Security Issues

Please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.
Do **not** open public GitHub issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
