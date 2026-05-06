# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

Do not open a public issue for security vulnerabilities.

Report privately via GitHub Security Advisories:
[Report a vulnerability](https://github.com/brokenbartender/sovereign-vault/security/advisories/new)

Or email: codymckenzie23@gmail.com

Response within 48 hours, patch within 7 days for confirmed issues.

## Threat Model

- RAM-only storage: no vault state written to disk
- Session-scoped HMAC keys: tokens from one session cannot be reconstructed in another
- No network calls in core mode: regex layer runs fully offline
- Explicit destroy(): vault RAM cleared on vault.destroy() or context manager exit

## Known Limitations

- Vault tokens are reversible by design. Do not share the VaultSession object across trust boundaries.
- GLiNER and Ollama layers are probabilistic and may miss novel PII patterns.
- This library is not a substitute for legal advice on GDPR/HIPAA compliance.
