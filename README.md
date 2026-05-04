# sovereign-vault

**Send documents containing PII to any cloud AI. Reconstruct the original values locally.**

Sovereign Vault replaces personally identifiable information with HMAC-bound placeholder tokens before you send to a cloud model, then reconstructs the real values locally after the response comes back. The AI reasons about relationships and patterns — without ever seeing the real data.

```python
pip install sovereign-vault
```

```python
from sovereign_vault import VaultSession

with VaultSession() as vault:
    abstract = vault.tokenize(
        "John Doe (SSN: 123-45-6789) transferred funds to "
        "Jane Smith (SSN: 987-65-4321) via john@firm.com on 2024-01-15."
    )
    # abstract:
    # "[[PERSON_A1B2C3D4_e5f6a7]] (SSN: [[SSN_B8C9D0E1_f2a3b4]]) transferred
    #  funds to [[PERSON_F5G6H7I8_j9k0l1]] (SSN: [[SSN_J2K3L4M5_n6o7p8]])
    #  via [[EMAIL_N9O0P1Q2_r3s4t5]] on 2024-01-15."

    # Cloud AI sees only tokens — can still reason about
    # "the same person appearing in two transactions"
    response = your_llm_client.complete(abstract)

    result = vault.reconstruct(response)  # real values restored locally
    # VaultSession.destroy() called automatically on context exit
```

## The problem

You have documents with names, SSNs, emails, and account numbers. You need a cloud AI to analyze patterns, identify anomalies, or summarize findings. But you can't send the raw PII — compliance, legal, or just common sense says no.

Most redaction tools destroy the data permanently (`[REDACTED]`, SHA-256 hash). The AI then loses the ability to reason about cross-entity relationships — *"the same person appears in both documents"* becomes impossible.

Sovereign Vault replaces PII with **stable, consistent tokens** per session. The same value always maps to the same token within a vault session, so AI can track relationships. Then you reconstruct locally.

## Detection layers

Three layers run in sequence. Each is optional with graceful degradation — the system never falls below Layer 1 reliability.

| Layer | Method | Confidence | Requires |
|-------|--------|-----------|---------|
| 1 — Regex | Deterministic structural patterns | 1.0 | Nothing (always active) |
| 2 — GLiNER | Probabilistic NLP NER | 0.85× model score | `pip install sovereign-vault[ner]` |
| 3 — Ollama | Contextual LLM sweep | 0.65 | Local Ollama + `pip install sovereign-vault[llm]` |

Layer 3 triggers only when GLiNER finds fewer than 3 entities — it handles implicit identifiers and role references that regex and NER miss.

**Regex catches:** SSN, phone, email, IP address, credit card, passport, Michigan DL, court case numbers

**GLiNER catches:** person names, organizations, locations, addresses, DOB, financial accounts, government IDs, medical record numbers

**Ollama catches:** contextual identifiers — "the defendant", "Account #XYZ", role-based references

## Security model

- **RAM-only, session-scoped** — no disk writes, no persistence between sessions
- **HMAC-SHA256 bound tokens** — each token carries a keyed tag; tampered or cross-vault tokens raise `VaultSealBreach` on reconstruct
- **Injection prevention** — input containing `[[...]]` vault token format is rejected before processing
- **Entropy leak detection** — flags high-entropy tokens in cloud output that may be model-inferred identifiers
- **Memory wipe on destroy** — `VaultSession.destroy()` overwrites real values with random bytes before clearing

For hard egress blocking (the data must *never* leave), use a separate gate before calling `tokenize()`. Sovereign Vault is for the use case where you need cloud reasoning *with* reconstruction.

## Modes

```python
from sovereign_vault import VaultSession, ReconMode, SealMode

# STRICT (default) — raise VaultReconstructionDegraded if cloud drops any token
vault = VaultSession(recon_mode=ReconMode.STRICT)

# LENIENT — allow partial reconstruction, log missing tokens
vault = VaultSession(recon_mode=ReconMode.LENIENT)

# SEALED — disable reconstruction entirely (abstract output only, irreversible)
vault = VaultSession(seal_mode=SealMode.SEALED)
```

## Session registry (server / multi-call use)

```python
from sovereign_vault import new_session, get_session, drop_session

# Create and register a named session
session_id, vault = new_session()
abstract = vault.tokenize(document)

# ... in another handler ...
vault = get_session(session_id)
result = vault.reconstruct(cloud_response)

# Always clean up
drop_session(session_id)
```

## Audit log

```python
with VaultSession() as vault:
    vault.tokenize("SSN 123-45-6789, email audit@example.com")
    for entry in vault.audit_log():
        print(entry)
    # {'key': '[[SSN_...]]', 'label': 'SSN', 'source_layer': 'regex',
    #  'confidence': 1.0, 'span_score': 1.04, 'char_start': 4, 'char_end': 15}
    # No real values in the audit log — safe for compliance logging.
```

## Use cases

- **Forensic e-discovery** — analyze document patterns in cloud AI without exposing real names or case numbers
- **HIPAA/GDPR compliance** — LLM pipelines for healthcare or finance that must not send PII to cloud providers
- **Financial fraud detection** — transaction pattern analysis without raw account numbers
- **Government audit pipelines** — reason about relationships in sensitive case files
- **Cross-agent sensitive data passing** — pass context between AI agents without leaking identifiers

## Install

```bash
# Regex layer only (no extra deps)
pip install sovereign-vault

# + GLiNER NER layer
pip install sovereign-vault[ner]

# + Ollama contextual sweep (requires local Ollama running)
pip install sovereign-vault[llm]

# Everything
pip install sovereign-vault[all]
```

Requires Python 3.10+.

## Running tests

```bash
python -m pytest tests/ -v
# or
python -m unittest discover tests/
```

All 24 tests run fully offline — no GLiNER download or Ollama required.

## License

MIT
