# sovereign-vault

**Reversible PII tokenization for LLM pipelines.**

Send documents containing real names, SSNs, emails, and account numbers to any cloud AI — Claude, Gemini, GPT — without exposing the actual values. The AI reasons about relationships and patterns on placeholder tokens. You reconstruct the real values locally after the response comes back.

```
pip install sovereign-vault
```

[![PyPI version](https://badge.fury.io/py/sovereign-vault.svg)](https://pypi.org/project/sovereign-vault/)
[![Downloads](https://img.shields.io/pypi/dm/sovereign-vault.svg)](https://pypi.org/project/sovereign-vault/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/brokenbartender/sovereign-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/brokenbartender/sovereign-vault/actions)

---

## The problem

You have documents with names, SSNs, emails, and account numbers. You need a cloud AI to analyze patterns, identify anomalies, or summarize findings. But you can't send the raw PII — compliance, legal, or common sense says no.

Standard redaction destroys the data permanently. The AI then can't reason about cross-entity relationships — *"the same person appears in both transactions"* becomes impossible once everything is `[REDACTED]`.

## The solution

Sovereign Vault replaces PII with **stable, HMAC-bound tokens** per session. The same value always maps to the same token, so AI can track relationships across a document. You reconstruct locally after the cloud call.

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

    response = your_llm_client.complete(abstract)  # cloud sees only tokens

    result = vault.reconstruct(response)  # real values restored locally
    # VaultSession.destroy() called automatically on context exit
```

No disk writes. No persistence between sessions. The mapping lives in RAM and is wiped on `destroy()`.

---

## Detection layers

Three layers run in sequence. Each is optional — the system never falls below Layer 1 reliability.

| Layer | Method | Confidence | Requires |
|-------|--------|-----------|---------|
| 1 — Regex | Deterministic structural patterns | 1.0 | Nothing (always active) |
| 2 — GLiNER | Probabilistic NLP NER | 0.85× model score | `pip install sovereign-vault[ner]` |
| 3 — Ollama | Contextual LLM sweep | 0.65 | Local Ollama + `pip install sovereign-vault[llm]` |

Layer 3 triggers only when GLiNER finds fewer than 3 entities — handles implicit identifiers and role references that regex and NER miss.

**Regex catches:** SSN, phone, email, IP address, credit card, passport, Michigan DL, court case numbers

**GLiNER catches:** person names, organizations, locations, addresses, DOB, financial accounts, government IDs, medical record numbers

**Ollama catches:** contextual identifiers — "the defendant", "Account #XYZ", implicit role-based references

---

## Installation

```bash
# Core (regex only — no dependencies)
pip install sovereign-vault

# With NLP entity recognition
pip install sovereign-vault[ner]

# With local LLM sweep (requires Ollama running locally)
pip install sovereign-vault[llm]

# Everything
pip install sovereign-vault[all]
```

---

## Usage

### Basic round-trip

```python
from sovereign_vault import VaultSession

raw = "Alice (alice@corp.com, SSN 123-45-6789) authorized the transfer."

with VaultSession(use_gliner=False, use_ollama=False) as vault:
    abstract = vault.tokenize(raw)
    # Send `abstract` to cloud AI
    cloud_response = call_your_cloud_ai(abstract)
    restored = vault.reconstruct(cloud_response)
```

### LENIENT mode — cloud paraphrased some tokens

```python
with VaultSession(recon_mode=ReconMode.LENIENT) as vault:
    abstract = vault.tokenize(raw)
    cloud_response = call_cloud(abstract)
    # Won't raise even if cloud dropped or paraphrased some tokens
    restored = vault.reconstruct(cloud_response)
```

### SEALED mode — abstract output only, no reconstruction

```python
with VaultSession(seal_mode=SealMode.SEALED) as vault:
    abstract = vault.tokenize(raw)
    # Reconstruction is intentionally disabled
    # Use when the abstract output IS the final product
```

### Audit log — chain of custody, no real values

```python
vault = VaultSession()
vault.tokenize(raw)
for entry in vault.audit_log():
    print(entry["label"], entry["source_layer"], entry["confidence"])
vault.destroy()
```

### Multi-session / server use

```python
from sovereign_vault import new_session, get_session, drop_session

sid, vault = new_session()
abstract = vault.tokenize(raw)
# ... pass sid to the next step in your pipeline ...
vault2 = get_session(sid)
restored = vault2.reconstruct(cloud_output)
drop_session(sid)  # destroys and deregisters
```

---

## Security model

- **RAM-only, session-scoped** — no disk writes, no persistence between sessions
- **HMAC-bound tokens** — each token carries an HMAC tag derived from a 32-byte session secret; tampered or injected tokens raise `VaultSealBreach`
- **Injection prevention** — input containing pre-existing `[[...]]` vault token format is rejected immediately
- **Entropy leak detection** — `reconstruct()` flags high-entropy tokens in cloud output that may be inferred identifiers
- **Best-effort memory wipe** — `destroy()` overwrites real values with random bytes before clearing

---

## Reconstruction modes

| Mode | Behavior |
|------|----------|
| `ReconMode.STRICT` (default) | Raises `VaultReconstructionDegraded` if cloud dropped any vault token |
| `ReconMode.LENIENT` | Allows partial reconstruction — logs missing tokens as warnings |
| `SealMode.SEALED` | Disables reconstruction entirely — raises `VaultSealBreach` if attempted |

---

## Use cases

- **Forensic e-discovery** — send document patterns to cloud AI without exposing real names or case numbers
- **HIPAA pipelines** — analyze medical records cross-entity without raw patient identifiers leaving your perimeter
- **Financial fraud detection** — transaction pattern analysis without raw account numbers
- **Gov/defense document processing** — reason about relationships in sensitive case files
- **Cross-agent PII passing** — sanitize data moving between local and cloud agents in an agentic pipeline

---

## Part of the LexiPro Sovereign OS

Sovereign Vault is a component of **[LexiPro](https://lexipro.online)** — a local-first agentic OS running 15 MCP servers, 228 tools, and 20 agent personas on sovereign hardware. In the full OS, it powers **Workflow O (Privacy Bridge)**: tokenize before any cloud call, reconstruct locally after, audit trail preserved.

Powered by:
- **[Anthropic Claude](https://anthropic.com)** — Tier 5 reasoning backbone for multi-file analysis
- **[Google Gemini](https://deepmind.google/technologies/gemini/)** — OSINT, research, and long-context processing
- **[Ollama](https://ollama.ai)** — Layer 3 local LLM sweep (Gemma, Llama) for contextual entity detection
- **[GLiNER](https://github.com/urchade/GLiNER)** — Layer 2 NLP NER for named entity recognition

---

## Contributing

Issues and PRs welcome. The detection layer system is designed for extension — add new regex patterns to `REGEX_PATTERNS`, new GLiNER entity types to `_GLINER_TYPES`, or swap the Ollama model via `ollama_model` parameter.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Broken Arrow Entertainment LLC](https://lexipro.online) · Sovereign Intelligence Systems Group
