"""
Sovereign Vault — Reversible Privacy Tokenization for LLM Pipelines (v1.1)

Instead of destroying PII with irreversible redaction, this module replaces
sensitive values with HMAC-bound placeholder tokens so cloud AI can reason
about relationships (cross-entity, timeline, causality) without seeing real
values — then reconstructs locally.

Detection layers (each optional, graceful degradation):
  Layer 1 — Regex: deterministic, confidence=1.0
  Layer 2 — GLiNER: probabilistic NLP NER, confidence from model score
  Layer 3 — Ollama: contextual LLM sweep, confidence=0.65

Usage:
  with VaultSession() as vault:
      abstract = vault.tokenize(raw_text)
      restored = vault.reconstruct(call_cloud(abstract))
"""

__version__ = "1.1.0"

# Re-export public API from submodules
from .types import (
    VaultSealBreach,
    VaultReconstructionDegraded,
    ReconMode,
    SealMode,
    VaultEntry,
    SOURCE_WEIGHTS,
)
from .patterns import REGEX_PATTERNS
from .session import (
    VaultSession,
    new_session,
    get_session,
    drop_session,
)
from .proxy import VaultProxy

__all__ = [
    "VaultSession",
    "VaultProxy",
    "VaultSealBreach",
    "VaultReconstructionDegraded",
    "coverage_report",
    "ReconMode",
    "SealMode",
    "VaultEntry",
    "new_session",
    "get_session",
    "drop_session",
    "REGEX_PATTERNS",
    "SOURCE_WEIGHTS",
]
