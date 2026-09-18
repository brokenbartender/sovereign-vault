"""
sovereign_vault.types — Core types, enums, exceptions, and dataclasses.
"""

import math
from dataclasses import dataclass
from enum import Enum, auto


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class VaultSealBreach(Exception):
    """Hard stop — vault integrity violated. Never catch and continue."""

class VaultReconstructionDegraded(Exception):
    """Cloud output mutated or dropped vault tokens (STRICT mode)."""


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

class ReconMode(Enum):
    STRICT  = auto()  # fail if any vault key is missing from cloud output
    LENIENT = auto()  # allow missing keys, flag and continue

class SealMode(Enum):
    NORMAL = auto()  # reconstruction available
    SEALED = auto()  # reconstruction disabled — abstract output only


# ---------------------------------------------------------------------------
# Internal span type
# ---------------------------------------------------------------------------

# Source reliability weights for span scoring
SOURCE_WEIGHTS: dict[str, float] = {
    "regex":  1.00,
    "gliner": 0.85,
    "ollama": 0.65,
}


@dataclass
class Span:
    """Internal detection span — represents a PII match from any layer."""
    start:      int
    end:        int
    value:      str
    label:      str
    source:     str
    confidence: float

    @property
    def score(self) -> float:
        length_bonus = min(len(self.value) / 50.0, 0.1)
        return (self.confidence * SOURCE_WEIGHTS.get(self.source, 0.5)) + length_bonus


# ---------------------------------------------------------------------------
# Vault entry
# ---------------------------------------------------------------------------

@dataclass
class VaultEntry:
    """Public record of a vaulted entity — real value + metadata."""
    real_value:   str
    label:        str
    source_layer: str
    confidence:   float
    span_score:   float
    char_start:   int
    char_end:     int
    hmac_tag:     str = ""
