"""
sovereign_vault.patterns — Regex patterns and detection constants.
"""

import re

# ---------------------------------------------------------------------------
# Regex patterns — deterministic structural PII
# ---------------------------------------------------------------------------

REGEX_PATTERNS: dict[str, str] = {
    "SSN":         r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "MICHIGAN_DL": r"\b[A-Z]\d{12}\b",
    "COURT_CASE":  r"\b\d{2}-\d{6}-[A-Z]{2}\b",
    "PHONE":       r"\b(?:\+1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "EMAIL":       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]?){13,16}\b",
    "IP_ADDRESS":  r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "PASSPORT":    r"\b[A-Z]{1,2}[0-9]{6,9}\b",
}

# Vault token format — pre-screened on input to block injection
VAULT_TOKEN_RE = re.compile(r'\[\[[A-Z][A-Za-z0-9_]*_[a-f0-9]{6,}\]\]')

# GLiNER entity types
GLINER_TYPES = [
    "person", "organization", "location", "address",
    "date of birth", "financial account",
    "government id", "vehicle registration",
    "medical record number",
]
