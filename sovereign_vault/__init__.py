"""
Sovereign Vault — Reversible Privacy Tokenization for LLM Pipelines (v1.0)

Instead of destroying PII with irreversible redaction, this module replaces
sensitive values with HMAC-bound placeholder tokens so cloud AI can reason
about relationships (cross-entity, timeline, causality) without seeing real
values — then reconstructs locally.

Detection layers (each optional, graceful degradation):
  Layer 1 — Regex: deterministic, confidence=1.0
  Layer 2 — GLiNER: probabilistic NLP NER, confidence from model score
  Layer 3 — Ollama: contextual LLM sweep, confidence=0.65

Vault lifecycle:
  vault = VaultSession.create()
  abstract = vault.tokenize(raw_text)
  # ... send abstract to cloud ...
  restored = vault.reconstruct(cloud_output)
  vault.destroy()

Or use as context manager (auto-destroy on exit):
  with VaultSession() as vault:
      abstract = vault.tokenize(raw_text)
      restored = vault.reconstruct(call_cloud(abstract))
"""

import re
import uuid
import hmac
import hashlib
import json
import logging
import secrets
import math
from dataclasses import dataclass
from enum import Enum, auto

__version__ = "1.0.0"
__all__ = [
    "VaultSession",
    "VaultSealBreach",
    "VaultReconstructionDegraded",
    "coverage_report",
    "ReconMode",
    "SealMode",
    "VaultEntry",
    "new_session",
    "get_session",
    "drop_session",
]

log = logging.getLogger("sovereign_vault")

# ---------------------------------------------------------------------------
# Optional ML dependencies
# ---------------------------------------------------------------------------

try:
    from gliner import GLiNER as _GLiNER
    _GLINER_AVAILABLE = True
except ImportError:
    _GLINER_AVAILABLE = False

try:
    import ollama as _ollama
    _OLLAMA_AVAILABLE = True
except ImportError:
    _OLLAMA_AVAILABLE = False

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

# Source reliability weights for span scoring
SOURCE_WEIGHTS: dict[str, float] = {
    "regex":  1.00,
    "gliner": 0.85,
    "ollama": 0.65,
}

# Vault token format — pre-screened on input to block injection
_VAULT_TOKEN_RE = re.compile(r'\[\[[A-Z][A-Za-z0-9_]*_[a-f0-9]{6,}\]\]')

# GLiNER entity types
_GLINER_TYPES = [
    "person", "organization", "location", "address",
    "date of birth", "financial account",
    "government id", "vehicle registration",
    "medical record number",
]

# ---------------------------------------------------------------------------
# Internal span type
# ---------------------------------------------------------------------------

@dataclass
class _Span:
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
    real_value:   str
    label:        str
    source_layer: str
    confidence:   float
    span_score:   float
    char_start:   int
    char_end:     int
    hmac_tag:     str = ""

# ---------------------------------------------------------------------------
# VaultSession — one per pipeline run
# ---------------------------------------------------------------------------

class VaultSession:
    """
    RAM-only, session-scoped reversible tokenization store.
    Keys are HMAC-bound with a session-unique 32-byte secret.
    """

    def __init__(
        self,
        recon_mode: ReconMode = ReconMode.STRICT,
        seal_mode:  SealMode  = SealMode.NORMAL,
        use_gliner: bool = True,
        use_ollama: bool = True,
        gliner_model: str = "knowledgator/gliner-pii-base-v1.0",
        ollama_model: str = "gemma2:latest",
        gliner_threshold: float = 0.4,
        ollama_trigger_threshold: int = 3,
    ):
        self._secret: bytes = secrets.token_bytes(32)
        self._store:  dict[str, VaultEntry] = {}
        self._sealed: bool = False
        self._destroyed: bool = False
        self.recon_mode = recon_mode
        self.seal_mode  = seal_mode
        self.gliner_threshold = gliner_threshold
        self.ollama_trigger_threshold = ollama_trigger_threshold
        self.ollama_model = ollama_model
        self._gliner = None

        if use_gliner and _GLINER_AVAILABLE:
            try:
                self._gliner = _GLiNER.from_pretrained(gliner_model)
            except Exception as e:
                log.warning("GLiNER load failed (continuing regex-only): %s", e)

        self._use_ollama = use_ollama and _OLLAMA_AVAILABLE

    @classmethod
    def create(cls, **kwargs) -> "VaultSession":
        return cls(**kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.destroy()

    def _assert_alive(self):
        if self._destroyed:
            raise VaultSealBreach("VaultSession has been destroyed.")

    def _add(self, label: str, entry: VaultEntry) -> str:
        self._assert_alive()
        if self._sealed:
            raise VaultSealBreach("Vault is sealed — no new entries.")
        short_id = uuid.uuid4().hex[:8].upper()
        base_key = f"{label.upper()}_{short_id}"
        tag = hmac.new(self._secret, base_key.encode(), hashlib.sha256).hexdigest()[:6]
        key = f"[[{base_key}_{tag}]]"
        entry.hmac_tag = tag
        self._store[key] = entry
        return key

    def _verify_key(self, key: str) -> bool:
        if key not in self._store:
            return False
        inner = key[2:-2]
        parts = inner.rsplit("_", 1)
        if len(parts) != 2:
            return False
        expected = hmac.new(
            self._secret, parts[0].encode(), hashlib.sha256
        ).hexdigest()[:6]
        return hmac.compare_digest(parts[1], expected)

    def _apply_spans(self, text: str, spans: list[_Span]) -> str:
        """Merge overlapping spans (highest score wins), apply to text."""
        if not spans:
            return text
        spans_sorted = sorted(spans, key=lambda s: (s.start, -s.score))
        merged: list[_Span] = []
        last_end = -1
        for span in spans_sorted:
            if span.start >= last_end:
                merged.append(span)
                last_end = span.end
            elif merged and span.score > merged[-1].score:
                merged[-1] = span
                last_end = span.end

        result = []
        cursor = 0
        for span in merged:
            result.append(text[cursor:span.start])
            entry = VaultEntry(
                real_value=span.value,
                label=span.label,
                source_layer=span.source,
                confidence=span.confidence,
                span_score=span.score,
                char_start=span.start,
                char_end=span.end,
            )
            key = self._add(span.label, entry)
            result.append(key)
            cursor = span.end
        result.append(text[cursor:])
        return "".join(result)

    def _layer_regex(self, text: str) -> str:
        spans = []
        for label, pattern in REGEX_PATTERNS.items():
            for m in re.finditer(pattern, text):
                if _VAULT_TOKEN_RE.search(m.group()):
                    continue
                spans.append(_Span(
                    start=m.start(), end=m.end(),
                    value=m.group(), label=label,
                    source="regex", confidence=1.0,
                ))
        return self._apply_spans(text, spans)

    def _layer_gliner(self, text: str) -> tuple[str, int]:
        if not self._gliner:
            return text, 0
        try:
            raw = self._gliner.predict_entities(
                text, _GLINER_TYPES, threshold=self.gliner_threshold
            )
            seen: set[tuple[int, int]] = set()
            spans = []
            for ent in raw:
                k = (ent["start"], ent["end"])
                if k not in seen:
                    seen.add(k)
                    spans.append(_Span(
                        start=ent["start"], end=ent["end"],
                        value=ent["text"],
                        label=ent["label"].upper().replace(" ", "_"),
                        source="gliner",
                        confidence=ent.get("score", 0.8),
                    ))
            return self._apply_spans(text, spans), len(spans)
        except Exception as e:
            raise VaultSealBreach(f"GLiNER layer failed: {e}") from e

    def _layer_ollama(self, text: str) -> str:
        if not self._use_ollama:
            return text
        try:
            prompt = (
                "Forensic redaction assistant. Text has had structural PII replaced "
                "with [[PLACEHOLDER]] tokens.\n"
                "Identify any REMAINING sensitive values: implicit identifiers, "
                "role references, account numbers, anything identifying a person or org.\n"
                "Return ONLY a JSON array of exact strings from the text. "
                "Return [] if nothing remains.\n"
                "Do NOT include [[PLACEHOLDER]] tokens.\n\n"
                f"Text:\n{text}\n\nJSON:"
            )
            response = _ollama.generate(
                model=self.ollama_model,
                prompt=prompt,
                options={"temperature": 0.0},
            )
            raw = response["response"].strip()
            start = raw.find("[")
            end   = raw.rfind("]") + 1
            if start == -1 or end == 0:
                return text
            entities: list[str] = json.loads(raw[start:end])
            spans = []
            for val in sorted(set(entities), key=len, reverse=True):
                if not val or "[[" in val:
                    continue
                for m in re.finditer(re.escape(val), text):
                    spans.append(_Span(
                        start=m.start(), end=m.end(),
                        value=val, label="CONTEXTUAL",
                        source="ollama", confidence=0.65,
                    ))
            return self._apply_spans(text, spans)
        except Exception as e:
            log.warning("Ollama layer failed (non-fatal, continuing): %s", e)
            return text

    @staticmethod
    def _check_output_entropy(text: str, threshold: float = 4.2) -> list[str]:
        """Flag high-entropy tokens in cloud output that look like inferred IDs."""
        suspicious = []
        for token in text.split():
            clean = re.sub(r'[^\w]', '', token)
            if len(clean) >= 8:
                freq = {}
                for c in clean:
                    freq[c] = freq.get(c, 0) + 1
                length = len(clean)
                entropy = -sum(
                    (f / length) * math.log2(f / length)
                    for f in freq.values()
                )
                if entropy > threshold:
                    if not re.match(r'^[A-Z]+_[a-f0-9]{8}_[a-f0-9]{6}$', clean):
                        suspicious.append(token)
        return suspicious

    def tokenize(self, raw_text: str) -> str:
        """
        Run full detection pipeline. Returns abstract text with vault tokens.
        Call reconstruct() after cloud processing to restore real values.
        """
        self._assert_alive()
        if not raw_text or not raw_text.strip():
            raise ValueError("Input is empty.")

        # Block pre-existing vault tokens (injection prevention)
        if _VAULT_TOKEN_RE.search(raw_text):
            raise VaultSealBreach(
                "Input contains reserved [[...]] vault token format. "
                "Possible injection attempt — input rejected."
            )

        text = self._layer_regex(raw_text)

        gliner_count = 0
        if self._gliner:
            text, gliner_count = self._layer_gliner(text)

        if self._use_ollama and gliner_count < self.ollama_trigger_threshold:
            text = self._layer_ollama(text)

        self._sealed = True
        log.info("Tokenization complete. %d entities vaulted.", len(self._store))
        return text

    def reconstruct(self, abstract_text: str) -> str:
        """
        Restore real values from vault into cloud output.
        Verifies HMAC integrity on all tokens before restoring.
        Raises VaultSealBreach on unknown/tampered tokens.
        Raises VaultReconstructionDegraded in STRICT mode if tokens are missing.
        """
        self._assert_alive()
        if self.seal_mode == SealMode.SEALED:
            raise VaultSealBreach(
                "Reconstruction disabled — vault is in SEALED execution mode."
            )

        suspicious = self._check_output_entropy(abstract_text)
        if suspicious:
            log.warning(
                "Entropy leak detection: %d suspicious high-entropy tokens in "
                "cloud output: %s", len(suspicious), suspicious[:5]
            )

        found_keys = set(re.findall(r'\[\[[A-Z][A-Za-z0-9_]*_[a-f0-9]{6}\]\]', abstract_text))
        for fk in found_keys:
            if fk not in self._store:
                raise VaultSealBreach(
                    f"Unknown placeholder in cloud output: {fk} — possible injection."
                )
            if not self._verify_key(fk):
                raise VaultSealBreach(
                    f"HMAC verification failed: {fk} — possible tampering."
                )

        missing = [k for k in self._store if k not in abstract_text]
        if missing:
            if self.recon_mode == ReconMode.STRICT:
                raise VaultReconstructionDegraded(
                    f"STRICT mode: {len(missing)} vault keys missing from cloud output. "
                    f"Cloud model may have paraphrased or dropped references. "
                    f"Missing: {missing[:3]}{'...' if len(missing) > 3 else ''}"
                )
            log.warning(
                "LENIENT mode: %d vault keys missing — reconstruction partial.",
                len(missing)
            )

        result = abstract_text
        for key in sorted(self._store.keys(), key=len, reverse=True):
            if key in result:
                result = result.replace(key, self._store[key].real_value)
        return result

    def audit_log(self) -> list[dict]:
        """Safe audit trail — no real values included."""
        self._assert_alive()
        return [
            {
                "key":          k,
                "label":        v.label,
                "source_layer": v.source_layer,
                "confidence":   v.confidence,
                "span_score":   v.span_score,
                "char_start":   v.char_start,
                "char_end":     v.char_end,
            }
            for k, v in self._store.items()
        ]

    def coverage_report(self) -> dict:
        """Per-layer entity counts, confidence distribution, and detection coverage.

        Call after tokenize() and before sending to cloud to assess detection
        quality. Answers: how confident should I be that all PII was caught?
        """
        self._assert_alive()
        by_layer: dict[str, dict] = {}
        confidence_buckets = {
            "high (>0.85)":      0,
            "medium (0.50-0.85)": 0,
            "low (<0.50)":       0,
        }
        for entry in self._store.values():
            layer = entry.source_layer
            if layer not in by_layer:
                by_layer[layer] = {"count": 0, "labels": {}}
            by_layer[layer]["count"] += 1
            by_layer[layer]["labels"][entry.label] = (
                by_layer[layer]["labels"].get(entry.label, 0) + 1
            )
            c = entry.confidence
            if c > 0.85:
                confidence_buckets["high (>0.85)"] += 1
            elif c >= 0.50:
                confidence_buckets["medium (0.50-0.85)"] += 1
            else:
                confidence_buckets["low (<0.50)"] += 1

        layers_active = list(by_layer.keys())
        return {
            "total_entities_vaulted":   len(self._store),
            "layers_active":            layers_active,
            "by_layer":                 by_layer,
            "confidence_distribution":  confidence_buckets,
            "recommendation": (
                "Consider enabling GLiNER (pip install sovereign-vault[ner]) "
                "for contextual NER detection."
                if "gliner" not in layers_active and "ollama" not in layers_active
                else "All available detection layers active."
            ),
        }

    def destroy(self):
        """Best-effort memory wipe. Overwrites real values before clearing."""
        if self._destroyed:
            return
        for entry in self._store.values():
            entry.real_value = secrets.token_hex(len(entry.real_value))
            entry.hmac_tag   = ""
        self._store.clear()
        self._secret = b""
        self._destroyed = True
        log.info("VaultSession destroyed and wiped.")

    def __len__(self):
        return len(self._store)


# ---------------------------------------------------------------------------
# Module-level session registry (for multi-call / server use cases)
# ---------------------------------------------------------------------------

_sessions: dict[str, VaultSession] = {}


def get_session(session_id: str) -> VaultSession:
    """Retrieve an active vault session by ID. Raises KeyError if not found."""
    if session_id not in _sessions:
        raise KeyError(f"No active vault session: {session_id}")
    return _sessions[session_id]


def new_session(**kwargs) -> tuple[str, VaultSession]:
    """Create a new vault session and register it. Returns (session_id, vault)."""
    session_id = uuid.uuid4().hex[:12]
    vault = VaultSession(**kwargs)
    _sessions[session_id] = vault
    return session_id, vault


def drop_session(session_id: str) -> bool:
    """Destroy and deregister a session. Returns True if it existed."""
    vault = _sessions.pop(session_id, None)
    if vault is not None:
        vault.destroy()
        return True
    return False
