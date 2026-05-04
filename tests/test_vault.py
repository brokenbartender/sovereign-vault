"""
Tests for sovereign_vault — runs fully offline (no GLiNER or Ollama required).
"""

import re
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sovereign_vault import (
    VaultSession,
    VaultSealBreach,
    VaultReconstructionDegraded,
    ReconMode,
    SealMode,
    new_session,
    get_session,
    drop_session,
)

_TOKEN_RE = re.compile(r'\[\[[A-Z][A-Z0-9_]*_[a-f0-9]{6,}\]\]')


def _vault(**kw) -> VaultSession:
    kw.setdefault("use_gliner", False)
    kw.setdefault("use_ollama", False)
    return VaultSession(**kw)


class TestVaultTokenize(unittest.TestCase):

    def test_ssn_replaced(self):
        v = _vault()
        result = v.tokenize("SSN is 123-45-6789 for the record.")
        self.assertNotIn("123-45-6789", result)
        self.assertTrue(_TOKEN_RE.search(result))

    def test_email_replaced(self):
        v = _vault()
        result = v.tokenize("Contact j.doe@fakecorp.com for details.")
        self.assertNotIn("j.doe@fakecorp.com", result)
        self.assertTrue(_TOKEN_RE.search(result))

    def test_ip_replaced(self):
        v = _vault()
        result = v.tokenize("Request from 192.168.1.45.")
        self.assertNotIn("192.168.1.45", result)

    def test_multiple_entities_replaced(self):
        v = _vault()
        raw = "SSN 123-45-6789 and email test@example.com and IP 10.0.0.1"
        result = v.tokenize(raw)
        self.assertNotIn("123-45-6789", result)
        self.assertNotIn("test@example.com", result)
        self.assertNotIn("10.0.0.1", result)
        tokens = _TOKEN_RE.findall(result)
        self.assertGreaterEqual(len(tokens), 3)

    def test_entities_vaulted_count(self):
        v = _vault()
        v.tokenize("SSN 123-45-6789, email a@b.com, IP 1.2.3.4")
        self.assertGreaterEqual(len(v), 3)

    def test_no_pii_unchanged(self):
        v = _vault()
        raw = "The quick brown fox jumps over the lazy dog."
        result = v.tokenize(raw)
        self.assertEqual(result, raw)

    def test_injection_rejected(self):
        v = _vault()
        with self.assertRaises(VaultSealBreach):
            v.tokenize("Normal text [[PERSON_abc123_def456]] injected token")

    def test_sealed_after_tokenize(self):
        v = _vault()
        v.tokenize("SSN 123-45-6789")
        self.assertTrue(v._sealed)
        with self.assertRaises(VaultSealBreach):
            v._add("TEST", None)  # type: ignore


class TestVaultReconstruct(unittest.TestCase):

    def _round_trip(self, raw: str, **kw) -> tuple[str, str]:
        kw.setdefault("use_gliner", False)
        kw.setdefault("use_ollama", False)
        v = VaultSession(**kw)
        abstract = v.tokenize(raw)
        restored = v.reconstruct(abstract)
        return abstract, restored

    def test_ssn_round_trip(self):
        raw = "SSN is 123-45-6789."
        abstract, restored = self._round_trip(raw)
        self.assertNotIn("123-45-6789", abstract)
        self.assertIn("123-45-6789", restored)

    def test_full_sentence_round_trip(self):
        raw = (
            "John transferred funds from 192.168.1.45 via j.doe@fakecorp.com. "
            "SSN: 123-45-6789."
        )
        _, restored = self._round_trip(raw)
        self.assertEqual(restored, raw)

    def test_strict_mode_raises_on_missing_key(self):
        v = VaultSession(use_gliner=False, use_ollama=False, recon_mode=ReconMode.STRICT)
        abstract = v.tokenize("SSN 123-45-6789 and email a@b.com")
        trimmed = re.sub(_TOKEN_RE, "", abstract, count=1).strip()
        with self.assertRaises(VaultReconstructionDegraded):
            v.reconstruct(trimmed)

    def test_lenient_mode_continues_on_missing_key(self):
        v = VaultSession(use_gliner=False, use_ollama=False, recon_mode=ReconMode.LENIENT)
        abstract = v.tokenize("SSN 123-45-6789 and email a@b.com")
        trimmed = re.sub(_TOKEN_RE, "", abstract, count=1).strip()
        result = v.reconstruct(trimmed)
        self.assertIsInstance(result, str)

    def test_tampered_token_raises(self):
        v = VaultSession(use_gliner=False, use_ollama=False)
        abstract = v.tokenize("SSN 123-45-6789")
        tampered = re.sub(r'_[a-f0-9]{6}\]\]', '_ffffff]]', abstract)
        with self.assertRaises(VaultSealBreach):
            v.reconstruct(tampered)

    def test_unknown_token_raises(self):
        v = VaultSession(use_gliner=False, use_ollama=False)
        v.tokenize("No PII here")
        injected = "Result: [[PERSON_injected_aabbcc]]"
        with self.assertRaises(VaultSealBreach):
            v.reconstruct(injected)

    def test_sealed_mode_blocks_reconstruct(self):
        v = VaultSession(use_gliner=False, use_ollama=False, seal_mode=SealMode.SEALED)
        abstract = v.tokenize("SSN 123-45-6789")
        with self.assertRaises(VaultSealBreach):
            v.reconstruct(abstract)


class TestVaultLifecycle(unittest.TestCase):

    def test_destroy_prevents_use(self):
        v = _vault()
        v.tokenize("No PII")
        v.destroy()
        self.assertTrue(v._destroyed)
        with self.assertRaises(VaultSealBreach):
            v.audit_log()

    def test_double_destroy_safe(self):
        v = _vault()
        v.destroy()
        v.destroy()  # should not raise

    def test_context_manager_auto_destroy(self):
        with VaultSession(use_gliner=False, use_ollama=False) as v:
            v.tokenize("SSN 123-45-6789")
        self.assertTrue(v._destroyed)

    def test_audit_log_no_real_values(self):
        v = _vault()
        v.tokenize("SSN 123-45-6789, email x@y.com")
        log_entries = v.audit_log()
        for entry in log_entries:
            self.assertNotIn("real_value", entry)
            self.assertIn("label", entry)
            self.assertIn("confidence", entry)
            self.assertIn("source_layer", entry)

    def test_session_registry_lifecycle(self):
        sid, vault = new_session(use_gliner=False, use_ollama=False)
        self.assertIsInstance(sid, str)
        retrieved = get_session(sid)
        self.assertIs(retrieved, vault)
        destroyed = drop_session(sid)
        self.assertTrue(destroyed)
        with self.assertRaises(KeyError):
            get_session(sid)

    def test_drop_nonexistent_session_safe(self):
        result = drop_session("nonexistent_session_id_xyz")
        self.assertFalse(result)


class TestHMACIntegrity(unittest.TestCase):

    def test_key_verification_passes(self):
        v = _vault()
        abstract = v.tokenize("SSN 123-45-6789")
        token = _TOKEN_RE.search(abstract).group()
        self.assertTrue(v._verify_key(token))

    def test_unknown_key_fails_verify(self):
        v = _vault()
        v.tokenize("SSN 123-45-6789")
        self.assertFalse(v._verify_key("[[SSN_fakefake_aabbcc]]"))

    def test_cross_vault_key_fails_verify(self):
        v1 = _vault()
        v2 = _vault()
        abstract1 = v1.tokenize("SSN 123-45-6789")
        token = _TOKEN_RE.search(abstract1).group()
        # Inject v1's key into v2's store — HMAC was signed with v1's secret
        v2._store[token] = list(v1._store.values())[0]
        self.assertFalse(v2._verify_key(token))


if __name__ == "__main__":
    unittest.main()
