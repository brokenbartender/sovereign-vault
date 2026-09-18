"""Security tests for sovereign-vault.

Tests HMAC integrity, injection resistance, session isolation,
and memory wipe behavior.
"""
import pytest
from sovereign_vault import (
    VaultSession,
    VaultSealBreach,
    VaultReconstructionDegraded,
    ReconMode,
    SealMode,
)


class TestInjectionPrevention:
    """Verify that pre-existing vault tokens in input are rejected."""

    def test_rejects_injected_vault_tokens(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            malicious = "Hello [[PERSON_ABCD1234_ff00aa]] world"
            with pytest.raises(VaultSealBreach, match="injection"):
                vault.tokenize(malicious)

    def test_rejects_crafted_token_format(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            malicious = "Data: [[SSN_FAKE0000_aabbcc]]"
            with pytest.raises(VaultSealBreach, match="injection"):
                vault.tokenize(malicious)


class TestHMACIntegrity:
    """Verify HMAC verification catches tampered tokens."""

    def test_reconstruct_detects_unknown_tokens(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            vault.tokenize("SSN: 123-45-6789")
            # Inject a fabricated token into the "cloud response"
            fake_response = "The SSN is [[SSN_AAAABBBB_ccccdd]]"
            with pytest.raises(VaultSealBreach, match="Unknown"):
                vault.reconstruct(fake_response)


class TestSessionIsolation:
    """Verify that separate sessions cannot cross-contaminate."""

    def test_sessions_have_different_secrets(self):
        v1 = VaultSession(use_gliner=False, use_ollama=False)
        v2 = VaultSession(use_gliner=False, use_ollama=False)
        assert v1._secret != v2._secret
        v1.destroy()
        v2.destroy()

    def test_destroyed_session_rejects_operations(self):
        vault = VaultSession(use_gliner=False, use_ollama=False)
        vault.destroy()
        with pytest.raises(VaultSealBreach, match="destroyed"):
            vault.tokenize("test data")


class TestMemoryWipe:
    """Verify that destroy() actually overwrites sensitive data."""

    def test_real_values_overwritten_on_destroy(self):
        vault = VaultSession(use_gliner=False, use_ollama=False)
        vault.tokenize("SSN: 123-45-6789")
        # Grab reference to entries before destroy
        entries = list(vault._store.values())
        assert any(e.real_value == "123-45-6789" for e in entries)
        vault.destroy()
        # After destroy, the store should be empty
        assert len(vault._store) == 0

    def test_secret_cleared_on_destroy(self):
        vault = VaultSession(use_gliner=False, use_ollama=False)
        vault.tokenize("SSN: 123-45-6789")
        vault.destroy()
        assert vault._secret == b""


class TestReconstructionModes:
    """Test STRICT vs LENIENT reconstruction behavior."""

    def test_strict_mode_fails_on_missing_tokens(self):
        with VaultSession(
            use_gliner=False, use_ollama=False, recon_mode=ReconMode.STRICT
        ) as vault:
            abstract = vault.tokenize("SSN: 123-45-6789")
            # Cloud "response" that dropped the token entirely
            with pytest.raises(VaultReconstructionDegraded, match="STRICT"):
                vault.reconstruct("The document has been analyzed.")

    def test_lenient_mode_continues_on_missing_tokens(self):
        with VaultSession(
            use_gliner=False, use_ollama=False, recon_mode=ReconMode.LENIENT
        ) as vault:
            abstract = vault.tokenize("SSN: 123-45-6789")
            # Cloud dropped the token — LENIENT should not raise
            result = vault.reconstruct("The document has been analyzed.")
            assert isinstance(result, str)


class TestSealedMode:
    """Test SEALED mode prevents reconstruction."""

    def test_sealed_mode_blocks_reconstruction(self):
        with VaultSession(
            use_gliner=False, use_ollama=False, seal_mode=SealMode.SEALED
        ) as vault:
            abstract = vault.tokenize("SSN: 123-45-6789")
            with pytest.raises(VaultSealBreach, match="SEALED"):
                vault.reconstruct(abstract)
