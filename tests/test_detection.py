"""Tests for the PII detection pipeline layers."""
import pytest
from sovereign_vault import VaultSession


class TestRegexDetection:
    """Layer 1: Deterministic regex pattern matching."""

    def test_ssn_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("SSN: 123-45-6789")
            assert "123-45-6789" not in result
            assert "[[SSN_" in result

    def test_email_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("Contact: alice@example.com")
            assert "alice@example.com" not in result
            assert "[[EMAIL_" in result

    def test_phone_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("Call me at 555-867-5309")
            assert "555-867-5309" not in result
            assert "[[PHONE_" in result

    def test_ip_address_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("Server at 192.168.1.100")
            assert "192.168.1.100" not in result
            assert "[[IP_ADDRESS_" in result

    def test_credit_card_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("Card: 4111 1111 1111 1111")
            assert "4111 1111 1111 1111" not in result

    def test_michigan_dl_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("DL: M123456789012")
            assert "M123456789012" not in result

    def test_court_case_detected(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            result = vault.tokenize("Case 24-123456-CZ")
            assert "24-123456-CZ" not in result

    def test_multiple_entities_same_text(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            text = "John (SSN: 123-45-6789, email: john@test.com)"
            result = vault.tokenize(text)
            assert "123-45-6789" not in result
            assert "john@test.com" not in result
            assert len(vault) >= 2

    def test_no_pii_passthrough(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            text = "The weather is nice today."
            result = vault.tokenize(text)
            assert result == text
            assert len(vault) == 0


class TestCrossEntityConsistency:
    """Verify that the same PII value gets the same token within a session."""

    def test_same_ssn_different_locations(self):
        """Same SSN appearing twice should get different tokens (unique per span)."""
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            text = "SSN: 123-45-6789. Confirmed SSN: 123-45-6789."
            result = vault.tokenize(text)
            assert "123-45-6789" not in result
            # Should have 2 vault entries for the 2 occurrences
            assert len(vault) == 2
