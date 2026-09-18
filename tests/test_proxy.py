"""Tests for the MCP proxy and new features (diff, CLI)."""
import json
import pytest
from sovereign_vault import VaultSession
from sovereign_vault.proxy import VaultProxy


class TestVaultDiff:
    """Test the new vault.diff() method."""

    def test_diff_shows_detected_entities(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            vault.tokenize("SSN: 123-45-6789 and email: test@example.com")
            diff_output = vault.diff()
            assert "DETECTED 2 entities" in diff_output
            assert "SSN" in diff_output
            assert "EMAIL" in diff_output
            assert "regex" in diff_output

    def test_diff_shows_original_and_tokenized(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            vault.tokenize("Contact alice@corp.com for details")
            diff_output = vault.diff()
            assert "ORIGINAL" in diff_output
            assert "TOKENIZED" in diff_output
            assert "alice@corp.com" in diff_output

    def test_diff_empty_when_no_pii(self):
        with VaultSession(use_gliner=False, use_ollama=False) as vault:
            vault.tokenize("The weather is nice today.")
            diff_output = vault.diff()
            assert "No entities detected" in diff_output


class TestVaultProxy:
    """Test the MCP middleware proxy."""

    def test_proxy_tokenizes_content(self):
        proxy = VaultProxy()
        safe, session_id = proxy.tokenize_content(
            "John Doe SSN: 123-45-6789"
        )
        assert "123-45-6789" not in safe
        assert "[[SSN_" in safe
        assert session_id  # non-empty

    def test_proxy_roundtrip(self):
        proxy = VaultProxy()
        original = "Contact alice@example.com about case 24-123456-CZ"
        safe, session_id = proxy.tokenize_content(original)
        assert "alice@example.com" not in safe

        # Simulate cloud returning the tokenized text unchanged
        restored = proxy.reconstruct_content(session_id, safe)
        assert "alice@example.com" in restored

    def test_proxy_intercept_jsonrpc(self):
        proxy = VaultProxy()
        message = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "resources/read",
            "params": {
                "content": "Patient SSN: 123-45-6789"
            },
        }
        result = proxy.intercept_jsonrpc(message)
        assert "123-45-6789" not in json.dumps(result)
        assert result["method"] == "resources/read"

    def test_proxy_skips_unprotected_methods(self):
        proxy = VaultProxy()
        message = {
            "jsonrpc": "2.0",
            "id": "req-2",
            "method": "notifications/initialized",
            "params": {"content": "SSN: 123-45-6789"},
        }
        result = proxy.intercept_jsonrpc(message)
        # Should pass through unchanged
        assert result["params"]["content"] == "SSN: 123-45-6789"

    def test_proxy_destroy_all(self):
        proxy = VaultProxy()
        proxy.tokenize_content("SSN: 123-45-6789")
        proxy.tokenize_content("Email: test@test.com")
        assert proxy.active_sessions() == 0  # tokenize_content doesn't track
        count = proxy.destroy_all()
        assert count == 0  # No tracked sessions (those are for jsonrpc flow)

    def test_proxy_jsonrpc_response_roundtrip(self):
        proxy = VaultProxy()
        # Intercept request
        request = {
            "jsonrpc": "2.0",
            "id": "42",
            "method": "tools/call",
            "params": {"text": "SSN: 123-45-6789"},
        }
        safe_request = proxy.intercept_jsonrpc(request)
        safe_text = safe_request["params"]["text"]
        assert "123-45-6789" not in safe_text

        # Simulate response with the tokenized text
        response = {
            "jsonrpc": "2.0",
            "id": "42",
            "result": {"output": safe_text},
        }
        restored_response = proxy.intercept_response("42", response)
        assert "123-45-6789" in json.dumps(restored_response)
