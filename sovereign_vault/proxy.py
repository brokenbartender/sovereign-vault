"""
sovereign_vault.proxy — MCP Middleware Proxy for zero-trust PII interception.

Sits between any MCP client and MCP server, transparently tokenizing PII
in JSON-RPC 2.0 payloads before they reach the LLM context window.

Usage:
    from sovereign_vault.proxy import VaultProxy

    proxy = VaultProxy()
    safe_payload = proxy.intercept_request(raw_payload)
    # ... send safe_payload to LLM ...
    restored = proxy.intercept_response(session_id, llm_response)
"""

import json
import logging
import re
from typing import Any, Optional

from .session import VaultSession, new_session, get_session, drop_session
from .types import VaultSealBreach, ReconMode

log = logging.getLogger("sovereign_vault.proxy")


class VaultProxy:
    """
    Zero-trust MCP middleware proxy.

    Intercepts JSON-RPC 2.0 messages and applies reversible PII tokenization
    to payloads before they reach the LLM. Supports method-level policies
    and automatic session lifecycle management.

    Intercepted methods:
        - tools/call: Tokenize tool arguments and results
        - resources/read: Tokenize resource content before model ingestion
        - prompts/get: Tokenize prompt template content

    Example:
        proxy = VaultProxy()
        result = proxy.intercept_resource(resource_content)
        # result.session_id can be used to reconstruct later
        # result.safe_content is PII-free
    """

    def __init__(
        self,
        use_gliner: bool = False,
        use_ollama: bool = False,
        recon_mode: ReconMode = ReconMode.LENIENT,
        protected_methods: Optional[set[str]] = None,
    ):
        self.use_gliner = use_gliner
        self.use_ollama = use_ollama
        self.recon_mode = recon_mode
        self.protected_methods = protected_methods or {
            "tools/call",
            "resources/read",
            "prompts/get",
        }
        self._active_sessions: dict[str, str] = {}  # request_id -> session_id

    def should_intercept(self, method: str) -> bool:
        """Check if a JSON-RPC method should be intercepted for PII tokenization."""
        return method in self.protected_methods

    def intercept_jsonrpc(self, message: dict[str, Any]) -> dict[str, Any]:
        """
        Intercept a JSON-RPC 2.0 request message.

        Scans string fields in the params for PII and replaces with vault tokens.
        Returns the modified message with a session_id attached for later reconstruction.
        """
        method = message.get("method", "")
        if not self.should_intercept(method):
            return message

        request_id = str(message.get("id", ""))
        session_id, vault = new_session(
            use_gliner=self.use_gliner,
            use_ollama=self.use_ollama,
            recon_mode=self.recon_mode,
        )

        # Deep-tokenize all string values in params
        params = message.get("params", {})
        tokenized_params = self._tokenize_recursive(vault, params)

        self._active_sessions[request_id] = session_id

        result = {**message, "params": tokenized_params}
        log.info(
            "Intercepted %s (request_id=%s): %d entities vaulted",
            method, request_id, len(vault),
        )
        return result

    def intercept_response(
        self, request_id: str, response: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Intercept a JSON-RPC 2.0 response and reconstruct PII.

        Finds the vault session associated with the original request
        and restores real values in the response payload.
        """
        session_id = self._active_sessions.pop(request_id, None)
        if session_id is None:
            return response

        try:
            vault = get_session(session_id)
        except KeyError:
            log.warning("Session %s expired before response arrived", session_id)
            return response

        result_data = response.get("result", {})
        restored = self._reconstruct_recursive(vault, result_data)
        drop_session(session_id)

        return {**response, "result": restored}

    def tokenize_content(self, content: str) -> tuple[str, str]:
        """
        Tokenize a raw content string. Returns (safe_content, session_id).

        Use for direct content interception without JSON-RPC framing.
        Call reconstruct_content(session_id, llm_output) to restore.
        """
        session_id, vault = new_session(
            use_gliner=self.use_gliner,
            use_ollama=self.use_ollama,
            recon_mode=self.recon_mode,
        )
        safe = vault.tokenize(content)
        return safe, session_id

    def reconstruct_content(self, session_id: str, content: str) -> str:
        """Reconstruct PII in content using a previously created session."""
        vault = get_session(session_id)
        result = vault.reconstruct(content)
        drop_session(session_id)
        return result

    def active_sessions(self) -> int:
        """Number of active vault sessions waiting for responses."""
        return len(self._active_sessions)

    def destroy_all(self) -> int:
        """Destroy all active sessions. Returns count of sessions destroyed."""
        count = 0
        for session_id in list(self._active_sessions.values()):
            if drop_session(session_id):
                count += 1
        self._active_sessions.clear()
        return count

    # --- Internal helpers ---

    def _tokenize_recursive(self, vault: VaultSession, obj: Any) -> Any:
        """Recursively tokenize all string values in a nested structure."""
        if isinstance(obj, str):
            if len(obj.strip()) < 3:
                return obj
            try:
                return vault.tokenize(obj)
            except (ValueError, VaultSealBreach):
                return obj  # Skip empty or already-tokenized strings
        elif isinstance(obj, dict):
            return {k: self._tokenize_recursive(vault, v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._tokenize_recursive(vault, item) for item in obj]
        return obj

    def _reconstruct_recursive(self, vault: VaultSession, obj: Any) -> Any:
        """Recursively reconstruct all string values in a nested structure."""
        if isinstance(obj, str):
            try:
                return vault.reconstruct(obj)
            except Exception:
                return obj
        elif isinstance(obj, dict):
            return {k: self._reconstruct_recursive(vault, v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._reconstruct_recursive(vault, item) for item in obj]
        return obj
