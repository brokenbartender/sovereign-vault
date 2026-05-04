"""
Basic sovereign-vault usage — no external dependencies required.
Run: python examples/basic_usage.py
"""

from sovereign_vault import VaultSession, ReconMode, SealMode

# ---------------------------------------------------------------------------
# Example 1: Round-trip tokenization (regex layer only)
# ---------------------------------------------------------------------------

print("=== Example 1: Basic round-trip ===\n")

raw = (
    "John transferred $50,000 from 192.168.1.45 via j.doe@firm.com. "
    "His SSN is 123-45-6789 and passport is AB1234567."
)

with VaultSession(use_gliner=False, use_ollama=False) as vault:
    abstract = vault.tokenize(raw)
    print("Original:  ", raw)
    print("Tokenized: ", abstract)
    print(f"Entities:   {len(vault)} vaulted")

    # Simulate cloud AI returning the abstract text unchanged
    cloud_response = abstract

    restored = vault.reconstruct(cloud_response)
    print("Restored:  ", restored)
    print("Match:     ", restored == raw)
    print()

# ---------------------------------------------------------------------------
# Example 2: LENIENT mode — cloud paraphrased, some tokens dropped
# ---------------------------------------------------------------------------

print("=== Example 2: Lenient reconstruction ===\n")

with VaultSession(use_gliner=False, use_ollama=False, recon_mode=ReconMode.LENIENT) as vault:
    abstract = vault.tokenize("Contact alice@example.com or 555-123-4567.")
    print("Tokenized:", abstract)

    # Cloud summarized and dropped the phone number token
    import re
    partial = re.sub(r'\[\[PHONE_[A-Z0-9_]+_[a-f0-9]{6}\]\]', '(phone redacted)', abstract)
    restored = vault.reconstruct(partial)
    print("Restored: ", restored)
    print()

# ---------------------------------------------------------------------------
# Example 3: SEALED mode — abstract output only, no reconstruction
# ---------------------------------------------------------------------------

print("=== Example 3: Sealed vault (abstract only) ===\n")

with VaultSession(use_gliner=False, use_ollama=False, seal_mode=SealMode.SEALED) as vault:
    abstract = vault.tokenize("SSN 999-88-7777, email sealed@example.com")
    print("Sealed abstract:", abstract)
    print("(Reconstruction intentionally disabled)")
    print()

# ---------------------------------------------------------------------------
# Example 4: Audit log — chain of custody without real values
# ---------------------------------------------------------------------------

print("=== Example 4: Audit log ===\n")

vault = VaultSession(use_gliner=False, use_ollama=False)
vault.tokenize("SSN 123-45-6789 and IP 10.0.0.1 and email audit@test.com")
for entry in vault.audit_log():
    print(f"  {entry['label']:15s} | layer={entry['source_layer']:6s} | confidence={entry['confidence']:.2f}")
vault.destroy()
