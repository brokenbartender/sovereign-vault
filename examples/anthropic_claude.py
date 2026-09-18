"""Example: Using sovereign-vault with Anthropic Claude.

Tokenize PII before sending to Claude, then reconstruct locally.
Requires: pip install sovereign-vault anthropic
"""
import os
import anthropic
from sovereign_vault import VaultSession

def analyze_with_claude(document: str) -> str:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    
    with VaultSession(use_gliner=False, use_ollama=False) as vault:
        abstract = vault.tokenize(document)
        print(f"Entities vaulted: {len(vault)}")
        
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": f"Analyze this document:\n\n{abstract}"}],
        )
        cloud_output = response.content[0].text
        
        result = vault.reconstruct(cloud_output)
        return result

if __name__ == "__main__":
    doc = (
        "Patient Alice Johnson (DOB: 1985-03-22, MRN: MRN-00482913) "
        "was prescribed Lisinopril 10mg by Dr. Robert Chen "
        "at Memorial Hospital, 456 Oak Ave, Detroit MI 48201."
    )
    print(analyze_with_claude(doc))
