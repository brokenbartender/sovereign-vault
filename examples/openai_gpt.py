"""Example: Using sovereign-vault with OpenAI GPT.

Tokenize PII before sending to GPT, then reconstruct the response locally.
Requires: pip install sovereign-vault openai
"""
import os
from openai import OpenAI
from sovereign_vault import VaultSession

def analyze_with_gpt(document: str) -> str:
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    
    with VaultSession(use_gliner=False, use_ollama=False) as vault:
        # Tokenize — real PII replaced with [[PLACEHOLDER]] tokens
        abstract = vault.tokenize(document)
        print(f"Entities vaulted: {len(vault)}")
        print(f"Sent to cloud:\n{abstract}\n")
        
        # Send tokenized text to GPT — no real PII leaves your machine
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "Analyze the document and identify key findings."},
                {"role": "user", "content": abstract},
            ],
        )
        cloud_output = response.choices[0].message.content
        
        # Reconstruct — [[PLACEHOLDER]] tokens restored to real values
        result = vault.reconstruct(cloud_output)
        return result

if __name__ == "__main__":
    doc = (
        "John Smith (SSN: 123-45-6789, email: john@example.com) "
        "transferred $50,000 to Jane Doe (SSN: 987-65-4321) "
        "on 2024-03-15 via account ending in 4532."
    )
    print(analyze_with_gpt(doc))
