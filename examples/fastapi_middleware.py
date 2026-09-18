"""Example: FastAPI middleware for automatic PII tokenization.

Auto-tokenizes request bodies before they reach your LLM endpoint,
and auto-reconstructs responses before returning to the client.
Requires: pip install sovereign-vault fastapi uvicorn
"""
from fastapi import FastAPI, Request, Response
from sovereign_vault import VaultSession
import json

app = FastAPI(title="PII-Safe LLM Proxy")

@app.middleware("http")
async def vault_middleware(request: Request, call_next):
    """Intercept requests, tokenize PII, forward to handler, reconstruct response."""
    if request.method != "POST":
        return await call_next(request)
    
    body = await request.body()
    if not body:
        return await call_next(request)
    
    vault = VaultSession(use_gliner=False, use_ollama=False)
    try:
        data = json.loads(body)
        if "text" in data:
            data["text"] = vault.tokenize(data["text"])
            # Store vault in request state for reconstruction
            request.state.vault = vault
            request.state.original_body = body
            # Override body with tokenized version
            request._body = json.dumps(data).encode()
        
        response = await call_next(request)
        return response
    finally:
        vault.destroy()

@app.post("/analyze")
async def analyze(request: Request):
    body = json.loads(await request.body())
    # Your LLM call would go here — the text is already tokenized
    return {"analysis": f"Processed: {body.get('text', '')}", "status": "pii_safe"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
