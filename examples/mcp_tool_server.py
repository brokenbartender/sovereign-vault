"""Example: MCP Tool Server for sovereign-vault.

Exposes vault tokenization as an MCP tool that any AI agent can call.
Requires: pip install sovereign-vault mcp

Run: python examples/mcp_tool_server.py
"""
import json
import sys
from sovereign_vault import VaultSession, new_session, get_session, drop_session

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

server = Server("sovereign-vault")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="vault_tokenize",
            description=(
                "Tokenize PII in text using reversible HMAC-bound placeholders. "
                "Returns tokenized text and a session_id for later reconstruction."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text containing PII to tokenize"},
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="vault_reconstruct",
            description="Reconstruct real PII values from tokenized text using a session_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session ID from vault_tokenize"},
                    "text": {"type": "string", "description": "Tokenized text to reconstruct"},
                },
                "required": ["session_id", "text"],
            },
        ),
        Tool(
            name="vault_destroy",
            description="Destroy a vault session and wipe all PII from memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session ID to destroy"},
                },
                "required": ["session_id"],
            },
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "vault_tokenize":
        session_id, vault = new_session(use_gliner=False, use_ollama=False)
        abstract = vault.tokenize(arguments["text"])
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "session_id": session_id,
                    "tokenized_text": abstract,
                    "entities_vaulted": len(vault),
                }),
            )
        ]
    
    elif name == "vault_reconstruct":
        vault = get_session(arguments["session_id"])
        restored = vault.reconstruct(arguments["text"])
        return [TextContent(type="text", text=restored)]
    
    elif name == "vault_destroy":
        dropped = drop_session(arguments["session_id"])
        return [TextContent(type="text", text=json.dumps({"destroyed": dropped}))]
    
    raise ValueError(f"Unknown tool: {name}")

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
