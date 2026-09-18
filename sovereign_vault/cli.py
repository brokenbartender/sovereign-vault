"""
sovereign_vault.cli — Command-line interface for sovereign-vault.

Usage:
    sovereign-vault tokenize "John Doe SSN 123-45-6789"
    sovereign-vault tokenize -f document.txt
    echo "PII text" | sovereign-vault tokenize --stdin
    sovereign-vault diff "John Doe SSN 123-45-6789"
"""

import argparse
import sys

from .session import VaultSession
from .types import ReconMode, SealMode


def main():
    parser = argparse.ArgumentParser(
        prog="sovereign-vault",
        description="Reversible PII tokenization for LLM pipelines.",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- tokenize ---
    tok = sub.add_parser("tokenize", help="Tokenize PII in text")
    tok.add_argument("text", nargs="?", help="Text to tokenize (or use --stdin / -f)")
    tok.add_argument("--stdin", action="store_true", help="Read from stdin")
    tok.add_argument("-f", "--file", help="Read from file")
    tok.add_argument("--json", action="store_true", help="Output as JSON")

    # --- diff ---
    diff = sub.add_parser("diff", help="Show what PII was detected and replaced")
    diff.add_argument("text", nargs="?", help="Text to analyze (or use --stdin / -f)")
    diff.add_argument("--stdin", action="store_true", help="Read from stdin")
    diff.add_argument("-f", "--file", help="Read from file")

    # --- coverage ---
    cov = sub.add_parser("coverage", help="Show detection coverage report")
    cov.add_argument("text", nargs="?", help="Text to analyze (or use --stdin / -f)")
    cov.add_argument("--stdin", action="store_true", help="Read from stdin")
    cov.add_argument("-f", "--file", help="Read from file")

    # --- version ---
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "version":
        from . import __version__
        print(f"sovereign-vault {__version__}")
        return

    # Get input text
    text = _get_input(args)
    if not text:
        print("Error: No input text provided.", file=sys.stderr)
        sys.exit(1)

    if args.command == "tokenize":
        _cmd_tokenize(text, as_json=args.json)
    elif args.command == "diff":
        _cmd_diff(text)
    elif args.command == "coverage":
        _cmd_coverage(text)


def _get_input(args) -> str:
    """Extract input text from args, stdin, or file."""
    if hasattr(args, "stdin") and args.stdin:
        return sys.stdin.read().strip()
    if hasattr(args, "file") and args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read().strip()
    if hasattr(args, "text") and args.text:
        return args.text
    # Try stdin if no other input
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""


def _cmd_tokenize(text: str, as_json: bool = False):
    """Tokenize PII and output the result."""
    import json

    with VaultSession(use_gliner=False, use_ollama=False) as vault:
        abstract = vault.tokenize(text)
        if as_json:
            output = {
                "original_length": len(text),
                "tokenized_length": len(abstract),
                "entities_vaulted": len(vault),
                "tokenized_text": abstract,
                "audit_log": vault.audit_log(),
            }
            print(json.dumps(output, indent=2))
        else:
            print(abstract)


def _cmd_diff(text: str):
    """Show detection diff."""
    with VaultSession(use_gliner=False, use_ollama=False) as vault:
        vault.tokenize(text)
        print(vault.diff())


def _cmd_coverage(text: str):
    """Show coverage report."""
    import json

    with VaultSession(use_gliner=False, use_ollama=False) as vault:
        vault.tokenize(text)
        report = vault.coverage_report()
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
