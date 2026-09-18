# Codex maintainer automation

sovereign-vault uses OpenAI models to assist a solo maintainer. Every workflow is **advisory** —
the model comments; a human decides. Nothing is auto-merged, auto-closed, or auto-labeled.

## Workflows

| Workflow | Trigger | What the model does | Human gate |
|---|---|---|---|
| `codex-pr-review.yml` | PR opened / updated | Reviews the **diff** for correctness, security (crypto/HMAC/PII paths), and missing tests; posts a comment | Maintainer reads the comment and decides; only a human approves/merges |
| `codex-issue-triage.yml` | Issue opened | Suggests a category, up to 3 labels, and a next step; routes suspected vulns to `SECURITY.md` | Maintainer applies labels and responds |
| `codex-release-notes.yml` | Release created (draft) | Drafts grouped release notes from the commit range | Maintainer edits and publishes the release |

## Enabling

1. Add a repository **secret** `OPENAI_API_KEY`.
2. (Optional) Add a repository **variable** `CODEX_MODEL` set to the model you have access to
   (default `gpt-4.1-mini`).

Without the secret, the workflows **skip cleanly** — no red X, so forks and contributors without
the key are never blocked.

## Key protection (fork PRs)

`codex-pr-review.yml` uses `pull_request_target`, which exposes the secret even to fork PRs. To make
that safe it **never checks out or executes the PR's code** — it fetches only the *diff* (data) and
sends that to the model. Untrusted contributor code never runs with the API key in scope.

## Cost model

Rough estimates using a small model (e.g. `gpt-4.1-mini`), typical diffs/issues. Actual cost depends
on the model you configure and PR/issue size; treat these as order-of-magnitude.

| Volume / month | PR reviews | Issue triage | Release notes | Est. tokens/mo | Est. cost/mo* |
|---|---|---|---|---|---|
| Light (10) | ~10 | ~10 | ~2 | ~0.5–1M | a few dollars |
| Moderate (100) | ~100 | ~100 | ~4 | ~6–12M | low tens of dollars |
| Heavy (1,000) | ~1,000 | ~1,000 | ~10 | ~60–120M | low hundreds of dollars |

\* Diffs are capped (`head -c 120000`) to bound per-run token use. Larger models cost more; you
control the model via `CODEX_MODEL`.

## Failure modes & fallbacks

- **No API key** → workflows skip (guarded), CI stays green.
- **API error / empty response** → step logs a warning and exits 0 (never blocks a PR/issue).
- **Model hallucination** → output is advisory only; a human reviews every suggestion before acting.
- **Rate limit / quota** → the run no-ops for that event; normal CI (`ci.yml`) is unaffected.
