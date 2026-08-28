# Warden

**An enterprise AI agent studio where every agent is governed by default.**

Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval, with a full audit trail behind every
step. Warden is a working demonstration of the thing every enterprise agent platform is
really selling: not the model, but the governance around letting an agent act.

## What's real here

- **Real MCP, multiple servers.** Warden ships two working local MCP servers
  (enterprise tools + a sandboxed filesystem) and connects to external ones from a
  catalog of common enterprise MCP servers, over stdio or remote HTTP. It discovers
  each server's tools over the protocol and routes calls back to the right server.
- **Real governance, including for tools you didn't write.** Built-in tools have a
  hand-set risk registry. Tools discovered from any other server are classified
  automatically and fail closed: reads run on their own, writes and anything
  unrecognized are gated. You can override any tool's risk from the Connections page.
- **Real agent loop.** A perceive -> decide -> act loop against an Anthropic model,
  with tool use across servers, pausing at the approval gate and resuming on decision.
- **Real audit.** Every thought, tool call, result, and approval decision is written to
  an append-only log, per-run and studio-wide, each stamped with its risk tier.

## Architecture

| File | Role |
|------|------|
| `catalog.py` | Curated directory of common enterprise MCP servers (metadata, transport, auth) |
| `connection_manager.py` | Multi-server MCP client: persistent sessions on one loop thread, stdio + HTTP |
| `mcp_server.py` | Built-in MCP server: lookup_customer, search_knowledge, create_ticket, issue_refund |
| `mcp_fs_server.py` | Built-in MCP server: sandboxed list_files, read_file, write_file |
| `governance.py` | Risk registry + auto-classification of external tools + overrides |
| `agent_runtime.py` | The agent loop, gating, and pause/resume on approval |
| `store.py` | SQLite: agents, runs, audit, approvals, connections, tool overrides |
| `app.py` | Flask app: dashboard, connections, builder, run console, approvals, audit |

## Connections

The Connections page lists common enterprise MCP servers grouped by category (GitHub,
Linear, Notion, Stripe, Sentry, Slack, Postgres, Supabase, Playwright, the Anthropic
reference servers, and more). Each entry shows who maintains it and how it connects:

- Built in (Enterprise Tools, Filesystem): always connected, no setup.
- Remote (GitHub, Linear, Notion, Stripe, Sentry, Cloudflare): paste an access token and
  connect over HTTP. Works without any local runtime.
- stdio (Filesystem official, Supabase, Playwright, Postgres, Slack, Fetch, Git): these
  are Node (npx) or Python (uvx) processes and require that runtime present. On a
  Python-only host they report a clear connection error rather than connecting; expected.

## Run locally

    pip install -r requirements.txt
    python app.py            # http://localhost:8000

No key -> sandbox mode: a deterministic planner drives the same governance flow so
everything is demonstrable offline. For live model calls:

    export ANTHROPIC_API_KEY=sk-...
    export WARDEN_MODEL=claude-sonnet-4-6   # optional; a model on your account
    python app.py

## Deploy (Render)

Two options:

**Docker (recommended, unlocks the whole catalog).** The included `Dockerfile` provides
Python + Node + uv, so npx- and uvx-based MCP servers spawn on the host.
- Set the Render service Language to **Docker**. It builds from the `Dockerfile`.
- Env: `ANTHROPIC_API_KEY` for live mode; `WARDEN_MODEL` optional.

**Python (lighter, built-in + remote-HTTP servers only).**
- Language: Python 3. Build: `pip install -r requirements.txt`.
- Start (from `Procfile`): `gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT`
- Keep it to one worker (MCP sessions and SQLite live in-process).
- On this path the npx/uvx catalog entries can't spawn (no Node); they report a clear
  connection error. The two built-in servers and any remote-HTTP servers still work.

`warden.db` and `data/` are ephemeral and reset on redeploy (fine for a demo).

## Connect a real remote server (GitHub)

On the Connections page, GitHub is a remote (HTTP) server. Paste a GitHub token
(a fine-grained PAT with the scopes you want the agent to have, or an OAuth token) into
its token box and click Connect. Warden opens an HTTP MCP session to
`https://api.githubcopilot.com/mcp/`, sends `Authorization: Bearer <token>`, discovers
GitHub's tools, and classifies them: reading issues and repos runs on its own, while
`create_issue`, `create_pull_request`, and the like are gated for approval. Scope the
token tightly, the whole point of Warden is that even a broadly-scoped token is safe
because writes stop at the gate.

## Try it

Build the "Billing Resolver" with the enterprise tools and run:

> Account AC-1001 says they were charged twice for $4200. Please make it right.

It looks up the account and checks policy (auto), then reaches for issue_refund and
stops at the approval gate. Approve to execute and log it; deny and nothing moves. Or
grant it the filesystem tools and ask it to write a file, same gate on write_file.
