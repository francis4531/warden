# Warden

**An enterprise AI agent studio where every agent is governed by default.**

Build an agent, grant it tools over the Model Context Protocol, and run it against a
live model. Warden runs low-risk actions on its own and holds anything that moves
money or changes state for a human to approve, with a full audit trail behind every
step. It is a working demonstration of the thing every enterprise agent platform is
really selling: not the model, but the governance around letting an agent act.

## What's real here

- **Real MCP.** `mcp_server.py` is a genuine Model Context Protocol server exposing
  four enterprise tools. The runtime is a real MCP client: it discovers tools over the
  protocol and invokes them. Nothing about the tool layer is mocked.
- **Real agent loop.** `agent_runtime.py` runs a perceive -> decide -> act loop against
  an Anthropic model, with tool use, tool results, and a final answer.
- **Real governance.** Every skill carries a risk tier (LOW / MED / HIGH). Reads
  auto-run; high-risk writes (issuing a refund) pause the run, open an approval, and
  execute only after a human decides. Deny, and the money never moves.
- **Real audit.** Every thought, tool call, tool result, and approval decision is
  written to an append-only log you can read per-run or across the whole studio.

## Architecture

| File | Role |
|------|------|
| `mcp_server.py` | MCP server: `lookup_customer`, `search_knowledge`, `create_ticket`, `issue_refund` |
| `mcp_client.py` | Thread-safe MCP client (one dedicated event-loop thread, one persistent session) |
| `governance.py` | Risk registry and the auto-run vs approval policy |
| `agent_runtime.py`| The agent loop, gating, and pause/resume on approval |
| `store.py` | SQLite persistence: agents, runs, audit, approvals |
| `app.py` | Flask app: dashboard, builder, run console, approvals queue, audit log |

## Run locally

```bash
pip install -r requirements.txt
python app.py            # http://localhost:8000
```

With no API key it runs in **sandbox** mode: a deterministic planner drives the same
governance flow so everything is demonstrable offline. Set a key for live model calls:

```bash
export ANTHROPIC_API_KEY=sk-...
export WARDEN_MODEL=claude-sonnet-4-5   # optional; set to a model on your account
python app.py
```

## Deploy (Render)

1. Push this folder to a repo and create a Render Web Service from it.
2. Build command: `pip install -r requirements.txt`
3. Start command comes from the `Procfile`:
   `gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT`
   Keep it to **one worker** (the MCP session and SQLite live in-process; one worker
   with threads is the simplest correct setup for a demo).
4. Environment variables:
   - `ANTHROPIC_API_KEY` — set this to run agents against a live model.
   - `WARDEN_MODEL` — optional, defaults to `claude-sonnet-4-5`.

Note: `warden.db` and the JSON ledgers under `data/` sit on Render's ephemeral
filesystem and reset on redeploy. That is fine for a demo; the point is that within a
session every action and approval is durably recorded and queryable.

## Try it

Build the sample "Billing Resolver" agent with all four skills, then run:

> Account AC-1001 says they were charged twice for $4200. Please make it right.

The agent looks up the account and checks policy (both auto-run), then reaches for
`issue_refund` and **stops** at the approval gate. Approve it and the refund executes
and is logged; deny it and nothing moves. Either way, open the audit log.
