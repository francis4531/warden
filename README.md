# Warden

**An enterprise AI agent studio where every agent is governed by default.**

Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval, with a full audit trail behind every
step. Warden is built on the thing every enterprise agent platform is really selling: not
the model, but the governance around letting an agent act.

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

## Agents know where they run

Every agent's system prompt states that it runs inside Warden, lists its granted tools by
server, and forbids the usual chatbot failure modes: claiming abilities it lacks, denying
abilities Warden can add, or telling the user to edit configuration files. When a task needs
a capability the agent does not have, it calls `request_connection(need, keywords)`. Warden
matches the request against the catalog (and the MCP Registry as a fallback), records it on
the audit trail, and shows a card in the conversation. An admin connects the server from that
card; its tools are granted to the requesting agent and the conversation resumes on its own.
Open requests are listed on the Connections page. Requesting is a LOW-risk governed action,
so a policy can gate or deny agents asking for capabilities.

## Teams

Any agent can be given member agents in the builder; that makes it a team lead with one
extra tool, `delegate(member, task)`. Each hand-off spawns a member run under the member's
own tool grants, policies, and per-run budget; the lead never inherits a member's tools.
Delegation is governed like any other tool: it has a risk tier (MED, auto by default;
override it to HIGH to hold every hand-off), policies can gate or deny it (tool `delegate`,
field `member`), and a hard cap limits hand-offs per run (`WARDEN_MAX_DELEGATIONS`, 8).
A member's HIGH action pauses the whole team until a human decides. The lead's run budget
covers the whole tree. Members cannot delegate further (`WARDEN_MAX_DELEGATION_DEPTH`, 1).

## Evals

An eval suite belongs to one agent and holds cases (inputs, optionally with an expected
output) and checks. Running a suite creates a real run per case in evaluation mode: reads
run, and anything that would need human approval is recorded as held and never executed.
Checks come in three kinds, cheapest first: code assertions (answer contains / regex,
red-flag words, tool called or not, held for approval, max tool calls, cost under N, no tool
errors, quotes grounded in tool results), golden comparisons against an expected output,
and LLM-as-a-judge checks that ask one binary question; humans mark each verdict agree or
disagree so the suite reports judge error rather than hiding it. Every eval run snapshots
the agent, so two runs compare check by check with the instructions diff between them.
Error analysis feeds the suites: any conversation can be marked Good or Wrong with a
category, and any conversation becomes a case with one click.

## Architecture

| File | Role |
|------|------|
| `catalog.py` | Curated directory of common enterprise MCP servers (metadata, transport, auth) |
| `connection_manager.py` | Multi-server MCP client: persistent sessions on one loop thread, stdio + HTTP |
| `mcp_server.py` | Built-in MCP server: lookup_customer, search_knowledge, create_ticket, issue_refund |
| `mcp_fs_server.py` | Built-in MCP server: sandboxed list_files, read_file, write_file |
| `governance.py` | Risk registry + auto-classification of external tools + overrides |
| `agent_runtime.py` | The agent loop, gating, pause/resume on approval, and team delegation |
| `evals.py` | Eval suites: code assertions, golden comparisons, LLM-as-a-judge, run snapshots and comparison |
| `store.py` | SQLite: agents, runs, audit, approvals, connections, tool overrides, eval suites, annotations |
| `app.py` | Flask app: dashboard, connections, builder, run console, approvals, audit |

## Connections

The Connections page lists common enterprise MCP servers grouped by category (GitHub,
Linear, Notion, Stripe, Sentry, Slack, Postgres, Supabase, Playwright, the Anthropic
reference servers, Google Workspace, and more). Each entry shows who maintains it and how
it connects, and the card matches the credential the server actually needs:

- Built in (Enterprise Tools, Filesystem): always connected, no setup.
- Google (Gmail, Drive, Calendar, Docs, Sheets): "Connect with Google". Warden runs the
  OAuth flow with its own Google client, read-only scopes by default, stores the refresh
  token encrypted, and mints a fresh access token before every call. One-time setup: add
  `WARDEN_BASE_URL/connections/oauth/google/callback` as a redirect URI and enable the API.
- MCP-standard OAuth (Linear, Notion, Sentry, Atlassian, Cloudflare, Vercel, GitHub):
  "Sign in with <vendor>". Warden discovers the authorization server, registers itself as
  a client, and completes the PKCE flow in the browser. No token to paste.
- API key (Stripe, Terraform, Grafana, PagerDuty, Firecrawl, Exa, Supabase): paste a key,
  with a link to the vendor page that issues one.
- stdio (Filesystem official, Supabase, Playwright, Postgres, Slack, Fetch, Git): these
  are Node (npx) or Python (uvx) processes and require that runtime present. On a
  Python-only host they report a clear connection error rather than connecting; expected.

## Run locally

    pip install -r requirements.txt
    python app.py            # http://localhost:8000

No key -> sandbox mode: a deterministic planner drives the same governance flow so
the whole governance flow works offline. For live model calls:

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

## Keeping configuration across deploys

Render's filesystem is ephemeral, so attach a **Render Disk** and set `WARDEN_DATA_DIR`
to its mount path (e.g. `/var/warden`). Everything Warden stores, agents, enabled
connections, tool overrides, runs, and the audit log, lives on that disk and survives
redeploys.

**Tokens are entered in the UI and persist on the disk, encrypted.** Paste a server's
access token on the Connections page once; it is encrypted at rest (never stored as
plaintext) and reused after every redeploy. No per-token environment variables.

- Encryption key: taken from `WARDEN_SECRET_KEY` if you set one (kept out of the data
  dir, the stronger option), otherwise generated once and stored on the disk beside the
  data (zero-config). Any string works as `WARDEN_SECRET_KEY`.
- Optional: a server can instead read its token from an environment variable
  (`GITHUB_TOKEN`, `STRIPE_API_KEY`, etc.) if you prefer that for a specific one, and
  `WARDEN_AUTOCONNECT=deepwiki,github` will auto-connect a list of servers on boot. These
  are optional conveniences, not required, the disk handles persistence on its own.

Example env for the disk setup: `ANTHROPIC_API_KEY=...`, `WARDEN_MODEL=claude-sonnet-4-6`,
`WARDEN_DATA_DIR=/var/warden`, and optionally `WARDEN_SECRET_KEY=<any long random string>`.

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
