# Warden

**An enterprise AI agent studio where every agent is governed by default.**

Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval, with a full audit trail behind every
step. Warden is built on the thing every enterprise agent platform is really selling: not
the model, but the governance around letting an agent act.

## What's real here

- **Real MCP, multiple servers.** Warden ships one working local MCP server (sample
  enterprise tools) and connects to external ones from a catalog of common enterprise
  MCP servers, over stdio or remote HTTP. It discovers
  each server's tools over the protocol and routes calls back to the right server.
- **Real governance, including for tools you didn't write.** Built-in tools have a
  hand-set risk registry. Tools discovered from any other server are classified
  automatically and fail closed: a server's own MCP annotations (read-only, destructive)
  come first, then the strongest verb anywhere in the name (find_and_replace is a write),
  and anything unrecognized is gated. An admin can override any tool's risk from the Catalog page;
  the override is per catalog server and tool, so it applies to every user's own copy.
- **Real agent loop.** A perceive -> decide -> act loop against an Anthropic model,
  with tool use across servers, pausing at the approval gate and resuming on decision.
- **Real audit.** Every thought, tool call, result, and approval decision is written to
  a hash-chained log, per-run and studio-wide, each stamped with its risk tier.
- **Tool output is data.** Everything a tool returns enters the transcript labelled as
  outside data with a size cap, and the agent is told that instructions found inside it
  (a web page, an email, a record) are content to report, never commands to follow. This
  is a boundary, not a guarantee: the risk gate is what stops a hijacked agent from
  doing damage, which is why writes are held.
- **Approvals are binding.** A held action stays held until its owner decides, whatever
  changes to risk tiers or policies in the meantime; a decision is recorded once, on the
  audit chain, and cannot be flipped afterwards; what runs is exactly the payload the
  approver saw, and if the transcript's arguments differ nothing runs. The approver is
  the agent's owner: Warden's model is accountability (every decision is attributed and
  on the record), not separation of duties. Admins see pending actions and cannot act on
  them.

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
(LOW) run; anything above a read, including MED tools and HIGH tools a policy would
auto-run, is recorded as held and never executed.
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
| `governance.py` | Risk registry + auto-classification of external tools + overrides |
| `agent_runtime.py` | The agent loop, gating, pause/resume on approval, and team delegation |
| `evals.py` | Eval suites: code assertions, golden comparisons, LLM-as-a-judge, run snapshots and comparison |
| `store.py` | SQLite: agents, runs, audit, approvals, connections, tool overrides, eval suites, annotations |
| `app.py` | Flask app: dashboard, connections, builder, run console, approvals, audit |

## Two hats for the admin

An admin has two jobs, so Warden gives them two places. A switch at the top of the sidebar
picks between the Admin console (Overview, Users, Catalog, Policies, Approvals, Audit log,
Observability, Architecture: the studio as a whole) and My agents (Dashboard, Build an
agent, Connections, Approvals, Evals: exactly what every user gets, scoped to the admin's
own agents and accounts). Permissions never depend on the switch; only what a page shows.
Users never see it.

## The admin's view

Admins get a Users page: every user, their agents, conversations, what is active, what is
on hold, and spend today and all time. Any agent or conversation opens read-only, so an
admin can see exactly what an agent did without being able to reply, approve, edit, or mark
answers on the owner's behalf; opening someone else's conversation writes an `admin_view`
event to that run's audit trail, visible to the owner. The console's Approvals page is
read-only too: what is waiting on users, and which high-risk actions their owners have yet
to decide.

## Every connection is someone's own

The studio provides no connections. Every connection, admins included, belongs to the user
who made it: their Google account, their GitHub token, their Atlassian sign-in. It is stored
encrypted under their name, only their agents can be granted it, nobody else can see, grant,
or disconnect it, and an agent that needs a source it lacks asks its owner, never an admin.
Servers that run as a process on the Warden host (stdio) can only be enabled by an admin,
and even then only for the admin's own agents. The one thing every user gets without
connecting anything is the built-in sample server (fake customers, a knowledge base,
tickets, refunds), so a first agent works in one click.

What the admin does decide, on the Catalog page, is which servers are on offer (the curated
catalog plus anything added from the MCP Registry, each of which can be hidden from users), how each tool is risk-classified for
everyone (a risk override applies to every user's copy of that tool), and the Google client
that makes one-click Google connections possible.

## Connections

The catalog lists common enterprise MCP servers grouped by category (GitHub,
Linear, Notion, Stripe, Sentry, Slack, Postgres, Supabase, Playwright, the Anthropic
reference servers, Google Workspace, and more). Each entry shows who maintains it and how
it connects, and the card matches the credential the server actually needs:

- Built in (Enterprise Tools, a sample with fake customers, a knowledge base, tickets and refunds): always connected for everyone, no setup.
- Personal (Gmail, Drive, Calendar, Docs, Sheets): each user clicks "Connect your Google
  account" for themselves. The token is stored encrypted under that user, only their
  agents can be granted it, and they can disconnect any time. Read-only scopes by default;
  a fresh access token is minted before every call. The admin sets up the Google client
  once on the Catalog page (or brings their own Workspace-internal client, which needs no
  Google verification) and never touches a user's connection.
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
    python -m pytest -q      # the governance promises above, as tests (sandbox mode)

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

- Studio secret: `WARDEN_SECRET_KEY` (any long random string). It is the root of the
  token encryption key, the session signing key, and the audit chain's HMAC key, each
  derived separately. There is no built-in default. If unset, a random key is generated
  once and stored on the disk beside the data, and the admin Overview says so. Set it in
  production: a lost key means lost connections and a broken audit chain.
- Optional: a server can instead read its token from an environment variable
  (`GITHUB_TOKEN`, `STRIPE_API_KEY`, etc.) if you prefer that for a specific one, and
  `WARDEN_AUTOCONNECT=deepwiki,github` will auto-connect a list of servers on boot. These
  are optional conveniences, not required, the disk handles persistence on its own.

Example env for the disk setup: `ANTHROPIC_API_KEY=...`, `WARDEN_MODEL=claude-sonnet-4-6`,
`WARDEN_DATA_DIR=/var/warden`, `WARDEN_SECRET_KEY=<any long random string>`.

## Who can sign in

- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` turn on Sign in with Google.
- `WARDEN_ALLOWED_DOMAINS=example.com` or `WARDEN_ALLOWED_EMAILS=a@example.com,b@example.com`
  restrict who may sign in. With neither set, any Google account can sign in and the
  admin Overview flags it.
- `WARDEN_ADMIN_EMAILS=admin@example.com` names the admins.
- `WARDEN_PASSWORD` keeps a single shared password sign-in as a fallback; everyone who
  uses it shares one workspace named `operator`. Leave it unset once Google sign-in works.
- Every form and request from Warden's own pages carries a CSRF token; cookies are
  `SameSite=Lax`, `HttpOnly`, and `Secure` on Render (set `WARDEN_HTTPS=1` elsewhere
  behind TLS).

## Telemetry export

A run can be exported as an OpenTelemetry trace (`POST /run/<id>/export`) to
`OTEL_EXPORTER_OTLP_ENDPOINT`. Spans carry tool names, risk tiers, outcomes, latency and
cost. Tool arguments and results are left out unless `WARDEN_TRACE_PAYLOADS=on`; when
they are included, keys that look sensitive are replaced and values are scrubbed for
emails, card and social-security numbers, API keys, bearer tokens and phone numbers
(`WARDEN_REDACT_KEYS` extends the key list). Span names never contain user text.

## Model and cost

Each agent runs on the model entered in the builder, or `WARDEN_MODEL` (default
`claude-sonnet-4-6`) when none is. The system prompt and tool list are sent as a cache
prefix, so after the first turn of a run they bill at the cache-read rate. Cost is
computed from the published list prices per model id, including cache write and read
tokens; the table lives in `agent_runtime.PRICES` and should be re-checked when prices
change.

## Loop limits

A conversation may make at most 12 model calls per turn and `WARDEN_MAX_CALLS_PER_RUN`
(default 60) across all of its turns and resumes. A model call times out after
`WARDEN_MODEL_TIMEOUT` seconds (default 120). When the transcript grows past
`WARDEN_CONTEXT_TOKENS` (default 150,000, estimated), the oldest exchanges are dropped
in pairs and the first message says so. A reply cut off at the output limit is asked to
continue rather than shown as final. Runs still marked running when Warden restarts are
marked interrupted at boot and can be continued with a message.

## Audit chain

Every event's hash is an HMAC over the previous hash and the event, keyed with the studio
secret, and the chain head (last hash, count, signature) is stored with it. Editing a
row, deleting from the middle, or trimming the tail breaks verification, which the admin
Overview runs on every load. An editor with database access but without the secret
cannot recompute a link. Someone with both can still rewrite history; to close that,
copy the head from `/audit` to a place the app cannot write.

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
