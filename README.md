# Warden

**An enterprise AI agent studio where every agent is governed by default.**

Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval, with a full audit trail behind every
step. Warden is built on the thing every enterprise agent platform is really selling: not
the model, but the governance around letting an agent act.

## What's real here

- **Real MCP, multiple servers.** Warden connects to the vendors' own MCP servers from a
  catalog of common enterprise systems (a sample server with fake data exists only in sandbox
  mode, for trying Warden without a model key) and to others
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

## Chat first, agents second

The home page opens on one box: "What do you need done?" Type it (and attach files if you
like) and the conversation starts, with no agent to build and nothing to connect first. It
runs on a hidden quick-chat assistant, one per person, that holds every tool the person has
connected at that moment, plus built-in web search and fetch. In a quick chat Warden reads
on its own and asks before it changes anything: any tool above LOW risk is held for
approval (`rt.decide`, policy name "Quick chat: asks before changing anything"), on top of
HIGH tools that always are, and a studio policy that explicitly allows or denies a tool
still wins. The assistant is never listed with the person's agents, pickers or counts, but
its conversations and spend appear in Recent and in the totals, and the admin's oversight
(read-only, as ever) covers them.

When a chat goes well, "Keep as an agent" turns it into one. Warden reads the conversation
(file contents never included), drafts a name and generalized instructions, and keeps
exactly the tools the chat used. Anything that changes something defaults to "ask me
first", because in the chat each change was approved one at a time. The original task is
waiting in the new agent's box so it can run again straight away. The audit log records
how the agent came to be (`agent_created`, how `kept_from_chat`, with the source run).

## Two ways to build an agent

The default (Build an agent) is one sentence: "Handle refund requests from customers who
were charged twice". Warden drafts a name, instructions, the tools it needs from the
sources you have connected, and the sources it still lacks, and shows a card in plain
language: what it does on its own, what it asks you about first, what it needs. Each
write action has a stance (on its own, ask me first, never) which becomes a per-agent
policy; a HIGH action can be made stricter from the card but never looser. Type a first
task and the conversation starts. The model drafts it live; in sandbox mode a keyword
planner stands in. Advanced setup keeps every dial: templates, each tool by name,
model, budget, team.

## Policies in plain language

An admin writes the rule as a sentence ("Require approval for refunds over $500", "No
more than 3 refunds in one conversation", "Never let Night Desk issue a refund"). Warden
drafts one structured rule (who, what, when, then) and shows it as a sentence with each
part editable; saving it is one click. Live, the model does the drafting; in sandbox, or
when the model's answer does not parse, a built-in grammar covers amounts, counts, hours,
weekends, risk tiers and agent names. Rules in force read back as sentences. The
field-by-field form is still there under Advanced.

## Declining a request

A connection request can be turned down as well as satisfied. The agent's owner can
decline it from the conversation, the dashboard, Approvals or Connections; an admin can
decline it from the console (the one thing an admin does to a user's conversation beyond
reading it, and it only ever narrows what the agent may do). Either way the decision is
on the audit log with who made it, the agent is told, is instructed never to ask for that
source again in the conversation, and carries on with the tools it has.

## Agents know where they run

Every agent's system prompt states that it runs inside Warden, lists its granted tools by
server, and forbids the usual chatbot failure modes: claiming abilities it lacks, denying
abilities Warden can add, or telling the user to edit configuration files. When a task needs
a capability the agent does not have, it calls `request_connection(need, keywords)`. Warden
matches the request against the catalog (and the MCP Registry as a fallback), records it on
the audit trail, and shows a card in the conversation. The person whose agent asked connects
right there, in the conversation, with the same controls the Connections page uses for that
source: sign in (Google with a read-only or read-and-write choice, read-only by default; or
the vendor's own sign-in), paste a key with a link to where it comes from, or one click for a
source that needs nothing. Their own account, never an admin's: an admin looking in sees the
card read-only. Connecting grants the tools to that agent and the conversation resumes on its
own, in place; the connection stays for every later chat. If it fails (a refused sign-in, a
bad key) the person lands back in the same conversation with the reason on the card, and can
retry or decline right there ("No thanks, carry on without it": the agent is told, does what
it can, and does not ask again). Open requests also show under Needs you on the home page and
link to the conversation; the Connections page is for managing what is already connected.
Requesting is a LOW-risk governed action, so a policy can gate or deny agents asking for
capabilities.

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
Observability, Architecture: the studio as a whole) and My agents (Home, Build an
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
connecting anything, in sandbox mode only, is the built-in sample server (fake customers,
a knowledge base, tickets, refunds), so a first agent works in one click. A live studio
(ANTHROPIC_API_KEY set) does not offer it; set WARDEN_SAMPLE_TOOLS=1 to keep it alongside
real systems. The Anthropic reference servers (fetch, filesystem, git, memory) were removed
from the catalog in v0.27; agents that held their tools lose those grants on first boot,
recorded in the audit log.

What the admin does decide, on the Catalog page, is which servers are on offer (the curated
catalog plus anything added from the MCP Registry, each of which can be hidden from users), how each tool is risk-classified for
everyone (a risk override applies to every user's copy of that tool), and the Google client
that makes one-click Google connections possible.

## Connections

The catalog lists common enterprise MCP servers grouped by category (GitHub,
Linear, Notion, Stripe, Sentry, Slack, Postgres, Supabase, Playwright, the Anthropic
reference servers, Google Workspace, and more). Each entry shows who maintains it and how
it connects, and the card matches the credential the server actually needs:

- Built in (Enterprise Tools, a sample with fake customers, a knowledge base, tickets and refunds): sandbox mode only, always connected there, no setup.
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

## Privacy policy and Google verification

`/privacy` is a public page that says what the studio collects, why, where it goes, how long it is kept, and how to remove it. It is written to satisfy Google's OAuth branding review: link it from your OAuth consent screen as the privacy policy URL, set the home page URL to the studio's base URL (the home page links to `/privacy`), and verify the domain in Google Search Console. `WARDEN_PRIVACY_CONTACT` sets the contact shown on the page; it defaults to the first admin email. Disconnecting a Google connection revokes the token at Google as well as deleting the studio's copy.

## Files in a conversation

Users can attach files when they start a conversation and in any reply: PDFs and images go
to the model as they are; Word, Excel and PowerPoint files and text, CSV, JSON and similar
files are read into text (Word, Excel and PowerPoint with the standard library only, with
bounded reads, so no new dependency and no XML parser to abuse). Up to 5 files of 10 MB per
message, 20 MB together, 150,000 characters of text each, 2,000 rows per sheet. A file that
cannot be read is skipped and the agent is told, so it can say so. Every file's text is
framed as data, not instructions. Files are stored with the conversation and removed with
the agent; the audit log keeps file names, never contents.

## Web access without a connection

Every agent can search the public web and read pages with nothing to connect. Both run on
the model provider's side, so they work the moment a model key is set. They are reads, so
they run without approval; each search and fetch is a line on the audit log (what was asked
for and which pages came back), a search costs $0.01 on top of tokens and is added to the
run's cost, and a run's budget and call ceiling still apply. Under Catalog, an admin
switches search and page reading on or off for the whole studio, may allow only named
domains or block named domains, and sets the most searches per model turn. Web search must
be enabled for the organization that owns `ANTHROPIC_API_KEY` (Anthropic Console, privacy
settings); if it is not, a run fails with a message that says so. Two limits to know: the
studio's own gate does not sit between the agent and the page (the switches, domain lists
and audit log are the controls), and sandbox mode has no model, so web access is live only.

## The release archive

Each release is one file, `warden_v<version>_<timestamp>.tar.gz`, laid out as a single
`warden/` directory (the code, exactly what `git archive` produces). The same archive also
carries `warden/.warden-history.bundle`: a self-contained git bundle with the full
commit-by-commit history of the `feature/v0.16-governance` branch (the governance work from
v0.16 and everything built on it). The bundle file is listed in `.gitignore`, so copying the
archive over a checkout and committing never commits it; it just sits there for a script to
use. To publish the history from a checkout that has the archive's contents:

```
git fetch .warden-history.bundle feature/v0.16-governance
git push origin FETCH_HEAD:refs/heads/feature/v0.16-governance
```

The push is fast-forward only, so it can never overwrite work on that branch, and running it
twice is harmless. Nothing about the code or the deploy depends on the bundle.

## Deploy (Render)

Python is pinned to 3.13 by `.python-version` (Render's native runtime defaults to the
newest Python, which the MCP SDK's dependency chain does not always support yet), and
`requirements.txt` pins the ranges that have been exercised by the test suite. When a
deploy fails at import time, that file is the first place to look.

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
- No account tokens in the environment, ever. GitHub, Gmail, Notion and the rest are
  connected by each user, with their own account or key, in the conversation that needs it
  (or from the Connections page). Warden has no code path that
  reads a service token from an environment variable.

Example env for the disk setup: `ANTHROPIC_API_KEY=...`, `WARDEN_MODEL=claude-sonnet-4-6`,
`WARDEN_DATA_DIR=/var/warden`, `WARDEN_SECRET_KEY=<any long random string>`.

## Who can sign in

- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` turn on Sign in with Google.
- `WARDEN_ALLOWED_DOMAINS=example.com` or `WARDEN_ALLOWED_EMAILS=a@example.com,b@example.com`
  restrict who may sign in. With neither set, any Google account can sign in and the
  admin Overview flags it.
- `WARDEN_ADMIN_EMAILS=admin@example.com` names the admins.
- There is no password sign-in: every user is a Google account. (Before v0.26 a
  `WARDEN_PASSWORD` fallback signed in as a shared `operator` user. On the first boot of
  v0.26 with Google sign-in on, agents and connections owned by `operator`, or by no one,
  are removed and the removal is written to the audit log. The variable is now ignored.)
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
