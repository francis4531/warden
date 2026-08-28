"""
The connections catalog: a curated directory of common enterprise MCP servers.
Accurate as of mid-2026. Each entry records who maintains it, how it connects
(transport), what credentials it needs, and a default governance posture.

'maintainer': official = Anthropic reference (educational), vendor = product owner,
              community = third party, warden = ships built in with this app.
'transport':  stdio_python (uvx ...), stdio_node (npx ...), http (remote OAuth URL),
              builtin (a local server this app runs itself).
'status':     ready = connectable in this app's runtime now,
              needs_node = requires npx/Node in the runtime,
              needs_python = requires uvx/uv in the runtime,
              remote = a hosted URL you paste in (works without local runtime),
              archived = still works but no longer maintained upstream.
Risk posture is a starting point; Warden classifies each discovered tool and lets
you override it.
"""

CATALOG = [
  # --- ships with Warden (always connectable) ---
  {"id":"builtin_enterprise","name":"Enterprise Tools (Warden)","category":"Reference",
   "maintainer":"warden","transport":"builtin","auth":"none","status":"ready",
   "desc":"Customer lookup, knowledge search, ticketing, and refunds. The built-in demo server."},
  {"id":"builtin_files","name":"Filesystem (Warden)","category":"Files & Docs",
   "maintainer":"warden","transport":"builtin","auth":"none","status":"ready",
   "desc":"Read, list, and write files inside a sandboxed workspace. A working second server."},
  {"id":"builtin_code","name":"Self-Audit (Warden)","category":"Dev",
   "maintainer":"warden","transport":"builtin","auth":"none","status":"ready",
   "desc":"Reads Warden's own source, runs a static self-check, and proposes fixes (gated). Warden debugging Warden."},

  # --- live public remote server, no credentials, connect and go ---
  {"id":"deepwiki","name":"DeepWiki (GitHub repos)","category":"Dev","maintainer":"vendor",
   "transport":"http","run":"https://mcp.deepwiki.com/mcp","auth":"none","status":"ready",
   "desc":"Ask real questions about any public GitHub repository and read its docs, live. No token needed."},

  # --- Anthropic official reference servers ---
  {"id":"fetch","name":"Fetch","category":"Web","maintainer":"official","transport":"stdio_python",
   "run":"uvx mcp-server-fetch","auth":"none","status":"needs_python",
   "desc":"Fetch a URL and return its content as text for the agent to read."},
  {"id":"filesystem","name":"Filesystem (official)","category":"Files & Docs","maintainer":"official",
   "transport":"stdio_node","run":"npx -y @modelcontextprotocol/server-filesystem <path>",
   "auth":"none","status":"needs_node","desc":"Reference filesystem server. Read and write within allowed paths."},
  {"id":"git","name":"Git","category":"Dev","maintainer":"official","transport":"stdio_python",
   "run":"uvx mcp-server-git --repository <path>","auth":"none","status":"needs_python",
   "desc":"Read a repo: status, diff, log, branches, and commits."},
  {"id":"memory","name":"Memory","category":"Reference","maintainer":"official","transport":"stdio_node",
   "run":"npx -y @modelcontextprotocol/server-memory","auth":"none","status":"needs_node",
   "desc":"A simple knowledge-graph memory the agent can write to and recall."},

  # --- vendor-maintained (the right pick for production) ---
  {"id":"github","name":"GitHub","category":"Dev","maintainer":"vendor","transport":"http",
   "run":"https://api.githubcopilot.com/mcp/","auth":"oauth_or_pat","status":"remote",
   "desc":"Read repos and issues; create issues, branches, and pull requests. Hosted OAuth endpoint."},
  {"id":"linear","name":"Linear","category":"Product","maintainer":"vendor","transport":"http",
   "run":"https://mcp.linear.app/sse","auth":"oauth","status":"remote",
   "desc":"Issue tracking and project planning. Read issues and create or update them."},
  {"id":"notion","name":"Notion","category":"Knowledge","maintainer":"vendor","transport":"http",
   "run":"https://mcp.notion.com/mcp","auth":"oauth","status":"remote",
   "desc":"Read and write Notion docs and databases. A common agent knowledge base."},
  {"id":"stripe","name":"Stripe","category":"Payments","maintainer":"vendor","transport":"http",
   "run":"https://mcp.stripe.com","auth":"api_key","status":"remote",
   "desc":"Look up customers, invoices, and payments; issue refunds. High-impact by nature."},
  {"id":"sentry","name":"Sentry","category":"Observability","maintainer":"vendor","transport":"http",
   "run":"https://mcp.sentry.dev/mcp","auth":"oauth","status":"remote",
   "desc":"Read issues and errors; triage and resolve. Hosted OAuth endpoint."},
  {"id":"supabase","name":"Supabase","category":"Data","maintainer":"vendor","transport":"stdio_node",
   "run":"npx -y @supabase/mcp-server-supabase","auth":"api_key","status":"needs_node",
   "desc":"Query and manage a Supabase Postgres project, tables, and rows."},
  {"id":"playwright","name":"Playwright","category":"Web","maintainer":"vendor","transport":"stdio_node",
   "run":"npx -y @playwright/mcp","auth":"none","status":"needs_node",
   "desc":"Drive a real browser: navigate, click, fill forms, extract. Microsoft-maintained."},
  {"id":"cloudflare","name":"Cloudflare","category":"Infra","maintainer":"vendor","transport":"http",
   "run":"https://observability.mcp.cloudflare.com/sse","auth":"oauth","status":"remote",
   "desc":"Inspect and manage Cloudflare resources over a hosted OAuth connection."},

  # --- data (archived reference, still functional) ---
  {"id":"postgres","name":"PostgreSQL","category":"Data","maintainer":"community","transport":"stdio_node",
   "run":"npx -y @modelcontextprotocol/server-postgres postgresql://<conn>","auth":"conn_string",
   "status":"archived","desc":"Query a Postgres database. Reference server is archived; use read-only creds."},
  {"id":"slack","name":"Slack","category":"Comms","maintainer":"community","transport":"stdio_node",
   "run":"npx -y @modelcontextprotocol/server-slack","auth":"bot_token","status":"archived",
   "desc":"Read channels and post messages. Original reference archived; community builds exist."},
]

BY_ID = {c["id"]: c for c in CATALOG}

MAINTAINER_LABEL = {"warden":"Built in","official":"Anthropic reference",
                    "vendor":"Vendor-maintained","community":"Community"}
STATUS_LABEL = {"ready":"Ready","needs_node":"Needs Node runtime","needs_python":"Needs Python runtime",
                "remote":"Remote (paste URL + token)","archived":"Archived but works"}
