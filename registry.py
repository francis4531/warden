"""
Discover MCP servers by searching the official MCP Registry
(registry.modelcontextprotocol.io). The raw registry accepts anything anyone publishes,
so Warden only surfaces servers that are (a) the current, active version and (b) from a
recognized, reputable publisher, either a domain-verified vendor namespace or one of a
curated set of trusted maintainers. Personal one-off repos are filtered out.
Stdlib only, short timeout, graceful fallback.
"""
import json
import urllib.request
import urllib.parse

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
TIMEOUT = 6

TRUSTED_PUBLISHERS = {
    "modelcontextprotocol", "anthropic",
    "waystation", "mintmcp", "composio", "pipedream", "zapier", "klavis",
    "cloudflare", "hashicorp", "terraform", "vercel", "netlify", "aws", "amazon",
    "microsoft", "azure", "google", "gcp", "digitalocean", "heroku", "render",
    "supabase", "neon", "mongodb", "elastic", "redis", "snowflake", "databricks",
    "clickhouse", "planetscale", "chroma", "pinecone", "weaviate", "qdrant",
    "github", "gitlab", "atlassian", "linear", "sentry", "circleci", "jetbrains",
    "sonarsource", "sonarqube", "buildkite", "grafana", "pagerduty", "datadog",
    "honeycomb", "posthog", "raygun",
    "notion", "asana", "monday", "airtable", "clickup", "todoist", "trello", "slack",
    "discord", "zoom", "box", "dropbox", "figma", "canva", "miro", "contentful", "sanity",
    "twilio", "sendgrid", "resend", "intercom", "zendesk", "front",
    "stripe", "paypal", "square", "plaid", "ramp", "brex", "mercury", "quickbooks",
    "salesforce", "hubspot", "pipedrive", "mailchimp", "klaviyo",
    "exa", "brave", "tavily", "perplexity", "firecrawl", "browserbase", "apify",
    "brightdata", "serpapi", "e2b",
    "shopify", "wordpress", "wix", "webflow", "tableau", "amplitude", "mixpanel", "segment",
}

def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Warden/0.3 (+mcp-discovery)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))

def _publisher(name):
    ns = name.split("/")[0]
    parts = ns.split(".")
    if ns.startswith("io.github.") and len(parts) >= 3:
        return parts[2].lower()
    if len(parts) >= 2:
        return parts[1].lower()
    return ns.lower()

def _official_meta(entry):
    return (entry.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}

def _norm(entry):
    s = entry.get("server", entry) if isinstance(entry, dict) else {}
    name = s.get("name", "")
    seg = name.split("/")[-1]
    display = seg.replace("-", " ").replace("_", " ").strip().title()
    pub = _publisher(name)
    if display.lower() in ("mcp", "server", "main", "index", "app", "mcp Server", "mcp-server", ""):
        display = pub.title()                      # com.notion/mcp -> "Notion"
    desc = (s.get("description") or "").strip()
    repo = (s.get("repository") or {}).get("url", "")
    remotes = s.get("remotes") or []
    packages = s.get("packages") or []
    transport, endpoint, run_hint = "unknown", "", ""
    if remotes:
        transport = "remote"; endpoint = remotes[0].get("url", ""); run_hint = endpoint
    elif packages:
        pk = packages[0]
        reg = pk.get("registry_type") or pk.get("registry_name") or ""
        ident = pk.get("identifier") or pk.get("name") or ""
        transport = "stdio"; endpoint = ident
        run_hint = ("npx -y " + ident) if "npm" in reg else ("uvx " + ident) if "pypi" in reg else ident
    meta = _official_meta(entry)
    return {"name": name, "display": display, "description": desc, "repo": repo,
            "transport": transport, "endpoint": endpoint, "run_hint": run_hint,
            "publisher": pub, "rehost": "/@" in name,
            "is_latest": meta.get("isLatest", True), "status": meta.get("status", "active"),
            "updated": (meta.get("updatedAt") or "")[:10]}

def _score(item, terms):
    score = 0
    for t in terms:
        if t in item["display"].lower(): score += 5
        if t in item["publisher"]:       score += 4
        if t in item["name"].lower():    score += 3
        if t in item["description"].lower(): score += 1
    if item["transport"] == "remote": score += 2
    if not item["name"].startswith("io.github."): score += 2
    return score

def search(query, limit=6):
    q = (query or "").strip()
    if not q:
        return {"ok": True, "results": [], "error": None}
    try:
        url = REGISTRY + "?" + urllib.parse.urlencode({"search": q, "limit": 60})
        data = _get(url)
    except Exception as ex:
        return {"ok": False, "results": [], "error": str(ex)[:200]}
    raw = data.get("servers") or data.get("data") or []
    terms = [t for t in q.lower().split() if t]
    seen, kept = set(), []
    for i in [_norm(e) for e in raw]:
        if not i["name"] or i["name"] in seen:
            continue
        if i["status"] not in ("active", "", None) or not i["is_latest"]:
            continue
        if i["rehost"]:                          # aggregator-hosted community re-post, not vetted
            continue
        if i["publisher"] not in TRUSTED_PUBLISHERS:
            continue
        seen.add(i["name"]); kept.append(i)
    kept.sort(key=lambda i: _score(i, terms), reverse=True)
    return {"ok": True, "results": kept[:limit], "error": None}
