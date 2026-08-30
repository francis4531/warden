"""
Discover MCP servers by searching the official MCP Registry
(registry.modelcontextprotocol.io), the community catalog backed by Anthropic, GitHub,
and Microsoft. Given a plain need like "gmail", return the best-matching servers with
enough detail to connect: how it's run (remote HTTP vs a local package), its endpoint,
and its repository. Stdlib only, short timeout, graceful fallback so a slow registry
never breaks the page.
"""
import json
import urllib.request
import urllib.parse

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
TIMEOUT = 6

def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Warden/0.3 (+mcp-discovery)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))

def _norm(entry):
    """Flatten a registry entry into what Warden needs to show and connect."""
    s = entry.get("server", entry) if isinstance(entry, dict) else {}
    name = s.get("name", "")                       # reverse-DNS, e.g. io.github.foo/gmail
    display = name.split("/")[-1].replace("-", " ").replace("_", " ").strip().title() or name
    desc = (s.get("description") or "").strip()
    repo = (s.get("repository") or {}).get("url", "")
    remotes = s.get("remotes") or []
    packages = s.get("packages") or []
    # prefer a remote HTTP endpoint (connects on the native runtime, no Docker)
    transport, endpoint, run_hint = "unknown", "", ""
    if remotes:
        rm = remotes[0]
        transport = "remote"
        endpoint = rm.get("url", "")
        run_hint = endpoint
    elif packages:
        pk = packages[0]
        reg = pk.get("registry_type") or pk.get("registry_name") or ""
        ident = pk.get("identifier") or pk.get("name") or ""
        transport = "stdio"
        endpoint = ident
        if "npm" in reg:
            run_hint = "npx -y " + ident
        elif "pypi" in reg:
            run_hint = "uvx " + ident
        else:
            run_hint = ident
    return {"name": name, "display": display, "description": desc, "repo": repo,
            "transport": transport, "endpoint": endpoint, "run_hint": run_hint}

def _score(item, terms):
    hay = (item["display"] + " " + item["name"] + " " + item["description"]).lower()
    score = 0
    for t in terms:
        if t in item["display"].lower(): score += 5
        if t in item["name"].lower():    score += 3
        if t in item["description"].lower(): score += 1
    # prefer remote (easier to connect) and named matches
    if item["transport"] == "remote": score += 2
    return score

def search(query, limit=6):
    """Return {ok, results, error}. results are ranked, connect-ready dicts."""
    q = (query or "").strip()
    if not q:
        return {"ok": True, "results": [], "error": None}
    try:
        url = REGISTRY + "?" + urllib.parse.urlencode({"search": q, "limit": 30})
        data = _get(url)
    except Exception as ex:
        return {"ok": False, "results": [], "error": str(ex)[:200]}
    raw = data.get("servers") or data.get("data") or []
    terms = [t for t in q.lower().split() if t]
    items = [_norm(e) for e in raw]
    items = [i for i in items if i["name"]]
    items.sort(key=lambda i: _score(i, terms), reverse=True)
    return {"ok": True, "results": items[:limit], "error": None}
