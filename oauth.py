"""
OAuth for connections. Two flows, one token format.

Google  Warden's own Google OAuth client (the same one used for sign-in) requests the
        scopes a Google server needs, read-only by default. The refresh token is stored
        encrypted, and a fresh access token is minted before every MCP call.

MCP     Servers that follow the MCP authorization spec (OAuth 2.1): Warden discovers the
        authorization server from the MCP endpoint, registers itself as a client on the
        fly when the server allows it, runs the PKCE code flow through the operator's
        browser, and stores the tokens. No token to paste.

A connection's stored "token" is JSON:
  {"type":"oauth","provider":"google"|"mcp","access_token":..,"refresh_token":..,
   "expires_at":<unix>,"token_endpoint":..,"client_id":..,"client_secret":..,"scopes":[..]}
Plain strings (pasted API keys) keep working as before.
"""
import os, json, time, base64, hashlib, secrets, urllib.parse, urllib.request, urllib.error

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
CLIENT_NAME = "Warden"

def is_oauth(token):
    return parse(token) is not None

def parse(token):
    try:
        d = json.loads(token)
        return d if isinstance(d, dict) and d.get("type") == "oauth" else None
    except Exception:
        return None

def _post(url, data, headers=None):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                          "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

def _get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Warden/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

# ---- PKCE / state ----
def pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge

# ---- Google ----
def google_authorize_url(client_id, redirect_uri, scopes, state):
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
              "scope": " ".join(["openid", "email"] + list(scopes)), "state": state,
              "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true"}
    return GOOGLE_AUTH + "?" + urllib.parse.urlencode(params)

def google_exchange(client_id, client_secret, redirect_uri, code, scopes):
    t = _post(GOOGLE_TOKEN, {"code": code, "client_id": client_id, "client_secret": client_secret,
                             "redirect_uri": redirect_uri, "grant_type": "authorization_code"})
    return _pack("google", t, GOOGLE_TOKEN, client_id, client_secret, scopes)

# ---- MCP-standard OAuth (RFC 9728 + RFC 8414 + RFC 7591 + PKCE) ----
def mcp_discover(server_url):
    """Find the authorization server's endpoints for an MCP server URL."""
    u = urllib.parse.urlparse(server_url)
    origin = f"{u.scheme}://{u.netloc}"
    auth_servers = []
    for cand in (origin + "/.well-known/oauth-protected-resource" + (u.path.rstrip("/") or ""),
                 origin + "/.well-known/oauth-protected-resource"):
        try:
            pr = _get(cand)
            auth_servers = pr.get("authorization_servers") or []
            if auth_servers:
                break
        except Exception:
            continue
    if not auth_servers:
        # last resort: the MCP endpoint's 401 challenge may name its resource metadata (RFC 9728)
        try:
            req = urllib.request.Request(server_url, data=b"{}", headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as he:
            www = he.headers.get("WWW-Authenticate", "") or ""
            import re as _re
            m = _re.search(r'resource_metadata="([^"]+)"', www)
            if m:
                try:
                    auth_servers = _get(m.group(1)).get("authorization_servers") or []
                except Exception:
                    pass
        except Exception:
            pass
    if not auth_servers:
        auth_servers = [origin]
    last = None
    for a in auth_servers:
        au = urllib.parse.urlparse(a)
        base = f"{au.scheme}://{au.netloc}"
        path = au.path.rstrip("/")
        for cand in (base + "/.well-known/oauth-authorization-server" + path,
                     base + path + "/.well-known/oauth-authorization-server",
                     base + "/.well-known/openid-configuration" + path):
            try:
                meta = _get(cand)
                if meta.get("authorization_endpoint") and meta.get("token_endpoint"):
                    meta["_issuer"] = a
                    return meta
            except Exception as ex:
                last = ex
    raise RuntimeError("no OAuth metadata found for %s%s" % (server_url, (": " + str(last)[:80]) if last else ""))

def mcp_register(meta, redirect_uri):
    """Dynamic client registration. Returns (client_id, client_secret or None)."""
    reg = meta.get("registration_endpoint")
    if not reg:
        raise RuntimeError("this server does not offer dynamic client registration; a pre-registered client id is needed")
    body = json.dumps({"client_name": CLIENT_NAME, "redirect_uris": [redirect_uri],
                       "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                       "token_endpoint_auth_method": "none"}).encode()
    req = urllib.request.Request(reg, data=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read())
    if not d.get("client_id"):
        raise RuntimeError("registration returned no client_id")
    return d["client_id"], d.get("client_secret")

def mcp_authorize_url(meta, client_id, redirect_uri, state, challenge, scopes=None, resource=None):
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    sc = list(scopes or []) or list(meta.get("scopes_supported") or [])
    if sc:
        params["scope"] = " ".join(sc)
    if resource:
        params["resource"] = resource
    return meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)

def mcp_exchange(meta, client_id, client_secret, redirect_uri, code, verifier, scopes, resource=None):
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": client_id, "code_verifier": verifier}
    if client_secret:
        data["client_secret"] = client_secret
    if resource:
        data["resource"] = resource
    t = _post(meta["token_endpoint"], data)
    return _pack("mcp", t, meta["token_endpoint"], client_id, client_secret, scopes or t.get("scope", "").split())

# ---- shared ----
def _pack(provider, t, token_endpoint, client_id, client_secret, scopes):
    if "access_token" not in t:
        raise RuntimeError("token endpoint returned no access token: " + json.dumps(t)[:160])
    return json.dumps({"type": "oauth", "provider": provider, "access_token": t["access_token"],
                       "refresh_token": t.get("refresh_token"), "expires_at": int(time.time()) + int(t.get("expires_in") or 3600),
                       "token_endpoint": token_endpoint, "client_id": client_id, "client_secret": client_secret,
                       "scopes": list(scopes or []), "obtained_at": int(time.time())})

def access_token(token_json, persist=None):
    """A valid bearer token for a stored OAuth connection, refreshing when within 60s of
    expiry. persist(new_json) is called when the stored record changes."""
    d = parse(token_json)
    if not d:
        return token_json
    if d.get("expires_at", 0) - 60 > time.time():
        return d["access_token"]
    if not d.get("refresh_token"):
        raise RuntimeError("access token expired and no refresh token was granted; reconnect")
    data = {"grant_type": "refresh_token", "refresh_token": d["refresh_token"], "client_id": d.get("client_id") or ""}
    if d.get("client_secret"):
        data["client_secret"] = d["client_secret"]
    t = _post(d["token_endpoint"], data)
    d["access_token"] = t["access_token"]; d["expires_at"] = int(time.time()) + int(t.get("expires_in") or 3600)
    if t.get("refresh_token"):
        d["refresh_token"] = t["refresh_token"]
    new = json.dumps(d)
    if persist:
        persist(new)
    return d["access_token"]

def describe(token_json):
    """Short human status for a stored OAuth connection."""
    d = parse(token_json)
    if not d:
        return None
    left = d.get("expires_at", 0) - time.time()
    return {"provider": d.get("provider"), "scopes": d.get("scopes") or [], "refreshable": bool(d.get("refresh_token")),
            "expires_in_min": int(max(left, 0) // 60), "obtained_at": d.get("obtained_at")}
