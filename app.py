"""
Warden, an enterprise AI agent studio where every agent is governed by default.
Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval with a full audit trail.
"""
import os
import datetime
import threading
import json as _json
from flask import Flask, request, redirect, url_for, render_template, abort
import store, governance as gov, agent_runtime as rt
import connection_manager as cmod
import catalog as cat
import telemetry
import policy
import registry
import icons
import evals
import oauth

WARDEN_VERSION = "0.7"

def _build_info():
    """Increment a build number on each new deploy. Identity comes from RENDER_GIT_COMMIT
    if Render provides it, else a BUILD_ID baked into the image at build time (see
    Dockerfile), else 'local'. The counter (persisted on the disk) bumps whenever that
    identity changes; a plain restart of the same build does not bump it."""
    import json
    ident = os.environ.get("RENDER_GIT_COMMIT", "")
    src = "commit"
    if not ident:
        try:
            ident = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "BUILD_ID")).read().strip()
            src = "build"
        except Exception:
            ident = ""
    meta_path = os.path.join(store.DATA_ROOT, "build.json")
    try:
        meta = json.load(open(meta_path))
    except Exception:
        meta = {}
    num = meta.get("build", 0)
    if not ident or ident != meta.get("ident"):
        num += 1
    try:
        json.dump({"ident": ident or "local", "build": num}, open(meta_path, "w"))
    except Exception:
        pass
    if src == "commit":
        label = ident[:7]
    elif src == "build":
        label = ident[:13]           # e.g. 20260828T1912
    else:
        label = "local"
    return num, label

_BUILD_NUM, BUILD_COMMIT = _build_info()
VERSION_FULL = f"{WARDEN_VERSION}.{_BUILD_NUM}"

try:
    from zoneinfo import ZoneInfo
    _PT = ZoneInfo("America/Los_Angeles")
except Exception:
    _PT = datetime.timezone(datetime.timedelta(hours=-7), "PDT")
# captured once at process start; on Render each deploy restarts the process
DEPLOYED_AT = datetime.datetime.now(_PT).strftime("%Y-%m-%d %H:%M %Z")

app = Flask(__name__)
app.secret_key = os.environ.get("WARDEN_SECRET_KEY", "dev-insecure-change-me")
store.init()

# ---- authentication ----
# Sign in with Google (OAuth 2.0), optionally restricted to an email allow-list.
# A single operator password is kept as a fallback. The landing page and /healthz stay
# public; everything else requires sign-in. If neither method is configured the app runs
# open, for local development only.
import hmac, secrets, urllib.parse, urllib.request, json as _authjson
from flask import session
AUTH_PASSWORD = os.environ.get("WARDEN_PASSWORD", "")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_ON = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
ALLOWED_EMAILS = {e.strip().lower() for e in os.environ.get("WARDEN_ALLOWED_EMAILS", "").split(",") if e.strip()}
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("WARDEN_ADMIN_EMAILS", "").split(",") if e.strip()}
AUTH_ON = bool(GOOGLE_ON or AUTH_PASSWORD)
rt.ADMIN_INFO = {"auth_on": AUTH_ON, "admins": sorted(ADMIN_EMAILS)}
_PUBLIC_ENDPOINTS = {"landing", "login", "logout", "google_login", "google_callback", "healthz", "static"}
# OAuth callbacks for connections come back from a provider with a state we issued; auth is
# still required (the operator started the flow while signed in), they are just not admin-gated twice

def current_owner():
    """The signed-in user's identity, used to scope their workspace. Falls back to a
    single 'operator' bucket when auth is off (local/dev, everything is one user's)."""
    return session.get("email") or "operator"

def is_admin():
    """Admins manage shared infrastructure (connections, policies, tokens). Regular users
    only build and run their own agents. With auth off, the single local user is admin."""
    if not AUTH_ON:
        return True
    e = (session.get("email") or "").lower()
    if ADMIN_EMAILS:
        return e in ADMIN_EMAILS
    return e in ALLOWED_EMAILS if ALLOWED_EMAILS else False

def _scope():
    """Owner to filter lists by. None means no filter (single-user / auth off)."""
    return current_owner() if AUTH_ON else None

def _owned_agent(aid):
    ag = store.get_agent(aid)
    if not ag:
        abort(404)
    if AUTH_ON and (ag.get("owner") or "") != current_owner():
        abort(404)   # not yours -> as if it doesn't exist
    return ag

def _owned_run(rid):
    r = store.get_run(rid)
    if not r:
        abort(404)
    if AUTH_ON and (r.get("owner") or "") != current_owner():
        abort(404)
    return r

def _authed():
    return (not AUTH_ON) or bool(session.get("auth"))

def _member_ids(form, self_id=None):
    """Member agent ids from the builder form, restricted to agents the current user owns.
    A lead can never list itself."""
    mine = {a["id"] for a in store.list_agents(_scope())}
    out = []
    for mid in form.getlist("members"):
        if mid in mine and mid != self_id and mid not in out:
            out.append(mid)
    return out

def _team_view(agent):
    """Members of a lead with their governance counts, plus the team's combined ceiling:
    every distinct tool any member can reach, split by whether it runs freely or asks first."""
    idx = {t["key"]: t for t in connected_tools()}
    members, seen_free, seen_ask = [], set(), set()
    for m in rt.members_of(agent):
        keys = [k for k in (m.get("skills") or []) if k in idx]
        free = [idx[k] for k in keys if idx[k]["gate"] != "approval"]
        ask = [idx[k] for k in keys if idx[k]["gate"] == "approval"]
        seen_free.update(t["key"] for t in free); seen_ask.update(t["key"] for t in ask)
        members.append({"agent": m, "freely": len(free), "asks": len(ask), "tools": len(keys),
                        "ask_names": sorted(t["tool"] for t in ask),
                        "budget": m.get("budget_usd") or 0, "is_lead": bool(m.get("members"))})
    dmeta = rt.risk_for(rt.DELEGATE_KEY, rt.tool_index())
    return {"members": members, "ceiling_free": len(seen_free), "ceiling_ask": len(seen_ask),
            "ceiling_ask_names": sorted(idx[k]["tool"] for k in seen_ask),
            "delegate_risk": dmeta["risk"], "delegate_gate": dmeta["gate"],
            "max_delegations": rt.MAX_DELEGATIONS}

def _redirect_uri():
    base = os.environ.get("WARDEN_BASE_URL", "").rstrip("/")
    return (base + "/auth/google/callback") if base else url_for("google_callback", _external=True)

@app.before_request
def _require_auth():
    if not AUTH_ON:
        return
    if (request.endpoint or "") in _PUBLIC_ENDPOINTS:
        return
    if not session.get("auth"):
        return redirect(url_for("login", next=request.path))

def _login_ctx(**kw):
    return dict(google_on=GOOGLE_ON, has_password=bool(AUTH_PASSWORD),
                next=request.args.get("next", ""), **kw)

@app.route("/login", methods=["GET", "POST"])
def login():
    if not AUTH_ON or session.get("auth"):
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        if AUTH_PASSWORD and hmac.compare_digest(request.form.get("password", ""), AUTH_PASSWORD):
            session["auth"] = True; session["email"] = "operator"; session.permanent = True
            nxt = request.form.get("next") or url_for("home")
            return redirect(nxt if nxt.startswith("/") else url_for("home"))
        error = "Incorrect password."
    return render_template("login.html", error=error, **_login_ctx())

@app.route("/auth/google")
def google_login():
    if not GOOGLE_ON:
        abort(404)
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    session["oauth_next"] = request.args.get("next", "")
    params = {"client_id": GOOGLE_CLIENT_ID, "redirect_uri": _redirect_uri(),
              "response_type": "code", "scope": "openid email profile",
              "state": state, "access_type": "online", "prompt": "select_account"}
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params))

@app.route("/auth/google/callback")
def google_callback():
    if not GOOGLE_ON:
        abort(404)
    if not request.args.get("state") or request.args.get("state") != session.pop("oauth_state", None):
        return render_template("login.html", error="Sign-in expired. Please try again.", **_login_ctx()), 400
    code = request.args.get("code")
    if not code:
        return render_template("login.html", error="Google sign-in was cancelled.", **_login_ctx())
    try:
        data = urllib.parse.urlencode({"code": code, "client_id": GOOGLE_CLIENT_ID,
                                       "client_secret": GOOGLE_CLIENT_SECRET,
                                       "redirect_uri": _redirect_uri(),
                                       "grant_type": "authorization_code"}).encode()
        tok = _authjson.loads(urllib.request.urlopen(
            urllib.request.Request("https://oauth2.googleapis.com/token", data=data), timeout=10).read())
        info = _authjson.loads(urllib.request.urlopen(urllib.request.Request(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": "Bearer " + tok.get("access_token", "")}), timeout=10).read())
    except Exception:
        return render_template("login.html", error="Could not complete Google sign-in. Try again.", **_login_ctx())
    email = (info.get("email") or "").lower()
    if not email or info.get("email_verified") is False:
        return render_template("login.html", error="Your Google email could not be verified.", **_login_ctx())
    if ALLOWED_EMAILS and email not in ALLOWED_EMAILS:
        return render_template("login.html", error="%s is not authorized for this studio." % email, **_login_ctx()), 403
    session["auth"] = True; session["email"] = email; session["name"] = info.get("name") or email
    session.permanent = True
    nxt = session.pop("oauth_next", "") or url_for("home")
    return redirect(nxt if nxt.startswith("/") else url_for("home"))

@app.route("/admin/cleanup-orphans", methods=["POST"])
def cleanup_orphans():
    if not is_admin():
        abort(403)
    n = store.delete_orphan_agents()
    return {"deleted": n}

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))

@app.context_processor
def _auth_ctx():
    return {"auth_on": AUTH_ON, "authed": _authed(), "user_email": session.get("email"),
            "is_admin": is_admin(),
            "daily_cap": float(os.environ.get("WARDEN_DAILY_BUDGET", "0") or 0)}

_ADMIN_ENDPOINTS = {"connections", "enable_connection", "disable_connection", "tool_risk",
                    "oauth_start", "oauth_google_callback", "oauth_mcp_callback",
                    "discover", "discover_add", "discover_remove", "discover_json",
                    "policies", "create_policy", "toggle_policy", "delete_policy"}

@app.before_request
def _require_admin():
    if (request.endpoint or "") in _ADMIN_ENDPOINTS and not is_admin():
        if request.method == "GET":
            return redirect(url_for("home"))
        abort(403)


def _env_specs():
    """Servers to auto-connect on boot, from WARDEN_AUTOCONNECT (comma-separated catalog ids).
    Tokens resolve from each server's env var, so config survives redeploys."""
    ids = [x.strip() for x in os.environ.get("WARDEN_AUTOCONNECT", "").split(",") if x.strip()]
    return [{"id": i, "transport": cat.BY_ID[i]["transport"]} for i in ids if i in cat.BY_ID]

def cm():
    c = cmod.manager()
    c.ensure_started(store.enabled_connections() + _env_specs())
    return c

@app.context_processor
def inject_globals():
    try:
        open_requests = _requests_for_me() if _authed() else []
    except Exception:
        open_requests = []
    return {"pending": store.pending_approvals(_scope()), "mode": rt.mode(),
            "open_requests": open_requests, "admin_emails": sorted(ADMIN_EMAILS),
            "version": VERSION_FULL, "commit": BUILD_COMMIT, "deployed_at": DEPLOYED_AT}

def connected_tools():
    """All tools across connected servers, with effective governance risk."""
    ovr = store.all_overrides()
    out = []
    for t in cm().all_tools():
        m = gov.meta(t["key"], t["tool"], t["description"], ovr.get(t["key"]))
        out.append({**t, "risk": m["risk"], "gate": m["gate"], "override": ovr.get(t["key"])})
    return out

def tools_by_server():
    groups = {}
    for t in connected_tools():
        groups.setdefault(t["server_id"], {"name": t["server_name"], "tools": []})
        groups[t["server_id"]]["tools"].append(t)
    return groups

def arg_summary(inp):
    """A one-line, human summary of a tool's arguments for compact rows (dashboard,
    lists). Never dumps a code blob: prefers a filename, then an amount, then a short field."""
    if not isinstance(inp, dict):
        return str(inp)[:110]
    f = inp.get("filename") or inp.get("path") or inp.get("file")
    if f:
        return f
    if "amount" in inp:
        r = inp.get("reason") or inp.get("rationale") or ""
        return ("$%s" % inp.get("amount")) + ((" \u00b7 " + str(r)) if r else "")
    for k, v in inp.items():
        if isinstance(v, str) and v.strip():
            return "%s: %s" % (k, v[:90])
    return _json.dumps(inp)[:110]

app.jinja_env.globals["arg_summary"] = arg_summary

@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/app")
def home():
    servers = cm().connected_servers()
    return render_template("dashboard.html", agents=store.list_agents(_scope()), runs=store.list_runs(12, _scope()),
                           pending=_with_team_context(store.pending_approvals(_scope())), servers=servers,
                           tool_count=len(connected_tools()))

@app.route("/connections")
def connections():
    status = {s["id"]: s for s in cm().connected_servers()}
    dq = (request.args.get("discover") or "").strip()
    discover = registry.search(dq) if dq else None
    oauth_status = {}
    for c_ in store.enabled_connections():
        d_ = oauth.describe(c_.get("token"))
        if d_: oauth_status[c_["id"]] = d_
    return render_template("connections.html", catalog=merged_catalog(), status=status,
                           enabled={c["id"] for c in store.enabled_connections()},
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL,
                           tools=connected_tools(), discover=discover, discover_q=dq,
                           requests=_requests_for_me(), oauth_status=oauth_status, google_on=GOOGLE_ON,
                           google_redirect=_oauth_redirect("google") if GOOGLE_ON else "",
                           oauth_error=request.args.get("oauth_error", ""), just_connected=request.args.get("connected", ""),
                           grant_to=request.args.get("grant_to", ""), resume=request.args.get("resume", ""),
                           connect_id=request.args.get("connect", ""),
                           grant_agent=store.get_agent(request.args.get("grant_to", "")) if request.args.get("grant_to") else None)

@app.route("/connections/enable", methods=["POST"])
def enable_connection():
    cid = request.form.get("id"); entry = cat_by_id(cid)
    if not entry: abort(404)
    transport = entry["transport"]
    token = request.form.get("token") or None
    command = request.form.get("command") or None
    url = request.form.get("url") or entry.get("run")
    store.enable_connection(cid, transport, command=command, url=url, token=token)
    st = cm().connect_spec({"id": cid, "transport": transport, "command": command, "url": url, "token": token})
    grant_to, resume = request.form.get("grant_to"), request.form.get("resume")
    granted = False
    if grant_to and (st or {}).get("status") == "connected":
        _grant_and_resume(cid, grant_to, resume); granted = True
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True, "status": (st or {}).get("status"), "error": (st or {}).get("error"),
                "tool_count": (st or {}).get("tool_count", 0), "granted": granted,
                "resume_url": url_for("run_view", rid=resume) if (granted and resume) else None}
    if granted and resume:
        return redirect(url_for("run_view", rid=resume))
    return redirect(url_for("connections"))

@app.route("/connections/disable", methods=["POST"])
def disable_connection():
    cid = request.form.get("id")
    store.disable_connection(cid); cm().disconnect(cid)
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True}
    return redirect(url_for("connections"))

def merged_catalog():
    """Built-in curated catalog plus any servers discovered from the MCP registry,
    so discovered servers become connectable through the same flow."""
    extra = []
    for cs in store.list_custom_servers():
        extra.append({"id": cs["id"], "name": cs["name"], "category": cs["category"] or "Discovered",
                      "maintainer": "community", "transport": cs["transport"],
                      "run": cs["url"] or cs["command"] or "",
                      "auth": "api_key" if cs["transport"] == "http" else "",
                      "status": "remote" if cs["transport"] == "http" else "needs runtime",
                      "env": "", "desc": cs["description"] or "", "repo": cs.get("repo") or "",
                      "custom": True})
    return list(cat.CATALOG) + extra

def cat_by_id(cid):
    for c in merged_catalog():
        if c["id"] == cid:
            return c
    return None

@app.route("/discover.json")
def discover_json():
    return registry.search(request.args.get("q", ""))

@app.route("/discover/add", methods=["POST"])
def discover_add():
    import re as _re
    name = (request.form.get("display") or request.form.get("name") or "server").strip()
    transport = request.form.get("transport", "remote")
    endpoint = (request.form.get("endpoint") or "").strip()
    desc = request.form.get("desc", "")
    repo = request.form.get("repo", "")
    sid = "disc_" + (_re.sub(r"[^a-z0-9]+", "_", (request.form.get("name") or name).lower()).strip("_")[:44] or "server")
    if transport == "remote":
        store.add_custom_server(sid, name, "Discovered", "http", url=endpoint, description=desc, repo=repo)
    else:
        store.add_custom_server(sid, name, "Discovered", "stdio_node", command=endpoint, description=desc, repo=repo)
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True, "id": sid}
    return redirect(url_for("connections") + "#" + sid)

@app.route("/discover/remove", methods=["POST"])
def discover_remove():
    store.delete_custom_server(request.form.get("id"))
    return redirect(url_for("connections"))

@app.route("/tool-risk", methods=["POST"])
def tool_risk():
    store.set_override(request.form.get("key"), request.form.get("risk"))
    return redirect(request.form.get("back") or url_for("connections"))

@app.route("/connlist")
def connlist():
    status = {s["id"]: s for s in cm().connected_servers()}
    return render_template("_connlist.html", catalog=merged_catalog(), status=status,
                           enabled={c["id"] for c in store.enabled_connections()},
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL)

@app.route("/tools.json")
def tools_json():
    groups = {}
    for t in connected_tools():
        g = groups.setdefault(t["server_id"], {"server": t["server_name"], "tools": []})
        g["tools"].append({"key": t["key"], "tool": t["tool"], "risk": t["risk"],
                           "gate": t["gate"], "description": t["description"]})
    return {"groups": list(groups.values())}

AGENT_TEMPLATES = [
    {"id": "billing", "name": "Billing Resolver",
     "instructions": "You resolve billing issues for enterprise customers. Look up the account, check policy, and make the customer whole. Be concise and never guess at numbers.",
     "servers": ["builtin_enterprise"], "tools": ["lookup_customer", "search_knowledge", "create_ticket", "issue_refund"]},
    {"id": "triage", "name": "Support Triage",
     "instructions": "You triage inbound support requests. Look up the customer, search the knowledge base for a known fix, and open a ticket with a clear summary when it needs a human. Do not promise resolutions you cannot verify.",
     "servers": ["builtin_enterprise"], "tools": ["lookup_customer", "search_knowledge", "create_ticket"]},
    {"id": "refund_audit", "name": "Refund Auditor (read-only)",
     "instructions": "You investigate refund requests but cannot issue refunds yourself. Look up the account, verify the charge against policy, and write a clear recommendation for a human to approve. State the exact amount and the policy basis.",
     "servers": ["builtin_enterprise"], "tools": ["lookup_customer", "search_knowledge"]},
    {"id": "repo_qa", "name": "Codebase Explainer",
     "instructions": "You answer questions about a public GitHub repository. Read its docs and structure, then explain how it works in plain language with references to the relevant files. If you are unsure, say so.",
     "servers": ["deepwiki"], "tools": ["ask_question", "read_wiki_contents", "read_wiki_structure"]},
    {"id": "repo_maint", "name": "Repo Maintainer",
     "instructions": "You help maintain a GitHub repository. Read issues, pull requests, and code to understand the request, then propose changes. Any write (a branch, a commit, a pull request) is held for review before it runs. Never merge without explicit approval.",
     "servers": ["github"], "tools": ["get_file_contents", "list_issues", "list_pull_requests", "search_code",
               "create_branch", "create_pull_request", "push_files", "merge_pull_request"]},
    {"id": "files", "name": "File Organizer",
     "instructions": "You organize a working folder. List and read files to understand what is there, then propose a tidier structure. Any file you create or overwrite is held for review first.",
     "servers": ["builtin_files"], "tools": ["list_files", "read_file", "write_file"]},
    {"id": "self_audit", "name": "Warden Self-Audit",
     "instructions": "You audit Warden's own source code. List and read the source, run the self-check, and report concrete issues with file and line references. Any fix you propose is held as a patch for a human to review before anything changes.",
     "servers": ["builtin_code"], "tools": ["list_source", "read_source", "run_selfcheck", "propose_patch"]},
    {"id": "kb", "name": "Knowledge Assistant",
     "instructions": "You answer policy and product questions from the internal knowledge base and public repo docs. Cite the source you used. If the answer is not in the sources, say you do not know rather than guessing.",
     "servers": ["builtin_enterprise", "deepwiki"], "tools": ["search_knowledge", "ask_question", "read_wiki_contents"]},
    {"id": "incident", "name": "Incident Responder",
     "instructions": "You are on-call support. Read active alerts, error spikes, and recent metrics to understand what is failing, then propose the smallest safe remediation. Reading is automatic. Acknowledging or resolving an incident, and anything that changes production, is held for a human. Never restart or roll back without approval.",
     "servers": ["sentry", "grafana", "pagerduty"], "tools": ["acknowledge_incident", "resolve_incident", "resolve_issue"]},
    {"id": "jira", "name": "Jira / Confluence Agent",
     "instructions": "You help manage work in Jira and Confluence. Read issues, boards, and wiki pages to understand context, then draft updates. Comments and new items are routine; transitioning, closing, or deleting an issue is held for a human. Always cite the issue key or page you used.",
     "servers": ["atlassian"], "tools": ["add_comment", "create_issue", "transition_issue", "create_page", "update_page"]},
    {"id": "warehouse", "name": "Warehouse Analyst",
     "instructions": "You answer questions from the data warehouse. Run read-only queries to investigate, and explain what the numbers mean in plain language. Anything that writes, updates, deletes, or changes schema is held for a human. Never guess at a number you did not query.",
     "servers": ["supabase", "postgres"], "tools": ["execute_sql", "apply_migration"]},
    {"id": "billing_desk", "name": "Billing Desk (team)", "team": True,
     "instructions": "You run the billing desk. For each customer issue, have the Refund Auditor verify the account and the charge against policy first, then hand the verified facts and exact amount to the Billing Resolver to make it right. Never issue a refund yourself; report exactly what each member did.",
     "servers": ["builtin_enterprise"], "tools": ["lookup_customer"],
     "members": ["refund_audit", "billing"]},
    {"id": "research", "name": "Web Research Analyst",
     "instructions": "You research questions using the web and public documentation. Search, fetch, and read sources, then synthesize an answer with citations to the sources you used. If the sources do not support a claim, say so plainly. This agent is read-only by design and never needs to write anything.",
     "servers": ["deepwiki", "firecrawl", "exa", "fetch"], "tools": ["ask_question", "read_wiki_contents", "search", "scrape", "fetch"]},
]

def _builder_ctx(edit_agent=None):
    status = {s["id"]: s for s in cm().connected_servers()}
    groups = tools_by_server()
    connected_ids = set(groups.keys())
    catalog_meta = {c["id"]: {"name": c["name"], "connected": c["id"] in connected_ids}
                    for c in merged_catalog()}
    return dict(groups=groups, catalog=merged_catalog(), status=status,
                enabled={c["id"] for c in store.enabled_connections()},
                mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL,
                templates=AGENT_TEMPLATES, catalog_meta=catalog_meta,
                edit_agent=edit_agent,
                edit_skills=set(edit_agent["skills"]) if edit_agent else None,
                candidates=[a for a in store.list_agents(_scope())
                            if not edit_agent or a["id"] != edit_agent["id"]],
                edit_members=set(edit_agent.get("members") or []) if edit_agent else set(),
                delegate_risk=rt.risk_for(rt.DELEGATE_KEY, rt.tool_index())["risk"])

@app.route("/new")
def new_agent():
    return render_template("builder.html", **_builder_ctx())

@app.route("/agent/<aid>/edit")
def edit_agent(aid):
    ag = _owned_agent(aid)
    return render_template("builder.html", **_builder_ctx(ag))

@app.route("/agent/<aid>/update", methods=["POST"])
def update_agent(aid):
    ag = _owned_agent(aid)
    name = request.form.get("name", "").strip() or ag["name"]
    instructions = request.form.get("instructions", "").strip()
    model = request.form.get("model", "").strip() or ag["model"] or rt.MODEL_DEFAULT
    skills = request.form.getlist("skills")
    store.update_agent(aid, name, instructions, model, skills, icon=request.form.get("icon", ""),
                       budget_usd=request.form.get("budget_usd") or 0,
                       members=_member_ids(request.form, self_id=aid))
    return redirect(url_for("agent", aid=aid))

@app.route("/agent/<aid>/delete", methods=["POST"])
def delete_agent(aid):
    _owned_agent(aid)
    store.delete_agent(aid)
    return redirect(url_for("home"))

@app.route("/agents", methods=["POST"])
def create_agent():
    name = request.form.get("name", "").strip() or "Untitled agent"
    instructions = request.form.get("instructions", "").strip()
    model = request.form.get("model", "").strip() or rt.MODEL_DEFAULT
    skills = request.form.getlist("skills")
    members = _member_ids(request.form)
    # a team template can bring its own members: create them for the user when none were picked
    tpl = next((t for t in AGENT_TEMPLATES if t["id"] == request.form.get("template")), None)
    if tpl and tpl.get("members") and not members:
        members = _create_template_members(tpl)
    aid = store.create_agent(name, instructions, model, skills, owner=current_owner(), icon=request.form.get("icon", ""),
                             budget_usd=request.form.get("budget_usd") or 0, members=members)
    return redirect(url_for("agent", aid=aid))

def _create_template_members(tpl):
    """Create the member agents a team template names (from their own templates), granting
    each the template's tools that are connected right now. Returns the new ids."""
    keys = {t["tool"]: t["key"] for t in connected_tools()}
    by_id = {t["id"]: t for t in AGENT_TEMPLATES}
    ids = []
    for mid in tpl["members"]:
        mt = by_id.get(mid)
        if not mt:
            continue
        skills = [keys[n] for n in mt["tools"] if n in keys]
        ids.append(store.create_agent(mt["name"], mt["instructions"], rt.MODEL_DEFAULT, skills,
                                      owner=current_owner(), icon=mt.get("icon", "")))
    return ids

@app.route("/agent/<aid>")
def agent(aid):
    ag = _owned_agent(aid)
    all_tools = connected_tools()
    idx = {t["key"]: t for t in all_tools}
    skills = set(ag["skills"] or [])
    granted = [idx[k] for k in (ag["skills"] or []) if k in idx]
    # governance tiers: what runs on its own, what asks first, and what is deliberately withheld
    freely = sorted([t for t in granted if t["gate"] != "approval"], key=lambda t: t["tool"])
    asks   = sorted([t for t in granted if t["gate"] == "approval"], key=lambda t: t["tool"])
    agent_server_ids = {t["server_id"] for t in granted}
    withheld = sorted([t for t in all_tools
                       if t["server_id"] in agent_server_ids and t["key"] not in skills],
                      key=lambda t: (t["gate"] != "approval", t["tool"]))
    counts = {"total": len(granted), "freely": len(freely), "asks": len(asks), "withheld": len(withheld)}
    missing = [k for k in (ag["skills"] or []) if k not in idx]
    team = _team_view(ag) if ag.get("members") else None
    if team and team["members"]:
        dm = rt.risk_for(rt.DELEGATE_KEY, rt.tool_index())
        dtool = {"key": rt.DELEGATE_KEY, "tool": "delegate", "server_name": "Team", "risk": dm["risk"],
                 "gate": dm["gate"], "description": "Hand a task to a team member agent."}
        (asks if dm["gate"] == "approval" else freely).append(dtool)
        counts["total"] += 1; counts["asks" if dm["gate"] == "approval" else "freely"] += 1
    runs = [r for r in store.list_runs(50) if r["agent_id"] == aid]
    leads = store.leads_of(aid)
    est_rate = rt.rate_for(ag["model"])
    est_base = max(200, len(ag["instructions"] or "") // 4 + len(granted) * 80 + 350)
    return render_template("agent.html", agent=ag, freely=freely, asks=asks, withheld=withheld,
                           counts=counts, missing=missing, runs=runs, team=team, leads=leads,
                           est_in_rate=est_rate[0], est_base=est_base, live=(rt.mode() == "live"))

def _advance_bg(rid):
    """Run the agent loop in the background so the browser isn't blocked."""
    def worker():
        try:
            rt.advance(rid)
        except Exception as e:
            try:
                r = store.get_run(rid)
                store.audit(rid, r["agent_id"], "error", detail={"text": str(e)[:200]})
                store.update_run(rid, status="error")
            except Exception:
                pass
    threading.Thread(target=worker, daemon=True).start()

@app.route("/run", methods=["POST"])
def run():
    aid = request.form.get("agent_id"); user_input = request.form.get("input", "").strip()
    if not user_input: abort(400)
    _owned_agent(aid)
    rid = store.create_run(aid, user_input)
    _advance_bg(rid)
    return redirect(url_for("run_view", rid=rid))

@app.route("/run/<rid>")
def run_view(rid):
    r = _owned_run(rid)
    ag = store.get_agent(r["agent_id"])
    parent = store.get_run(r["parent_run_id"]) if r.get("parent_run_id") else None
    lead = store.get_agent(parent["agent_id"]) if parent else None
    ev = store.get_eval_run(r["eval_run_id"]) if r.get("eval_run_id") else None
    return render_template("run.html", run=r, agent=ag, audit=store.audit_for_run(rid),
                           approvals=store.approvals_for_run(rid), parent=parent, lead=lead,
                           is_team=bool(ag and ag.get("members")),
                           annotations=store.annotations_for_run(rid),
                           suites=store.list_suites(_scope(), agent_id=r["agent_id"]),
                           eval_run=ev, categories=_categories())

def _fmt_event(e):
    d = e.get("detail") or {}
    kind = e["kind"]
    if kind in ("run_started", "user_message"):
        text = d.get("input") or d.get("text") or ""
    elif kind in ("final", "thought", "error", "budget_stop"):
        text = d.get("text", "")
    elif kind in ("delegation", "delegation_result"):
        text = d.get("task") or d.get("result") or ""
    elif "result" in d:
        res = d["result"]
        s = res if isinstance(res, str) else _json.dumps(res, ensure_ascii=False)
        s = " ".join(s.split())               # collapse newlines/whitespace
        text = "-> " + s[:200]
    elif "input" in d:
        s = _json.dumps(d["input"], ensure_ascii=False)
        text = " ".join(s.split())[:200]
    else:
        text = ""
    out = {"ts": (e["ts"] or "")[11:19], "kind": kind, "risk": e.get("risk"),
           "tool": (e["skill"] or "").split("__")[-1] if e.get("skill") else "",
           "text": text}
    if kind in ("delegation", "delegation_result"):
        out["child_run"] = d.get("child_run"); out["member"] = d.get("member")
    if kind == "connection_request":
        out["text"] = d.get("need") or ""
    if kind == "connection_granted":
        out["text"] = d.get("text") or ""
    if kind == "eval_held":
        out["text"] = " ".join(_json.dumps(d.get("input"), ensure_ascii=False).split())[:200]
    if kind == "budget_stop" and d.get("scope"):
        out["scope"] = d["scope"]
    return out

_CODE_FIELDS = ("new_content", "content", "patch", "diff", "code", "source", "body", "text")
_PROSE_FIELDS = ("rationale", "reason", "note", "description", "summary", "explanation")
_LANGS = {"py": "python", "js": "javascript", "ts": "typescript", "jsx": "jsx", "tsx": "tsx",
          "html": "html", "css": "css", "json": "json", "md": "markdown", "sh": "bash",
          "yml": "yaml", "yaml": "yaml", "sql": "sql", "go": "go", "rs": "rust", "java": "java"}

def _lang_of(fname):
    if fname and "." in fname:
        return _LANGS.get(fname.rsplit(".", 1)[-1].lower(), "")
    return ""

import difflib as _difflib
_APP_DIR = os.path.dirname(os.path.abspath(__file__))

def _read_current(filename):
    """Read the current version of a file, restricted to Warden's own source dir
    (self-audit's propose_patch targets these). Returns None if not found."""
    if not filename:
        return None
    base = os.path.realpath(_APP_DIR)
    cand = os.path.realpath(os.path.join(base, os.path.basename(filename)))
    if not cand.startswith(base):
        return None
    try:
        with open(cand) as f:
            return f.read()
    except Exception:
        return None

def _diff_lines(old, new):
    out, add, rem = [], 0, 0
    for line in _difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=3):
        if line[:3] in ("---", "+++"):
            continue
        if line.startswith("@@"):
            out.append({"sign": "@", "text": line})
        elif line.startswith("+"):
            out.append({"sign": "+", "text": line[1:]}); add += 1
        elif line.startswith("-"):
            out.append({"sign": "-", "text": line[1:]}); rem += 1
        else:
            out.append({"sign": " ", "text": line[1:] if line[:1] == " " else line})
    return out, add, rem

def format_args(inp):
    """Turn a tool's arguments into readable parts: code fields become code blocks (or a
    diff when the current file is known), reasons render as prose, else labeled rows."""
    if not isinstance(inp, dict):
        return [{"type": "field", "label": "input", "value": str(inp)}]
    fname = inp.get("filename") or inp.get("path") or inp.get("file")
    parts, used_fname = [], False
    for k, v in inp.items():
        if k in ("filename", "file", "path"):
            continue
        if k in _CODE_FIELDS and isinstance(v, str) and ("\n" in v or len(v) > 100):
            old = _read_current(fname)
            if old is not None and old != v:
                lines, add, rem = _diff_lines(old, v)
                parts.append({"type": "diff", "label": (fname or k), "lang": _lang_of(fname),
                              "lines": lines, "added": add, "removed": rem})
            else:
                parts.append({"type": "code", "label": (fname or k), "lang": _lang_of(fname), "content": v})
            used_fname = True
        elif k in _PROSE_FIELDS and isinstance(v, str):
            parts.append({"type": "prose", "label": k, "value": v})
        elif isinstance(v, (dict, list)):
            parts.append({"type": "json", "label": k, "value": _json.dumps(v, indent=2)})
        else:
            parts.append({"type": "field", "label": k, "value": str(v)})
    if fname and not used_fname:
        parts.insert(0, {"type": "field", "label": "path", "value": fname})
    return parts

app.jinja_env.globals["fmt_args"] = format_args
app.jinja_env.globals["describe_policy"] = policy.describe
app.jinja_env.globals["agent_icon"] = icons.svg
app.jinja_env.globals["ICON_SET"] = icons.PLANETS

@app.route("/run/<rid>/events")
def run_events(rid):
    r = _owned_run(rid)
    audit = store.audit_for_run(rid)
    mc = []
    for e in audit:
        if e["kind"] == "model_call" and e["detail"]:
            d = e["detail"] if isinstance(e["detail"], dict) else _json.loads(e["detail"])
            mc.append(d)
    usage = rt.tree_usage(rid)
    pend = [{"id": a["id"], "tool": (a["skill"] or "").split("__")[-1], "risk": a["risk"],
             "parts": format_args(a["arguments"].get("input")),
             "approve": url_for("approval", apid=a["id"]), "member": None}
            for a in store.approvals_for_run(rid) if a["status"] == "pending"]
    # a lead's conversation also surfaces what its members are waiting on
    delegations = []
    for ch in store.child_runs(rid):
        m = store.get_agent(ch["agent_id"]) or {"name": "member", "icon": "", "id": ch["agent_id"]}
        cu = rt.tree_usage(ch["id"])
        steps = [e for e in store.audit_for_run(ch["id"])
                 if e["kind"] in ("tool_result", "tool_result_gated", "denied", "policy_denied")]
        delegations.append({"tool_use_id": ch.get("parent_tool_use_id"), "run": ch["id"],
                            "url": url_for("run_view", rid=ch["id"]), "member": m["name"],
                            "icon": icons.svg(m.get("icon"), seed=m["id"]), "task": ch["input"],
                            "status": ch["status"], "cost": cu["cost"], "calls": cu["calls"],
                            "steps": [{"tool": (e["skill"] or "").split("__")[-1], "risk": e["risk"],
                                       "kind": e["kind"]} for e in steps],
                            "result": rt._final_text(ch) if ch["status"] in ("done", "error") else ""})
        for a in store.approvals_for_run(ch["id"]):
            if a["status"] == "pending":
                pend.append({"id": a["id"], "tool": (a["skill"] or "").split("__")[-1], "risk": a["risk"],
                             "parts": format_args(a["arguments"].get("input")),
                             "approve": url_for("approval", apid=a["id"]), "member": m["name"]})
    waiting_on = [dg["member"] for dg in delegations if dg["status"] in ("running", "awaiting_approval")]
    requests_ = _open_requests(rid, r["agent_id"])
    return {"status": r["status"], "events": [_fmt_event(e) for e in audit],
            "pending": pend, "back": url_for("run_view", rid=rid), "delegations": delegations,
            "waiting_on": waiting_on, "team": len(delegations) > 0, "requests": requests_, "admin": is_admin(),
            "admins": sorted(ADMIN_EMAILS),
            "cost": usage["cost"], "tokens": usage["tokens"], "calls": usage["calls"], "live": rt.mode() == "live"}

@app.route("/run/<rid>/say", methods=["POST"])
def run_say(rid):
    r = _owned_run(rid)
    if r["status"] in ("running", "awaiting_approval"):
        return {"error": "busy"}, 409
    text = request.form.get("input", "").strip()
    if not text:
        return {"error": "empty"}, 400
    tr = r["transcript"]
    tr.append({"role": "user", "content": text})
    store.update_run(rid, status="running", transcript=tr)
    store.audit(rid, r["agent_id"], "user_message", detail={"text": text})
    _advance_bg(rid)
    return {"ok": True}

@app.route("/approval/<apid>", methods=["POST"])
def approval(apid):
    ap = store.get_approval(apid)
    if not ap: abort(404)
    if AUTH_ON:
        ag = store.get_agent(ap["agent_id"])
        if not ag or (ag.get("owner") or "") != current_owner():
            abort(404)
    decision = request.form.get("decision")
    if decision in ("approved", "denied"):
        store.decide_approval(apid, decision, by=current_owner()); _advance_bg(ap["run_id"])
    # AJAX callers get JSON; form callers get a redirect
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True}
    return redirect(request.form.get("back") or url_for("run_view", rid=ap["run_id"]))

def _with_team_context(pending):
    """Label approvals raised inside a member run with the lead that delegated the work,
    and point 'Open run' at the lead's conversation where the gate is shown in context."""
    out = []
    for ap in pending:
        ap = dict(ap)
        r = store.get_run(ap["run_id"])
        ag = store.get_agent(ap["agent_id"])
        ap["agent_name"] = ag["name"] if ag else ""
        ap["lead_name"] = None; ap["lead_run"] = None
        if r and r.get("parent_run_id"):
            root = store.root_run(r)
            lead = store.get_agent(root["agent_id"]) if root else None
            if lead:
                ap["lead_name"] = lead["name"]; ap["lead_run"] = root["id"]
        out.append(ap)
    return out

@app.route("/approvals")
def approvals():
    return render_template("approvals.html", pending=_with_team_context(store.pending_approvals(_scope())),
                           requests=_requests_for_me())

@app.route("/architecture")
def architecture():
    servers = cm().connected_servers()
    return render_template("architecture.html", servers=servers, tools=connected_tools())

@app.route("/audit")
def audit():
    return render_template("audit.html", events=(store.audit_for_owner(_scope(),300) if _scope() else store.audit_all(300)), integrity=store.verify_audit())

@app.route("/policies")
def policies():
    return render_template("policies.html", policies=store.list_policies(),
                           agents=store.list_agents(), ops=policy.OPS)

@app.route("/policies/create", methods=["POST"])
def create_policy():
    f = request.form
    effect = f.get("effect", "require_approval")
    if effect not in policy.EFFECTS:
        effect = "require_approval"
    name = (f.get("name") or "").strip() or "Untitled policy"
    store.create_policy(name, effect,
                        agent_id=f.get("agent_id") or "*", tool=(f.get("tool") or "*").strip(),
                        field=(f.get("field") or "").strip(), op=f.get("op") or "",
                        value=(f.get("value") or "").strip(),
                        priority=int(f.get("priority") or 100))
    return redirect(url_for("policies"))

@app.route("/policies/<pid>/toggle", methods=["POST"])
def toggle_policy(pid):
    p = store.get_policy(pid)
    if p:
        store.toggle_policy(pid, not p["enabled"])
    return redirect(url_for("policies"))

@app.route("/policies/<pid>/delete", methods=["POST"])
def delete_policy(pid):
    store.delete_policy(pid)
    return redirect(url_for("policies"))

@app.route("/observability")
def observability():
    from collections import Counter, defaultdict
    events = store.audit_for_owner(_scope(), 4000) if _scope() else store.audit_all(4000)
    runs = store.list_runs(500, _scope())
    agents = {a["id"]: a["name"] for a in store.list_agents(_scope())}

    model_calls = [e for e in events if e["kind"] == "model_call"]
    tool_calls = [e for e in events if e["kind"] in ("tool_result", "tool_result_gated")]
    denied_ev = [e for e in events if e["kind"] == "denied"]

    def d(e): return e.get("detail") or {}
    total_cost = sum(d(e).get("cost", 0) or 0 for e in model_calls)
    total_tokens = sum((d(e).get("input_tokens", 0) or 0) + (d(e).get("output_tokens", 0) or 0) for e in model_calls)
    tool_errors = sum(1 for e in tool_calls if d(e).get("outcome") == "error")

    ac = store.approval_counts()
    approved = ac.get("approved", 0); denied = ac.get("denied", 0); pending = ac.get("pending", 0)
    decided = approved + denied

    kpis = {
        "runs": len(runs),
        "cost": total_cost,
        "tokens": total_tokens,
        "approval_rate": (approved / decided) if decided else None,
        "denial_rate": (denied / decided) if decided else None,
        "tool_err_rate": (tool_errors / len(tool_calls)) if tool_calls else None,
        "gated": approved + denied + pending,
        "decided": decided, "denied": denied, "approved": approved, "pending": pending,
        "mode": rt.mode(),
    }

    risk_dist = Counter(e["risk"] for e in tool_calls if e["risk"])

    per_agent = {}
    for r in runs:
        a = per_agent.setdefault(r["agent_id"], {"name": agents.get(r["agent_id"], "—"), "runs": 0, "cost": 0.0, "gated": 0, "denied": 0})
        a["runs"] += 1
    for e in model_calls:
        a = per_agent.get(e["agent_id"]);  a and a.__setitem__("cost", a["cost"] + (d(e).get("cost", 0) or 0))
    for e in events:
        if e["kind"] == "approval_request" and e["agent_id"] in per_agent: per_agent[e["agent_id"]]["gated"] += 1
    for e in denied_ev:
        if e["agent_id"] in per_agent: per_agent[e["agent_id"]]["denied"] += 1
    agent_rows = sorted(per_agent.values(), key=lambda x: x["runs"], reverse=True)

    per_tool = {}
    for e in tool_calls:
        name = (e["skill"] or "").split("__")[-1]
        t = per_tool.setdefault(name, {"tool": name, "calls": 0, "errors": 0, "lat": [], "risk": e["risk"]})
        t["calls"] += 1
        if d(e).get("outcome") == "error": t["errors"] += 1
        lm = d(e).get("latency_ms")
        if lm: t["lat"].append(lm)
    tool_rows = []
    for t in per_tool.values():
        t["avg_ms"] = int(sum(t["lat"]) / len(t["lat"])) if t["lat"] else None
        t["err_rate"] = (t["errors"] / t["calls"]) if t["calls"] else 0
        tool_rows.append(t)
    tool_rows.sort(key=lambda x: x["calls"], reverse=True)

    # runs per day (last 10 with activity)
    by_day = defaultdict(int)
    for r in runs:
        by_day[(r["created_at"] or "")[:10]] += 1
    days = sorted(by_day.items())[-10:]

    return render_template("observability.html", k=kpis, risk=dict(risk_dist),
                           agents=agent_rows, tools=tool_rows, days=days,
                           redact=telemetry.redaction_status(), integrity=store.verify_audit())

@app.route("/run/<rid>/trace")
def run_trace(rid):
    import telemetry
    r = store.get_run(rid)
    if not r: abort(404)
    spans, meta = telemetry.build_spans(rid)
    return render_template("trace.html", run=r, agent=store.get_agent(r["agent_id"]),
                           spans=spans, meta=meta,
                           otlp_configured=bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")))

@app.route("/run/<rid>/trace.json")
def run_trace_json(rid):
    import telemetry
    if not store.get_run(rid): abort(404)
    return app.response_class(_json.dumps(telemetry.to_otlp(rid), indent=2),
                              mimetype="application/json")

@app.route("/run/<rid>/export", methods=["POST"])
def run_export(rid):
    import telemetry
    if not store.get_run(rid): abort(404)
    return telemetry.export(rid)

# ---------------- capability requests ----------------
def _open_requests(rid, agent_id):
    """Connection requests raised in a run, with whether each match is now connected and
    granted to the agent, so the conversation can show what is still outstanding."""
    ag = store.get_agent(agent_id) or {"skills": []}
    granted_servers = {k.split("__")[0] for k in (ag.get("skills") or [])}
    connected = {s_["id"] for s_ in cm().connected_servers() if s_["status"] == "connected"}
    out = []
    for e in store.audit_for_run(rid):
        if e["kind"] != "connection_request":
            continue
        d = e.get("detail") or {}
        matches = []
        for m in d.get("matches", []):
            sid = m.get("id")
            matches.append({**m, "connected": sid in connected if sid else False,
                            "granted": sid in granted_servers if sid else False, "sid": sid,
                            "url": (url_for("connections", connect=sid, grant_to=agent_id, resume=rid) + "#" + sid) if sid
                                   else url_for("connections", discover=d.get("keywords") or "", grant_to=agent_id, resume=rid)})
        done = any(m["granted"] for m in matches)
        out.append({"ts": e["ts"], "need": d.get("need"), "keywords": d.get("keywords"), "matches": matches, "fulfilled": done})
    return out

def _all_open_requests(owner=None):
    """Unfulfilled connection requests. Admins see every agent's; a user sees their own."""
    seen = {}
    for e in store.audit_all(2000):
        if e["kind"] != "connection_request":
            continue
        ag = store.get_agent(e["agent_id"])
        if not ag:
            continue
        if owner is not None and (ag.get("owner") or "") != owner:
            continue
        reqs = _open_requests(e["run_id"], e["agent_id"])
        for q in reqs:
            if q["fulfilled"] or (e["run_id"], q["need"]) in seen:
                continue
            seen[(e["run_id"], q["need"])] = {**q, "agent": ag, "run_id": e["run_id"]}
    return sorted(seen.values(), key=lambda q: q["ts"], reverse=True)[:20]

def _requests_for_me():
    """Open requests this signed-in person should see: all of them for an admin, their own otherwise."""
    return _all_open_requests(None if is_admin() else _scope())

def _grant_and_resume(sid, agent_id, rid):
    """After a requested server connects: grant its tools to the requesting agent, note it on
    the audit trail, and nudge the conversation forward so the agent continues its task."""
    ag = store.get_agent(agent_id)
    if not ag:
        return
    if AUTH_ON and (ag.get("owner") or "") != current_owner() and not is_admin():
        return
    new_keys = [t["key"] for t in cm().all_tools() if t["server_id"] == sid]
    if not new_keys:
        return
    skills = list(ag.get("skills") or []) + [k for k in new_keys if k not in (ag.get("skills") or [])]
    store.update_agent(agent_id, ag["name"], ag["instructions"], ag["model"], skills)
    name = next((s_["name"] for s_ in cm().connected_servers() if s_["id"] == sid), sid)
    r = store.get_run(rid) if rid else None
    if r and r["agent_id"] == agent_id and r["status"] not in ("running", "awaiting_approval"):
        text = "%s is now connected and its %d tool%s are granted to you. Continue the task." % (name, len(new_keys), "" if len(new_keys) == 1 else "s")
        store.audit(rid, agent_id, "connection_granted", detail={"server": sid, "text": text, "tools": len(new_keys)})
        tr = r["transcript"]; tr.append({"role": "user", "content": text})
        store.update_run(rid, status="running", transcript=tr)
        _advance_bg(rid)

# ---------------- OAuth connect flows ----------------
def _oauth_redirect(kind):
    base = os.environ.get("WARDEN_BASE_URL", "").rstrip("/")
    path = "/connections/oauth/%s/callback" % kind
    return (base + path) if base else url_for("oauth_google_callback" if kind == "google" else "oauth_mcp_callback", _external=True)

def _finish_connection(cid, token_json, grant_to=None, resume=None):
    """Store the OAuth token, connect, and (if this came from a request) grant and resume."""
    entry = cat_by_id(cid)
    url = entry.get("run")
    store.enable_connection(cid, "http", url=url, token=token_json)
    st = cm().connect_spec({"id": cid, "transport": "http", "url": url, "token": token_json})
    if (st or {}).get("status") == "connected" and grant_to:
        _grant_and_resume(cid, grant_to, resume)
        if resume:
            return redirect(url_for("run_view", rid=resume))
    if (st or {}).get("status") != "connected":
        return redirect(url_for("connections", oauth_error="Connected to the provider but the MCP server refused the session: %s" % ((st or {}).get("error") or "unknown")) + "#" + cid)
    return redirect(url_for("connections", connected=cid) + "#" + cid)

@app.route("/connections/oauth/start", methods=["POST"])
def oauth_start():
    cid = request.form.get("id"); entry = cat_by_id(cid)
    if not entry or entry.get("provider") not in ("google", "mcp"):
        abort(404)
    state = secrets.token_urlsafe(20)
    ctx = {"cid": cid, "grant_to": request.form.get("grant_to") or "", "resume": request.form.get("resume") or ""}
    if entry["provider"] == "google":
        if not GOOGLE_ON:
            return redirect(url_for("connections", oauth_error="Google sign-in is not configured on this server (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET)."))
        level = "write" if request.form.get("scope") == "write" else "read"
        scopes = (entry.get("scopes") or {}).get(level) or []
        ctx["scopes"] = scopes
        session["conn_oauth"] = {"state": state, **ctx}
        return redirect(oauth.google_authorize_url(GOOGLE_CLIENT_ID, _oauth_redirect("google"), scopes, state))
    # MCP-standard: discover, register, PKCE
    try:
        meta = oauth.mcp_discover(entry["run"])
        client_id, client_secret = oauth.mcp_register(meta, _oauth_redirect("mcp"))
    except Exception as ex:
        return redirect(url_for("connections", oauth_error="%s: %s" % (entry["name"], str(ex)[:200])) + "#" + cid)
    verifier, challenge = oauth.pkce()
    ctx.update({"meta": {k: meta.get(k) for k in ("authorization_endpoint", "token_endpoint", "scopes_supported")},
                "client_id": client_id, "client_secret": client_secret, "verifier": verifier, "resource": entry["run"]})
    session["conn_oauth"] = {"state": state, **ctx}
    return redirect(oauth.mcp_authorize_url(meta, client_id, _oauth_redirect("mcp"), state, challenge, resource=entry["run"]))

def _oauth_ctx():
    ctx = session.pop("conn_oauth", None)
    if not ctx or not request.args.get("state") or request.args.get("state") != ctx.get("state"):
        return None
    return ctx

@app.route("/connections/oauth/google/callback")
def oauth_google_callback():
    ctx = _oauth_ctx()
    if not ctx:
        return redirect(url_for("connections", oauth_error="The Google sign-in expired or did not match. Try again."))
    if request.args.get("error") or not request.args.get("code"):
        return redirect(url_for("connections", oauth_error="Google did not grant access: %s" % (request.args.get("error") or "cancelled")) + "#" + ctx["cid"])
    try:
        tok = oauth.google_exchange(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, _oauth_redirect("google"), request.args["code"], ctx.get("scopes") or [])
    except Exception as ex:
        return redirect(url_for("connections", oauth_error="Could not exchange the Google code: %s" % str(ex)[:160]) + "#" + ctx["cid"])
    return _finish_connection(ctx["cid"], tok, ctx.get("grant_to"), ctx.get("resume"))

@app.route("/connections/oauth/mcp/callback")
def oauth_mcp_callback():
    ctx = _oauth_ctx()
    if not ctx:
        return redirect(url_for("connections", oauth_error="The sign-in expired or did not match. Try again."))
    if request.args.get("error") or not request.args.get("code"):
        return redirect(url_for("connections", oauth_error="The provider did not grant access: %s" % (request.args.get("error") or "cancelled")) + "#" + ctx["cid"])
    try:
        tok = oauth.mcp_exchange(ctx["meta"], ctx["client_id"], ctx.get("client_secret"), _oauth_redirect("mcp"),
                                 request.args["code"], ctx["verifier"], ctx["meta"].get("scopes_supported") or [], resource=ctx.get("resource"))
    except Exception as ex:
        return redirect(url_for("connections", oauth_error="Could not exchange the authorization code: %s" % str(ex)[:160]) + "#" + ctx["cid"])
    return _finish_connection(ctx["cid"], tok, ctx.get("grant_to"), ctx.get("resume"))

@app.route("/connections/grant", methods=["POST"])
def grant_connection():
    """Grant an already-connected server's tools to the agent that asked for it, and resume."""
    sid = request.form.get("id"); aid = request.form.get("grant_to"); rid = request.form.get("resume")
    ag = store.get_agent(aid)
    if not ag: abort(404)
    if AUTH_ON and (ag.get("owner") or "") != current_owner() and not is_admin(): abort(403)
    _grant_and_resume(sid, aid, rid)
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True, "resume_url": url_for("run_view", rid=rid) if rid else url_for("agent", aid=aid)}
    return redirect(url_for("run_view", rid=rid) if rid else url_for("agent", aid=aid))

# ---------------- evals ----------------
DEFAULT_CATEGORIES = ["wrong facts", "hallucinated detail", "missed a step", "took a risky action",
                      "wrong tone", "too long", "did not finish", "other"]

def _categories():
    seen = list(DEFAULT_CATEGORIES)
    for a in store.list_annotations(_scope(), 500):
        if a["category"] and a["category"] not in seen:
            seen.append(a["category"])
    return seen

def _owned_suite(sid):
    su = store.get_suite(sid)
    if not su: abort(404)
    if AUTH_ON and (su.get("owner") or "") != current_owner(): abort(404)
    return su

def _suite_rows(suites):
    out = []
    for su in suites:
        ag = store.get_agent(su["agent_id"])
        runs = store.list_eval_runs(su["id"], 20)
        last = runs[0] if runs else None
        out.append({**su, "agent": ag, "cases": len(store.list_cases(su["id"])), "checks": len(store.list_checks(su["id"])),
                    "runs": len(runs), "last": last,
                    "score": (last["summary"] or {}).get("score") if last and last["summary"] else None})
    return out

@app.route("/evals")
def evals_home():
    from collections import Counter
    suites = _suite_rows(store.list_suites(_scope()))
    agents = store.list_agents(_scope())
    ann = store.list_annotations(_scope(), 500)
    cats = Counter(a["category"] or "uncategorized" for a in ann if a["verdict"] == "down" or a["category"])
    by_cat = {}
    for a in ann:
        if a["verdict"] == "down" or a["category"]:
            by_cat.setdefault(a["category"] or "uncategorized", []).append(a)
    cat_rows = [{"category": c, "n": n, "examples": by_cat[c][:6]} for c, n in cats.most_common()]
    up = sum(1 for a in ann if a["verdict"] == "up"); down = sum(1 for a in ann if a["verdict"] == "down")
    ap = store.approval_stats_by_agent([a["id"] for a in agents])
    feedback = []
    for a in agents:
        st = ap.get(a["id"], {}); apn = st.get("approved", 0); dn = st.get("denied", 0)
        aup = sum(1 for x in ann if x["agent_id"] == a["id"] and x["verdict"] == "up")
        adn = sum(1 for x in ann if x["agent_id"] == a["id"] and x["verdict"] == "down")
        if apn or dn or aup or adn:
            feedback.append({"agent": a, "approved": apn, "denied": dn, "up": aup, "down": adn,
                             "denial_rate": (dn / (apn + dn)) if (apn + dn) else None})
    return render_template("evals.html", suites=suites, agents=agents, cat_rows=cat_rows, up=up, down=down,
                           feedback=feedback, total_ann=len(ann))

@app.route("/evals/new", methods=["POST"])
def create_suite():
    aid = request.form.get("agent_id"); ag = _owned_agent(aid)
    name = (request.form.get("name") or "").strip() or (ag["name"] + " suite")
    sid = store.create_suite(aid, current_owner(), name)
    if request.form.get("starter"):
        for kind, nm, cfg in evals.starter_checks(ag):
            store.add_check(sid, kind, nm, cfg)
    src = request.form.get("source_run_id")
    if src:
        r = store.get_run(src)
        if r and r["agent_id"] == aid:
            store.add_case(sid, r["input"], source_run_id=src)
    return redirect(url_for("suite", sid=sid))

@app.route("/evals/<sid>")
def suite(sid):
    su = _owned_suite(sid); ag = store.get_agent(su["agent_id"])
    runs = store.list_eval_runs(sid, 50)
    idx = {t["key"]: t for t in connected_tools()}
    tools = sorted({idx[k]["tool"] for k in (ag.get("skills") or []) if k in idx} | ({"delegate"} if ag.get("members") else set()))
    checks = store.list_checks(sid)
    for c in checks:
        c["desc"] = evals.describe(c) if hasattr(evals, "describe") else ""
    recent = [r for r in store.list_runs(30, _scope()) if r["agent_id"] == ag["id"]]
    have = {c["source_run_id"] for c in store.list_cases(sid) if c["source_run_id"]}
    return render_template("eval_suite.html", suite=su, agent=ag, cases=store.list_cases(sid), checks=checks,
                           runs=runs, code_kinds=evals.CODE_KINDS, tools=tools, recent=[r for r in recent if r["id"] not in have],
                           live=(rt.mode() == "live"))

@app.route("/evals/<sid>/delete", methods=["POST"])
def delete_suite(sid):
    _owned_suite(sid); store.delete_suite(sid)
    return redirect(url_for("evals_home"))

@app.route("/evals/<sid>/case", methods=["POST"])
def add_case(sid):
    _owned_suite(sid)
    if request.form.get("source_run_id"):
        r = store.get_run(request.form["source_run_id"])
        if r: store.add_case(sid, r["input"], source_run_id=r["id"])
    else:
        text = (request.form.get("input") or "").strip()
        if text: store.add_case(sid, text, expected=(request.form.get("expected") or "").strip())
    return redirect(url_for("suite", sid=sid) + "#cases")

@app.route("/evals/<sid>/case/<cid>/delete", methods=["POST"])
def delete_case(sid, cid):
    _owned_suite(sid); store.delete_case(cid)
    return redirect(url_for("suite", sid=sid) + "#cases")

@app.route("/evals/<sid>/check", methods=["POST"])
def add_check(sid):
    _owned_suite(sid); f = request.form
    kind = f.get("kind")
    if kind == "code":
        ck = f.get("check")
        if ck not in evals.CODE_BY_KIND: abort(400)
        label = evals.CODE_BY_KIND[ck][1]; val = (f.get("value") or "").strip()
        name = (f.get("name") or "").strip() or (label + (": " + val if val else ""))
        store.add_check(sid, "code", name, {"check": ck, "value": val})
    elif kind == "golden":
        store.add_check(sid, "golden", (f.get("name") or "").strip() or "Matches expected output",
                        {"mode": f.get("mode") if f.get("mode") in ("exact", "contains") else "contains"})
    elif kind == "judge":
        q = (f.get("question") or "").strip()
        if not q: abort(400)
        store.add_check(sid, "judge", (f.get("name") or "").strip() or q[:70],
                        {"question": q, "context": f.get("context") if f.get("context") in ("final", "final+tools") else "final"})
    else:
        abort(400)
    return redirect(url_for("suite", sid=sid) + "#checks")

@app.route("/evals/<sid>/check/<kid>/delete", methods=["POST"])
def delete_check(sid, kid):
    _owned_suite(sid); store.delete_check(kid)
    return redirect(url_for("suite", sid=sid) + "#checks")

@app.route("/evals/<sid>/run", methods=["POST"])
def run_suite(sid):
    su = _owned_suite(sid)
    if not store.list_cases(sid) or not store.list_checks(sid):
        return redirect(url_for("suite", sid=sid))
    label = (request.form.get("label") or "").strip() or ("baseline" if not store.list_eval_runs(sid, 1) else "experiment")
    erid = evals.start(sid, label)
    return redirect(url_for("eval_run_view", erid=erid))

def _eval_matrix(er):
    su = store.get_suite(er["suite_id"])
    cases = store.list_cases(su["id"]); checks = store.list_checks(su["id"])
    results = store.list_results(er["id"])
    cell = {}; run_of = {}
    for r in results:
        cell[(r["case_id"], r["check_id"])] = r; run_of[r["case_id"]] = r["run_id"]
    rows = []
    for c in cases:
        rows.append({"case": c, "run_id": run_of.get(c["id"]), "cells": [cell.get((c["id"], k["id"])) for k in checks],
                     "facts": evals.facts(run_of[c["id"]]) if run_of.get(c["id"]) else None})
    per = (er["summary"] or {}).get("per_check", {})
    cols = []
    for k in checks:
        p = per.get(k["id"], {"pass": 0, "fail": 0, "skip": 0})
        n = p["pass"] + p["fail"]
        cols.append({**k, "pass": p["pass"], "fail": p["fail"], "skip": p["skip"], "rate": (p["pass"] / n) if n else None})
    return su, cases, cols, rows, results

@app.route("/evals/run/<erid>")
def eval_run_view(erid):
    er = store.get_eval_run(erid)
    if not er: abort(404)
    su, cases, cols, rows, results = _eval_matrix(er)
    _owned_suite(su["id"])
    others = [r for r in store.list_eval_runs(su["id"], 50) if r["id"] != erid and r["status"] == "done"]
    cmp_id = request.args.get("compare"); cmp = None
    if cmp_id:
        o = store.get_eval_run(cmp_id)
        if o and o["suite_id"] == su["id"]:
            _, _, ocols, _, _ = _eval_matrix(o)
            orate = {c["id"]: c for c in ocols}
            deltas = []
            for c in cols:
                oc = orate.get(c["id"])
                deltas.append({"check": c, "then": oc["rate"] if oc else None, "now": c["rate"],
                               "delta": ((c["rate"] or 0) - (oc["rate"] or 0)) if (oc and oc["rate"] is not None and c["rate"] is not None) else None})
            a = o["snapshot"].get("instructions", ""); b = er["snapshot"].get("instructions", "")
            lines, add, rem = _diff_lines(a, b) if a != b else ([], 0, 0)
            changed = {k: (o["snapshot"].get(k), er["snapshot"].get(k)) for k in ("model", "tools", "budget_usd", "members")
                       if o["snapshot"].get(k) != er["snapshot"].get(k)}
            cmp = {"run": o, "deltas": deltas, "diff": lines, "added": add, "removed": rem, "changed": changed,
                   "regressions": [d for d in deltas if d["delta"] is not None and d["delta"] < 0]}
    judged = [r for r in results if store.get_check(r["check_id"]) and store.get_check(r["check_id"])["kind"] == "judge"]
    return render_template("eval_run.html", er=er, suite=su, agent=store.get_agent(su["agent_id"]), cols=cols, rows=rows,
                           others=others, cmp=cmp, align=evals.alignment(judged), live=(rt.mode() == "live"))

@app.route("/evals/run/<erid>/status")
def eval_run_status(erid):
    er = store.get_eval_run(erid)
    if not er: abort(404)
    done = len({r["case_id"] for r in store.list_results(erid)})
    return {"status": er["status"], "cases_done": done, "cases": len(store.list_cases(er["suite_id"]))}

@app.route("/evals/result/<rid>/label", methods=["POST"])
def label_result(rid):
    r = store.get_result(rid)
    if not r: abort(404)
    er = store.get_eval_run(r["eval_run_id"]); _owned_suite(er["suite_id"])
    lab = request.form.get("label")
    store.label_result(rid, lab if lab in ("agree", "disagree") else None)
    if request.headers.get("X-Requested-With") == "fetch": return {"ok": True}
    return redirect(url_for("eval_run_view", erid=er["id"]))

@app.route("/run/<rid>/annotate", methods=["POST"])
def annotate_run(rid):
    r = _owned_run(rid)
    v = request.form.get("verdict"); v = v if v in ("up", "down") else ""
    store.annotate(rid, r["agent_id"], current_owner(), v, request.form.get("category", ""), request.form.get("note", ""))
    if request.headers.get("X-Requested-With") == "fetch": return {"ok": True}
    return redirect(url_for("run_view", rid=rid))

@app.route("/annotation/<aid>/delete", methods=["POST"])
def delete_annotation(aid):
    store.delete_annotation(aid)
    return redirect(request.form.get("back") or url_for("evals_home"))

@app.route("/healthz")
def healthz():
    import paths
    dd = store.DATA_ROOT
    return {"ok": True, "mode": rt.mode(),
            "servers": len(cm().connected_servers()),
            "version": VERSION_FULL, "commit": BUILD_COMMIT,
            "auth": {
                "on": AUTH_ON,
                "google": GOOGLE_ON,
                "password": bool(AUTH_PASSWORD),
                "admins_set": bool(ADMIN_EMAILS),
                "allowlist_set": bool(ALLOWED_EMAILS),
                "multi_tenant": AUTH_ON,
            },
            "persistence": {
                "WARDEN_DATA_DIR_env": os.environ.get("WARDEN_DATA_DIR", "(unset)"),
                "requested_dir": paths.REQUESTED,
                "data_dir": dd,
                "using_fallback": paths.FALLBACK,
                "persisting": (not paths.FALLBACK),
                "writable": os.access(dd, os.W_OK),
                "build_json_exists": os.path.exists(os.path.join(dd, "build.json")),
                "agents_saved": len(store.list_agents()),
                "orphaned_agents": sum(1 for a in store.list_agents() if not (a.get("owner") or "")),
            }}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False, threaded=True)
