"""
Warden, an enterprise AI agent studio where every agent is governed by default.
Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval with a full audit trail.
"""
import os
import logging
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

WARDEN_VERSION = "0.24"

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
DEPLOYED_AT = datetime.datetime.now(_PT).strftime("%Y-%m-%d %H:%M:%S %Z")   # when this process started

import vault
app = Flask(__name__)
# The session signing key is derived from the studio secret (WARDEN_SECRET_KEY, or a random
# key generated once into the data dir). There is no built-in default: a forgeable cookie
# would make anyone an admin.
app.secret_key = vault.derive("session")
app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SECURE=os.environ.get("WARDEN_INSECURE_COOKIES", "") != "1" and bool(os.environ.get("RENDER") or os.environ.get("WARDEN_HTTPS", "")),
                  PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=14))
store.init()
_orphans = store.fail_orphaned_runs()
if _orphans:
    logging.getLogger("warden").warning("%d run(s) were still 'running' at boot and were marked as interrupted", len(_orphans))
if not vault.from_env():
    logging.getLogger("warden").warning("WARDEN_SECRET_KEY is not set; using a generated key in the data dir. "
                                        "Set it in production so sessions and secrets survive a disk change.")

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

def _google_client():
    """The Google OAuth client used for connectors: an admin-provided one from Settings
    (bring your own client, e.g. an internal Workspace app) wins over the sign-in client."""
    cid = store.get_setting("google_client_id") or GOOGLE_CLIENT_ID
    sec = store.get_setting("google_client_secret") or GOOGLE_CLIENT_SECRET
    return cid, sec

def _google_verified():
    """An admin marks the Google app verified (or Workspace Internal) once Google stops
    showing the unverified-app page; until then the connect card warns people about it."""
    return store.get_setting("google_verified") == "1"

def _google_connectors_on():
    cid, sec = _google_client()
    return bool(cid and sec)
ALLOWED_EMAILS = {e.strip().lower() for e in os.environ.get("WARDEN_ALLOWED_EMAILS", "").split(",") if e.strip()}
ALLOWED_DOMAINS = {d.strip().lower().lstrip("@") for d in os.environ.get("WARDEN_ALLOWED_DOMAINS", "").split(",") if d.strip()}

def _email_allowed(email):
    """Who may sign in with Google: an explicit email list, a domain list, or (if neither is
    set) anyone with a Google account. The last case is flagged on the admin Overview."""
    if not ALLOWED_EMAILS and not ALLOWED_DOMAINS:
        return True
    return email in ALLOWED_EMAILS or email.rsplit("@", 1)[-1] in ALLOWED_DOMAINS

def signin_open():
    return GOOGLE_ON and not ALLOWED_EMAILS and not ALLOWED_DOMAINS
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("WARDEN_ADMIN_EMAILS", "").split(",") if e.strip()}
AUTH_ON = bool(GOOGLE_ON or AUTH_PASSWORD)
rt.ADMIN_INFO = {"auth_on": AUTH_ON, "admins": sorted(ADMIN_EMAILS)}
rt.HIDDEN_CATALOG = lambda: hidden_catalog()
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

def admin_view():
    """Which hat an admin is wearing. Admins switch between the Admin console (the studio) and
    My agents (the same experience every user gets). Permissions never depend on this; only
    what a page shows. Regular users are always in the My agents view."""
    return is_admin() and session.get("hat", "admin") == "admin"

@app.route("/hat/<name>")
def set_hat(name):
    if not is_admin() or name not in ("admin", "agents"):
        abort(404)
    session["hat"] = name
    return redirect(url_for("home"))

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

def _viewable_run(rid):
    """A run the signed-in person may look at: their own, or anyone's for an admin, who
    gets it read-only (no replying, approving, or annotating on someone else's behalf)."""
    r = store.get_run(rid)
    if not r:
        abort(404)
    if not AUTH_ON or (r.get("owner") or "") == current_owner():
        return r, False
    if is_admin():
        return r, True
    abort(404)

def _viewable_agent(aid):
    """Like _viewable_run: the owner's agent, or read-only for an admin."""
    ag = store.get_agent(aid)
    if not ag:
        abort(404)
    if not AUTH_ON or (ag.get("owner") or "") == current_owner():
        return ag, False
    if is_admin():
        return ag, True
    abort(404)

def _authed():
    return (not AUTH_ON) or bool(session.get("auth"))

def _allowed_skills(form):
    """Only tool keys this person can see may be granted: never another person's personal
    connection, never a key that does not exist."""
    ok = {t["key"] for t in connected_tools()}
    return [k for k in form.getlist("skills") if k in ok]

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

def csrf_token():
    """Per-session token, created on first use and rendered into every form and the page
    <meta>; a POST without it (or the X-CSRF / X-Requested-With header) is refused."""
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24); session["csrf"] = tok
    return tok

@app.before_request
def _require_csrf():
    """Cross-site request forgery: a POST must prove it came from a Warden page. OAuth
    callbacks arrive as GET and are covered by their own state check."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if request.headers.get("X-Requested-With") == "fetch":
        return                           # a custom header never crosses origins without CORS, which Warden does not enable
    tok = session.get("csrf") or ""
    sent = request.headers.get("X-CSRF") or request.form.get("csrf") or ""
    if tok and sent and hmac.compare_digest(tok, sent):
        return
    if request.headers.get("X-Requested-With") == "fetch" or request.is_json:
        return {"error": "csrf"}, 403
    abort(403, description="This form was not sent from a Warden page (missing or stale CSRF token). Reload and try again.")

@app.before_request
def _require_auth():
    if not AUTH_ON:
        return
    if (request.endpoint or "") in _PUBLIC_ENDPOINTS:
        return
    if not session.get("auth"):
        return redirect(url_for("login", next=request.path))

def _safe_next(n):
    """Only a path on this site may follow a sign-in; //evil.com and friends are dropped."""
    n = (n or "").strip()
    if not n.startswith("/") or n.startswith("//") or "\\" in n or ":" in n.split("?")[0]:
        return ""
    return n

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
            return redirect(_safe_next(request.form.get("next")) or url_for("home"))
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
    # a connector flow (Connect your Google account) comes back here too; its state lives
    # in session["conn_oauth"], the sign-in state in session["oauth_state"]
    co = session.get("conn_oauth")
    if co and request.args.get("state") and request.args.get("state") == co.get("state"):
        return oauth_google_callback()
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
    if not email or info.get("email_verified") is not True:
        return render_template("login.html", error="Your Google email could not be verified.", **_login_ctx())
    if not _email_allowed(email):
        return render_template("login.html", error="%s is not authorized for this studio." % email, **_login_ctx()), 403
    session["auth"] = True; session["email"] = email; session["name"] = info.get("name") or email
    session.permanent = True
    return redirect(_safe_next(session.pop("oauth_next", "")) or url_for("home"))

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

_ADMIN_ENDPOINTS = {"tool_risk", "studio", "catalog",
                    "discover", "discover_add", "discover_remove", "discover_json",
                    "policies", "policies_draft", "create_policy", "toggle_policy", "delete_policy",
                    "settings", "save_settings"}

@app.before_request
def _require_admin():
    if (request.endpoint or "") in _ADMIN_ENDPOINTS and not is_admin():
        if request.method == "GET":
            return redirect(url_for("home"))
        abort(403)


def cm():
    c = cmod.manager()
    c.ensure_started(store.enabled_connections())      # only what users connected themselves
    return c

@app.context_processor
def inject_globals():
    try:
        open_requests = _requests_for_me() if _authed() else []
    except Exception:
        open_requests = []
    try:
        av = admin_view() if _authed() else False
    except Exception:
        av = False
    return {"pending": [] if av else store.pending_approvals(_scope()), "mode": rt.mode(), "admin_view": av, "csrf_token": csrf_token(),
            "hat": (session.get("hat", "admin") if av or is_admin() else "agents") if _authed() else "agents",
            "open_requests": open_requests, "admin_emails": sorted(ADMIN_EMAILS), "default_model": rt.MODEL_DEFAULT,
            "version": VERSION_FULL, "commit": BUILD_COMMIT, "deployed_at": DEPLOYED_AT}

def _visible(t):
    """A tool or server is visible to the signed-in user if it is their own. The only
    exception is the built-in sample server, which has no owner and is there so a new user
    can try an agent before connecting anything real."""
    own = t.get("owner") or ""
    return (not own) or own == current_owner()

def connected_tools():
    """Tools across connected servers this person may use (shared plus their personal
    connections), with effective governance risk."""
    ovr = store.all_overrides()
    out = []
    for t in cm().all_tools():
        if not _visible(t):
            continue
        mk = _model_key(t)
        m = gov.meta(mk, t["tool"], t["description"], ovr.get(mk), t.get("annotations"))
        out.append({**t, "risk": m["risk"], "gate": m["gate"], "override": ovr.get(mk), "model_key": mk})
    return out

def _migrate_shared_connections():
    """Before v0.15 an admin could connect a system for the whole studio. Those rows become
    the admin's own personal connections (nothing is shared any more), and agents that held
    their tools keep them only if the same user owns the agent."""
    import store as _st
    for c_ in _st.enabled_connections():
        if c_.get("owner") or c_["transport"] == "builtin":
            continue
        cid = c_["catalog_id"]
        owner = c_.get("connected_by") or (sorted(ADMIN_EMAILS)[0] if ADMIN_EMAILS else "operator")
        new_key = _st.conn_key(cid, owner)
        _st.reown_connection(c_["id"], new_key, owner)
        for ag in _st.list_agents(None):
            skills = ag.get("skills") or []
            if not any(k.startswith(c_["id"] + "__") for k in skills):
                continue
            if (ag.get("owner") or "operator") == owner:
                skills = [new_key + k[len(c_["id"]):] if k.startswith(c_["id"] + "__") else k for k in skills]
            else:
                skills = [k for k in skills if not k.startswith(c_["id"] + "__")]
            _st.update_agent(ag["id"], ag["name"], ag["instructions"], ag["model"], skills)
        _st.audit(None, None, "connection_reowned", detail={"server": cid, "owner": owner,
                  "text": "%s was studio-provided; it is now %s's own connection" % (cid, owner)})

def _model_key(t):
    """Risk overrides are per catalog server and tool, not per user's copy of it."""
    return "%s__%s" % (t.get("catalog_id") or t.get("server_id") or "", t.get("tool") or "")

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
    raw = {s["id"]: s for s in servers}
    personal = []
    for e in cat.CATALOG:
        if e.get("personal"):
            k = store.conn_key(e["id"], current_owner())
            personal.append({"entry": e, "connected": k in raw and raw[k]["status"] == "connected"})
    if admin_view():
        _rows, studio_totals = _studio_summary()
        return render_template("overview.html", studio=studio_totals, health=_admin_health(),
                               agents=_agent_rows(None, limit=12), n_agents=studio_totals["agents"],
                               days=store.runs_per_day(14))
    rows = _agent_rows(_scope())
    return render_template("dashboard.html", agents=rows, days=store.runs_per_day(14, _scope()),
                           pending=_with_team_context(store.pending_approvals(_scope())), servers=[s for s in servers if _visible(s)],
                           tool_count=len(connected_tools()), personal=personal, google_on=_google_connectors_on(), google_verified=_google_verified(),
                           spend7=round(sum(r["spend7"] for r in rows), 4), runs7=sum(r["runs7"] for r in rows))

def _agent_rows(owner=None, limit=None):
    """One row per agent with the numbers a dashboard needs: conversations (7 days and all
    time), active now, on hold, approved/denied, spend (7 days and all time), last activity,
    and the five latest conversations for drilling in. owner=None means the whole studio."""
    since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    week_prefix = None
    agents = store.list_agents(owner)
    if not agents:
        return []
    ids = [a["id"] for a in agents]
    rc_all = store.run_counts_by_agent(); rc_7 = store.run_counts_by_agent(since=since)
    spend_all = store.cost_by_agent()
    spend_7 = {}
    for e in store.audit_all(5000):
        if e["kind"] == "model_call" and e["ts"] >= since and isinstance(e.get("detail"), dict):
            spend_7[e["agent_id"]] = spend_7.get(e["agent_id"], 0.0) + (e["detail"].get("cost") or 0)
    pend = {}
    for a in store.pending_approvals(owner):
        pend[a["agent_id"]] = pend.get(a["agent_id"], 0) + 1
    appr = store.approval_stats_by_agent(ids)
    recent = store.recent_runs_by_agent(ids, 5)
    rows = []
    for a in agents:
        r_all = rc_all.get(a["id"], {"runs": 0, "last": None, "active": 0}); r_7 = rc_7.get(a["id"], {"runs": 0})
        st = appr.get(a["id"], {})
        rows.append({**a, "owner": a.get("owner") or "operator", "runs7": r_7["runs"], "runs": r_all["runs"],
                     "active": r_all["active"], "pending": pend.get(a["id"], 0),
                     "approved": st.get("approved", 0), "denied": st.get("denied", 0),
                     "spend7": round(spend_7.get(a["id"], 0.0), 4), "spend": spend_all.get(a["id"], 0.0),
                     "last": r_all["last"], "team": bool(a.get("members")), "recent": recent.get(a["id"], [])})
    rows.sort(key=lambda r: (r["pending"] > 0, r["last"] or ""), reverse=True)
    return rows[:limit] if limit else rows

def _recent_studio_runs(n):
    """Latest conversations across every user, for the admin's overview (read-only links)."""
    out = []
    for r in store.list_runs(n, None):
        ag = store.get_agent(r["agent_id"])
        out.append({**r, "agent_name": ag["name"] if ag else "deleted agent", "owner": r.get("owner") or "operator"})
    return out

def _credential_identity(cid, token):
    """Best effort: who a pasted key acts as, for vendors with a cheap whoami. GitHub only for now."""
    if not token or cid != "github":
        return ""
    try:
        req = urllib.request.Request("https://api.github.com/user", headers={"Authorization": "Bearer " + token.strip(),
                                                                             "Accept": "application/vnd.github+json", "User-Agent": "Warden"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = _json.loads(r.read())
        login = d.get("login") or ""
        return (login + (" (bot)" if d.get("type") == "Bot" else "")) if login else ""
    except Exception:
        return ""

def _my_key(entry):
    """The connection row a catalog entry maps to for the signed-in person."""
    return store.conn_key(entry["id"], current_owner() if entry.get("personal") else None)

@app.route("/connections")
def connections():
    """My connections: every row here belongs to the signed-in user. Admins in the console
    are sent to the Catalog, which is the studio-level view."""
    if admin_view():
        return redirect(url_for("catalog"))
    raw = {s["id"]: s for s in cm().connected_servers()}
    enabled_keys = {c["id"] for c in store.enabled_connections()}
    me = current_owner()
    mine = user_catalog()
    pkey = {e["id"]: (e["id"] if e["transport"] == "builtin" else store.conn_key(e["id"], me)) for e in mine}
    p_status = {e["id"]: raw[pkey[e["id"]]] for e in mine if pkey[e["id"]] in raw}
    p_enabled = {e["id"] for e in mine if pkey[e["id"]] in enabled_keys}
    oauth_status, cred = {}, {}
    for c_ in store.enabled_connections(me):
        cred[c_["id"]] = c_
        d_ = oauth.describe(c_.get("token"))
        if d_: oauth_status[c_["id"]] = d_
    return render_template("connections.html", catalog=mine, status=p_status, enabled=p_enabled, keyed=pkey,
                           pkey=pkey, p_status=p_status, p_enabled=p_enabled, cred=cred,
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL,
                           requests=_requests_for_me(), oauth_status=oauth_status, google_on=_google_connectors_on(), google_verified=_google_verified(),
                           oauth_error=request.args.get("oauth_error", ""), just_connected=request.args.get("connected", ""),
                           grant_to=request.args.get("grant_to", ""), resume=request.args.get("resume", ""),
                           connect_id=request.args.get("connect", ""),
                           grant_agent=store.get_agent(request.args.get("grant_to", "")) if request.args.get("grant_to") else None)

@app.route("/catalog")
def catalog():
    """Admin console: which servers are on offer, how their tools are risk-classified for
    everyone, and the Google client. No connections are made here."""
    if not is_admin():
        abort(404)
    dq = (request.args.get("discover") or "").strip()
    discover = registry.search(dq) if dq else None
    users_connected = {}
    for c_ in store.enabled_connections():
        if c_.get("owner"):
            users_connected[c_["catalog_id"]] = users_connected.get(c_["catalog_id"], 0) + 1
    # governed tools: one row per catalog server and tool, whichever users hold it
    seen, tools = set(), []
    ovr = store.all_overrides()
    for t in cm().all_tools():
        mk = _model_key(t)
        if mk in seen:
            continue
        seen.add(mk)
        m = gov.meta(mk, t["tool"], t["description"], ovr.get(mk), t.get("annotations"))
        entry = cat.BY_ID.get(t.get("catalog_id") or "", {})
        tools.append({**t, "risk": m["risk"], "gate": m["gate"], "override": ovr.get(mk), "model_key": mk,
                      "server_name": entry.get("name") or t["server_name"]})
    return render_template("catalog.html", **_settings_ctx(), catalog=merged_catalog(), users_connected=users_connected, hidden=hidden_catalog(),
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL, tools=tools,
                           discover=discover, discover_q=dq, google_on=_google_connectors_on(), google_verified=_google_verified())

@app.route("/connections/enable", methods=["POST"])
def enable_connection():
    cid = request.form.get("id"); entry = cat_by_id(cid)
    if not entry: abort(404)
    if not is_admin() and cid in hidden_catalog(): abort(403)
    transport = entry["transport"]
    token = request.form.get("token") or None
    # Every connection belongs to the user who makes it, admins included. A server that runs as
    # a process on Warden's host (stdio) is admin-only, since its command line executes here.
    owner = current_owner()
    if transport != "http":
        if not is_admin():
            abort(403)
        command = request.form.get("command") or None
        url = request.form.get("url") or entry.get("run")
    else:
        command = None; url = entry.get("run")
    key = store.enable_connection(cid, transport, command=command, url=url, token=token, owner=owner,
                                  connected_by=owner, credential=("api_key" if token else "none"),
                                  identity=_credential_identity(cid, token))
    st = cm().connect_spec({"id": key, "transport": transport, "command": command, "url": url, "token": token,
                            "owner": owner or "", "catalog_id": cid})
    if (st or {}).get("status") != "connected":
        store.disable_connection(key); cm().disconnect(key)     # no half-connected rows
    grant_to, resume = request.form.get("grant_to"), request.form.get("resume")
    granted = False
    if grant_to and (st or {}).get("status") == "connected":
        _grant_and_resume(key, grant_to, resume); granted = True
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True, "status": (st or {}).get("status"), "error": (st or {}).get("error"),
                "tool_count": (st or {}).get("tool_count", 0), "granted": granted,
                "resume_url": url_for("run_view", rid=resume) if (granted and resume) else None}
    if granted and resume:
        return redirect(url_for("run_view", rid=resume))
    if (st or {}).get("status") != "connected":
        return redirect(url_for("connections", oauth_error="%s did not connect: %s" % (entry["name"].split(" (")[0], (st or {}).get("error") or "unknown")) + "#" + cid)
    return redirect(url_for("connections", connected=cid) + "#" + cid)

@app.route("/connections/disable", methods=["POST"])
def disable_connection():
    cid = request.form.get("id")
    row = store.get_connection(cid)
    if not row:
        abort(404)
    # every connection is personal (v0.15); only its owner can disconnect it, admins included
    if (row.get("owner") or "") != current_owner():
        abort(403)
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

def hidden_catalog():
    """Catalog ids an admin has taken off offer for users. Admins can still connect them."""
    try:
        v = store.get_setting("catalog_hidden")
        return set(_json.loads(v)) if v else set()
    except Exception:
        return set()

def user_catalog():
    """What the signed-in user may connect: the whole catalog for admins, minus anything an
    admin has hidden for everyone else."""
    if is_admin():
        return merged_catalog()
    hidden = hidden_catalog()
    return [e for e in merged_catalog() if e["id"] not in hidden]

@app.route("/catalog/availability", methods=["POST"])
def catalog_availability():
    if not is_admin():
        abort(403)
    cid = request.form.get("id"); on = request.form.get("available") == "1"
    hidden = hidden_catalog()
    (hidden.discard if on else hidden.add)(cid)
    store.set_setting("catalog_hidden", _json.dumps(sorted(hidden)))
    store.audit(None, None, "catalog_availability", detail={"server": cid, "available": on,
                "text": "%s is %s to users" % (cid, "available" if on else "no longer available")})
    return redirect(url_for("catalog") + "#" + cid)

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
    return redirect(url_for("catalog") + "#" + sid)

@app.route("/discover/remove", methods=["POST"])
def discover_remove():
    store.delete_custom_server(request.form.get("id"))
    return redirect(url_for("catalog"))

@app.route("/tool-risk", methods=["POST"])
def tool_risk():
    key = (request.form.get("key") or "").strip(); risk = (request.form.get("risk") or "").upper()
    if "__" not in key or risk not in ("LOW", "MED", "HIGH"):
        abort(400)
    store.set_override(key, risk)
    store.audit(None, None, "risk_override", skill=key, risk=risk,
                detail={"by": current_owner(), "text": "%s set to %s for every user" % (key, risk)})
    return redirect(_safe_next(request.form.get("back")) or url_for("catalog"))

def _my_connlist_ctx():
    """The signed-in user's view of the catalog for the builder's connect panel: their own
    connections by catalog id, status keyed by catalog id, stdio only for admins."""
    me = current_owner()
    status = {}
    for s_ in cm().connected_servers():
        if _visible(s_):
            status[s_.get("catalog_id") or s_["id"]] = s_
    enabled = {c["catalog_id"] for c in store.enabled_connections(me)}
    entries = [e for e in user_catalog() if e["transport"] != "builtin" and (is_admin() or e["transport"] == "http")]
    return dict(catalog=entries, status=status, enabled=enabled, mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL)

@app.route("/connlist")
def connlist():
    return render_template("_connlist.html", **_my_connlist_ctx())

@app.route("/tools.json")
def tools_json():
    groups = {}
    for t in connected_tools():
        g = groups.setdefault(t["server_id"], {"server": t["server_name"], "tools": []})
        g["tools"].append({"key": t["key"], "tool": t["tool"], "risk": t["risk"], "personal": True,
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
    {"id": "inbox", "name": "Inbox Prioritizer (your Gmail)",
     "instructions": "You prioritize the user's Gmail inbox. Read recent threads, group them into needs a reply today, waiting on someone else, FYI, and noise, and write a short digest with the one next action for each item that needs one. Never send or delete mail; drafting is fine only if asked. Quote subject lines exactly.",
     "servers": ["google_gmail"], "tools": []},
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
    catalog_meta = {c["id"]: {"name": c["name"], "personal": bool(c.get("personal")),
                              "connected": store.conn_key(c["id"], current_owner()) in connected_ids or c["id"] in connected_ids}
                    for c in merged_catalog()}
    visible_servers = set(connected_ids)
    def tpl_ok(t):
        return True
    return dict(groups=groups, **_my_connlist_ctx(),
                templates=[t for t in AGENT_TEMPLATES if tpl_ok(t)], catalog_meta=catalog_meta,
                edit_agent=edit_agent,
                edit_skills=set(edit_agent["skills"]) if edit_agent else None,
                candidates=[a for a in store.list_agents(_scope())
                            if not edit_agent or a["id"] != edit_agent["id"]],
                edit_members=set(edit_agent.get("members") or []) if edit_agent else set(),
                delegate_risk=rt.risk_for(rt.DELEGATE_KEY, rt.tool_index())["risk"])

@app.route("/new")
def new_agent():
    """The simple builder: one sentence in, a plain-language card out."""
    return render_template("simple.html")

@app.route("/new/advanced")
def new_agent_advanced():
    return render_template("builder.html", **_builder_ctx())

def _draft_sources():
    """Sources this user could connect but has not, for the draft to pick from."""
    me = current_owner()
    have = {c["catalog_id"] for c in store.enabled_connections(me)}
    out = []
    for e in user_catalog():
        if e["transport"] == "builtin" or e["id"] in have:
            continue
        if e["transport"] != "http" and not is_admin():
            continue
        out.append({"id": e["id"], "name": e["name"], "desc": e.get("desc", ""), "personal": bool(e.get("personal"))})
    return out

@app.route("/draft", methods=["POST"])
def draft():
    sentence = (request.form.get("sentence") or (request.get_json(silent=True) or {}).get("sentence") or "").strip()
    if len(sentence) < 8:
        return {"error": "Say a little more about what it should do."}, 400
    tools = connected_tools()
    sources = _draft_sources()
    try:
        d = rt.draft_agent(sentence, tools, sources, owner=current_owner())
    except Exception as ex:
        return {"error": "Could not draft that right now: " + rt._friendly_error(ex)[:200]}, 502
    by_key = {t["key"]: t for t in tools}
    chosen = [by_key[k] for k in d["tool_keys"] if k in by_key]
    by_id = {s_["id"]: s_ for s_ in sources}
    needs = []
    for sid in d["sources"]:
        e = by_id.get(sid)
        if e:
            needs.append({**e, "url": url_for("connections", connect=sid)})
    return {"name": d["name"], "summary": d["summary"], "instructions": d["instructions"], "sandbox": d.get("sandbox", False),
            "tools": [{"key": t["key"], "tool": t["tool"], "server": t["server_name"], "risk": t["risk"], "gate": t["gate"],
                       "description": t["description"]} for t in chosen],
            "needs": needs}

@app.route("/agents/simple", methods=["POST"])
def create_agent_simple():
    """Create from the card: name, instructions, the tools it listed, and a stance per
    write tool (own | ask | never) which becomes a per-agent policy. Optionally start the
    first conversation right away."""
    f = request.form
    name = (f.get("name") or "").strip() or "Assistant"
    instructions = (f.get("instructions") or "").strip()
    skills = _allowed_skills(f)
    stances = {}
    for k in skills:
        st = f.get("stance__" + k)
        if st in ("own", "ask", "never"):
            stances[k] = st
    aid = store.create_agent(name, instructions, rt.MODEL_DEFAULT, skills, owner=current_owner())
    for k, st in stances.items():
        tool = k.split("__")[-1]
        risk = rt.risk_for(k)["risk"]
        if st == "never":
            store.create_policy("%s: never %s" % (name, tool), "deny", agent_id=aid, tool=k, priority=10)
        elif st == "ask" and risk != "HIGH":
            store.create_policy("%s: ask before %s" % (name, tool), "require_approval", agent_id=aid, tool=k, priority=20)
        # 'own' on a HIGH tool is not offered: the gate is not the user's to relax
    store.audit(None, aid, "agent_created", detail={"by": current_owner(), "how": "simple", "tools": len(skills),
                                                   "stances": {k.split("__")[-1]: v for k, v in stances.items()}})
    first = (f.get("first") or "").strip()
    if first:
        rid = store.create_run(aid, first)
        _advance_bg(rid)
        return redirect(url_for("run_view", rid=rid))
    return redirect(url_for("agent", aid=aid))

@app.route("/agent/<aid>/edit")
def edit_agent(aid):
    ag = _owned_agent(aid)
    return render_template("builder.html", **_builder_ctx(ag))

def _budget(form):
    """'0.50', '$0.50', ' 2 ' and blank are all fine; anything else is treated as no cap."""
    raw = (form.get("budget_usd") or "").strip().lstrip("$").replace(",", "")
    try:
        return max(0.0, float(raw)) if raw else 0
    except ValueError:
        return 0

@app.route("/agent/<aid>/update", methods=["POST"])
def update_agent(aid):
    ag = _owned_agent(aid)
    name = request.form.get("name", "").strip() or ag["name"]
    instructions = request.form.get("instructions", "").strip()
    model = request.form.get("model", "").strip() or ag["model"] or rt.MODEL_DEFAULT
    skills = _allowed_skills(request.form)
    store.update_agent(aid, name, instructions, model, skills, icon=request.form.get("icon", ""),
                       budget_usd=_budget(request.form),
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
    skills = _allowed_skills(request.form)
    members = _member_ids(request.form)
    # a team template can bring its own members: create them for the user when none were picked
    tpl = next((t for t in AGENT_TEMPLATES if t["id"] == request.form.get("template")), None)
    if tpl and tpl.get("members") and not members:
        members = _create_template_members(tpl)
    aid = store.create_agent(name, instructions, model, skills, owner=current_owner(), icon=request.form.get("icon", ""),
                             budget_usd=_budget(request.form), members=members)
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
    ag, readonly = _viewable_agent(aid)
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
                           est_in_rate=est_rate[0], est_base=est_base, live=(rt.mode() == "live"), readonly=readonly)

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
    r, readonly = _viewable_run(rid)
    ag = store.get_agent(r["agent_id"])
    if readonly:
        store.audit(rid, r["agent_id"], "admin_view", detail={"by": current_owner(), "text": "Opened read-only by admin %s" % current_owner()})
    parent = store.get_run(r["parent_run_id"]) if r.get("parent_run_id") else None
    lead = store.get_agent(parent["agent_id"]) if parent else None
    ev = store.get_eval_run(r["eval_run_id"]) if r.get("eval_run_id") else None
    return render_template("run.html", run=r, agent=ag, audit=store.audit_for_run(rid),
                           approvals=store.approvals_for_run(rid), parent=parent, lead=lead,
                           is_team=bool(ag and ag.get("members")),
                           annotations=store.annotations_for_run(rid),
                           suites=store.list_suites(_scope(), agent_id=r["agent_id"]),
                           eval_run=ev, categories=_categories(), readonly=readonly)

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
        if isinstance(res, dict) and res.get("error"):
            text = "error: " + " ".join(str(res.get("message") or res.get("error")).split())[:600]
        else:
            s = res if isinstance(res, str) else _json.dumps(res, ensure_ascii=False)
            s = " ".join(s.split())               # collapse newlines/whitespace
            text = "-> " + s[:200]
    elif "input" in d:
        s = _json.dumps(d["input"], ensure_ascii=False)
        text = " ".join(s.split())[:200]
    else:
        text = ""
    out = {"ts": (e["ts"] or "")[11:19], "kind": kind, "risk": e.get("risk"), "outcome": d.get("outcome") if isinstance(d, dict) else None,
           "tool": (e["skill"] or "").split("__")[-1] if e.get("skill") else "",
           "text": text}
    if kind == "approval_decided":
        out["decision"] = d.get("decision"); out["by"] = d.get("by")
    if kind == "connection_declined":
        out["text"] = d.get("text") or "connection request declined"; out["need"] = d.get("need")
    if kind in ("delegation", "delegation_result"):
        out["child_run"] = d.get("child_run"); out["member"] = d.get("member")
    if kind == "connection_request":
        out["text"] = d.get("need") or ""
    if kind in ("connection_granted", "admin_view"):
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
    r, _ro = _viewable_run(rid)
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
            "waiting_on": waiting_on, "team": len(delegations) > 0, "requests": requests_, "admin": is_admin(), "readonly": _ro,
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
    if decision not in ("approved", "denied"):
        abort(400)
    if ap["status"] != "pending" or store.decide_approval(apid, decision, by=current_owner()) is None:
        if request.headers.get("X-Requested-With") == "fetch":
            return {"ok": False, "error": "already_decided", "status": ap["status"]}, 409
        return redirect(_safe_next(request.form.get("back")) or url_for("run_view", rid=ap["run_id"]))   # already decided; nothing changes
    _advance_bg(ap["run_id"])
    # AJAX callers get JSON; form callers get a redirect
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True}
    return redirect(_safe_next(request.form.get("back")) or url_for("run_view", rid=ap["run_id"]))

def _with_team_context(pending):
    """Label approvals raised inside a member run with the lead that delegated the work,
    and point 'Open run' at the lead's conversation where the gate is shown in context."""
    out = []
    for ap in pending:
        ap = dict(ap)
        r = store.get_run(ap["run_id"])
        ag = store.get_agent(ap["agent_id"])
        ap["agent_name"] = ag["name"] if ag else ""
        ap["agent_icon"] = (ag or {}).get("icon") or ""
        ap["run_input"] = (r or {}).get("input") or ""
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
    if admin_view():
        # the console: what only the admin can do, plus what is waiting on users (read-only)
        return render_template("approvals.html", pending=[], requests=_requests_for_me(), waiting=_requests_waiting_on_people(),
                               others=_with_team_context(store.pending_approvals(None)))
    return render_template("approvals.html", pending=_with_team_context(store.pending_approvals(_scope())),
                           requests=_requests_for_me(), waiting=[], others=[])

@app.route("/architecture")
def architecture():
    servers = [s_ for s_ in cm().connected_servers() if _visible(s_)]
    return render_template("architecture.html", servers=servers, tools=connected_tools())

@app.route("/audit")
def audit():
    # admins see the whole studio's trail (their oversight view is read-only everywhere else too)
    events = store.audit_all(300) if (not _scope() or admin_view()) else store.audit_for_owner(_scope(), 300)
    return render_template("audit.html", events=events, integrity=store.verify_audit())

def _policy_tool_names():
    """Bare tool names an admin can write rules about: everything connected across the
    studio plus the sample server, deduplicated."""
    names = set()
    for t in cm().all_tools():
        names.add(t["tool"])
    return sorted(names)

@app.route("/policies")
def policies():
    agents = store.list_agents()
    pols = store.list_policies()
    for p in pols:
        p["sentence"] = rt.describe_rule(p, agents)
    return render_template("policies.html", policies=pols, agents=agents, ops=policy.OPS, tool_names=_policy_tool_names())

@app.route("/policies/draft", methods=["POST"])
def policies_draft():
    sentence = (request.form.get("sentence") or "").strip()
    if len(sentence) < 6:
        return {"error": "Say what the rule should do, in a sentence."}, 400
    try:
        d = rt.draft_policy(sentence, _policy_tool_names(), store.list_agents())
    except Exception as ex:
        return {"error": "Could not draft that: " + str(ex)[:160]}, 502
    d["agent_name"] = next((a["name"] for a in store.list_agents() if a["id"] == d["agent_id"]), "any agent")
    return d

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
    sc = None if admin_view() else _scope()
    events = store.audit_for_owner(sc, 4000) if sc else store.audit_all(4000)
    runs = store.list_runs(500, sc)
    agents = {a["id"]: a["name"] for a in store.list_agents(sc)}

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
    r, _ro = _viewable_run(rid)
    spans, meta = telemetry.build_spans(rid)
    return render_template("trace.html", run=r, agent=store.get_agent(r["agent_id"]),
                           spans=spans, meta=meta,
                           otlp_configured=bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")))

@app.route("/run/<rid>/trace.json")
def run_trace_json(rid):
    import telemetry
    _viewable_run(rid)
    return app.response_class(_json.dumps(telemetry.to_otlp(rid), indent=2),
                              mimetype="application/json")

@app.route("/run/<rid>/export", methods=["POST"])
def run_export(rid):
    import telemetry
    _viewable_run(rid)
    return telemetry.export(rid)

# ---------------- capability requests ----------------
def _open_requests(rid, agent_id):
    """Connection requests raised in a run, with whether each match is now connected and
    granted to the agent, so the conversation can show what is still outstanding."""
    ag = store.get_agent(agent_id) or {"skills": []}
    granted_servers = {k.split("__")[0] for k in (ag.get("skills") or [])}
    connected = {s_["id"] for s_ in cm().connected_servers() if s_["status"] == "connected"}
    out = []
    declined = {}
    for e in store.audit_for_run(rid):
        if e["kind"] == "connection_declined":
            dd = e.get("detail") or {}
            declined[dd.get("need")] = {"by": dd.get("by"), "ts": e["ts"]}
    for e in store.audit_for_run(rid):
        if e["kind"] != "connection_request":
            continue
        d = e.get("detail") or {}
        matches = []
        owner_is_admin = (ag.get("owner") or "") in ADMIN_EMAILS
        for m in d.get("matches", []):
            sid = m.get("id")
            entry = cat_by_id(sid) if sid else None
            if entry and entry.get("transport") != "http" and not owner_is_admin:
                continue   # stdio servers run on the host; only admins may connect them
            personal = bool(entry and entry.get("personal"))
            key = store.conn_key(sid, ag.get("owner") or "") if sid else None   # the requester's own copy
            matches.append({**m, "connected": key in connected if key else False,
                            "granted": key in granted_servers if key else False, "sid": key, "personal": personal,
                            "url": url_for("connections", connect=sid, grant_to=agent_id, resume=rid) if sid
                                   else url_for("connections", discover=d.get("keywords") or "", grant_to=agent_id, resume=rid)})
        done = any(m["granted"] for m in matches)
        dec = declined.get(d.get("need"))
        dec = dec if (dec and dec["ts"] >= e["ts"]) else None
        out.append({"ts": e["ts"], "need": d.get("need"), "keywords": d.get("keywords"), "matches": matches,
                    "fulfilled": done or bool(dec), "declined": dec, "run_id": rid, "agent_id": agent_id})
    return out

@app.route("/requests/decline", methods=["POST"])
def decline_request():
    """Turn a connection request down. The agent's owner may (it is their account that
    would be connected), and an admin may (a source can be off limits), which is the one
    thing an admin does to a user's conversation beyond reading it: it only ever narrows
    what the agent may do. The agent is told and carries on with what it has."""
    rid = request.form.get("run_id") or ""; need = (request.form.get("need") or "").strip()
    r = store.get_run(rid)
    if not r or not need:
        abort(404)
    ag = store.get_agent(r["agent_id"]) or {}
    if AUTH_ON and (ag.get("owner") or "") != current_owner() and not is_admin():
        abort(404)
    open_needs = {q["need"] for q in _open_requests(rid, r["agent_id"]) if not q["fulfilled"]}
    if need not in open_needs:
        if request.headers.get("X-Requested-With") == "fetch":
            return {"ok": False, "error": "not_open"}, 409
        return redirect(_safe_next(request.form.get("back")) or url_for("run_view", rid=rid))
    who = current_owner(); role = "admin" if (is_admin() and (ag.get("owner") or "") != who) else "owner"
    reason = (request.form.get("reason") or "").strip()[:300]
    store.audit(rid, r["agent_id"], "connection_declined", skill=rt.REQUEST_KEY,
                detail={"need": need, "by": who, "role": role, "reason": reason,
                        "text": "Connection request declined by %s%s" % (who, (": " + reason) if reason else "")})
    if r["status"] not in ("running", "awaiting_approval"):
        text = ("[Warden: the request to connect a source for \"%s\" was declined by %s%s. Do not ask for it again. "
                "Do what you can with the tools you already have, say plainly what you could not do and why, "
                "and finish.]" % (need, "the studio admin" if role == "admin" else "the user", (": " + reason) if reason else ""))
        tr = r["transcript"]; tr.append({"role": "user", "content": text})
        store.update_run(rid, status="running", transcript=tr)
        _advance_bg(rid)
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True}
    return redirect(_safe_next(request.form.get("back")) or url_for("run_view", rid=rid))

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

def _actionable(q):
    """Whether the signed-in user is the one who can satisfy a connection request: only
    the agent's owner ever connects anything."""
    return (q["agent"].get("owner") or "") == current_owner()   # only the owner connects anything

def _requests_for_me():
    """Open requests this signed-in user can act on: their own agents' requests. The admin
    console lists everyone's for awareness but acts on none."""
    if admin_view():
        return []                      # the console connects nothing; requests belong to their owners
    return [q for q in _all_open_requests(_scope()) if _actionable(q)]

def _requests_waiting_on_people():
    """Admin-only: open requests that someone else has to satisfy (their own Gmail, for
    example). Shown for awareness, never counted as the admin's to-do."""
    if not admin_view():
        return []
    return _all_open_requests(None)

def _grant_and_resume(sid, agent_id, rid):
    """After a requested server connects: grant its tools to the requesting agent, note it on
    the audit trail, and nudge the conversation forward so the agent continues its task."""
    ag = store.get_agent(agent_id)
    if not ag:
        return
    if AUTH_ON and (ag.get("owner") or "") != current_owner():
        return                           # only the agent's owner grants and resumes; admins are read-only
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

# ---------------- studio (admin, read-only view of everyone) ----------------
@app.route("/studio")
def studio():
    if not is_admin():
        abort(404)
    rows, totals = _studio_summary()
    by_owner = {}
    for a in _agent_rows(None):
        by_owner.setdefault(a["owner"], []).append(a)
    return render_template("studio.html", users=rows, totals=totals, by_owner=by_owner)

def _admin_health():
    """The admin's checklist: what is set up, what is broken, what needs them."""
    integ = store.verify_audit()
    errored = [s_ for s_ in cm().connected_servers() if s_.get("status") == "error"]
    h = {"errored": errored, "catalog": len(merged_catalog()),
         "google_on": _google_connectors_on(), "google_verified": _google_verified(),
         "policies": len(store.list_policies()),
         "audit_ok": bool(integ.get("ok")), "audit": integ,
         "signin_open": signin_open(), "secret_set": vault.from_env(),
         "allowed": ", ".join(sorted(ALLOWED_DOMAINS and {"@" + d for d in ALLOWED_DOMAINS} or set()) + sorted(ALLOWED_EMAILS)) or "the password",
         "actionable": [], "waiting": _requests_waiting_on_people()}
    # the same facts as a checklist: state ok | todo | bad, one line, one link
    checks = []
    if errored:
        checks.append({"state": "bad", "title": "Connections in error", "text": "%s. Their owners see it on their Connections page." % ", ".join(s_["name"] for s_ in errored), "href": url_for("catalog"), "cta": "Catalog"})
    else:
        checks.append({"state": "ok", "title": "Catalog", "text": "%d servers on offer" % h["catalog"], "href": url_for("catalog"), "cta": "Catalog"})
    if not h["google_on"]:
        checks.append({"state": "bad", "title": "Google client not configured", "text": "No user can connect Gmail, Drive or Calendar until it is.", "href": url_for("catalog") + "#google", "cta": "Set it up"})
    elif not h["google_verified"]:
        checks.append({"state": "todo", "title": "Google app unverified", "text": "Users see Google's warning page the first time they connect. Go Internal or verify, then mark it.", "href": url_for("catalog") + "#google", "cta": "Google client"})
    else:
        checks.append({"state": "ok", "title": "Google", "text": "configured and verified", "href": url_for("catalog") + "#google", "cta": "Google client"})
    if h["signin_open"]:
        checks.append({"state": "bad", "title": "Sign-in is open to any Google account", "text": "Set WARDEN_ALLOWED_DOMAINS or WARDEN_ALLOWED_EMAILS in Render.", "href": url_for("studio"), "cta": "Users"})
    elif not h["secret_set"]:
        checks.append({"state": "bad", "title": "WARDEN_SECRET_KEY is not set", "text": "Sessions and stored secrets depend on a generated key in the data dir.", "href": url_for("studio"), "cta": "Users"})
    else:
        checks.append({"state": "ok", "title": "Sign-in", "text": "restricted to " + h["allowed"], "href": url_for("studio"), "cta": "Users"})
    if not h["audit_ok"]:
        checks.append({"state": "bad", "title": "Audit chain broken", "text": "at %s. Investigate before trusting the log." % (integ.get("broken_at") or "unknown"), "href": url_for("audit"), "cta": "Audit log"})
    else:
        checks.append({"state": "ok", "title": "Audit chain", "text": "%d events verified" % (integ.get("total") or 0), "href": url_for("audit"), "cta": "Audit log"})
    if not h["policies"]:
        checks.append({"state": "todo", "title": "No policies yet", "text": "Only the risk tiers apply. Add spend caps, rate limits, time windows or per-agent rules.", "href": url_for("policies"), "cta": "Add a policy"})
    else:
        checks.append({"state": "ok", "title": "Policies", "text": "%d in force" % h["policies"], "href": url_for("policies"), "cta": "Policies"})
    if h["waiting"]:
        checks.append({"state": "ok", "title": "Connection requests", "text": "%d waiting on their owners, nothing for you to do" % len(h["waiting"]), "href": url_for("approvals"), "cta": "Approvals"})
    h["checks"] = checks
    h["attention"] = [c for c in checks if c["state"] != "ok"]
    h["fine"] = [c for c in checks if c["state"] == "ok"]
    return h

def _studio_summary():
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    spend_all = store.cost_by_agent(); spend_today = store.cost_by_agent(today)
    rc = store.run_counts_by_agent()
    pend = store.pending_approvals(None)
    pend_by_agent = {}
    for a in pend:
        pend_by_agent[a["agent_id"]] = pend_by_agent.get(a["agent_id"], 0) + 1
    reqs = _all_open_requests(None)
    req_by_owner = {}
    for q in reqs:
        req_by_owner.setdefault(q["agent"].get("owner") or "", []).append(q)
    conns = store.enabled_connections()
    personal_by_owner = {}
    for c_ in conns:
        if c_.get("owner"):
            personal_by_owner[c_["owner"]] = personal_by_owner.get(c_["owner"], 0) + 1
    people = {}
    for ag in store.list_agents(None):
        own = ag.get("owner") or "operator"
        p = people.setdefault(own, {"email": own, "agents": [], "runs": 0, "active": 0, "spend": 0.0, "today": 0.0,
                                    "pending": 0, "last": None, "requests": req_by_owner.get(own, []),
                                    "personal": personal_by_owner.get(own, 0), "admin": own.lower() in ADMIN_EMAILS})
        r_ = rc.get(ag["id"], {"runs": 0, "last": None, "active": 0})
        row = {**ag, "runs": r_["runs"], "active": r_["active"], "last": r_["last"],
               "spend": spend_all.get(ag["id"], 0.0), "pending": pend_by_agent.get(ag["id"], 0),
               "team": bool(ag.get("members"))}
        p["agents"].append(row)
        p["runs"] += row["runs"]; p["active"] += row["active"]; p["spend"] += row["spend"]
        p["today"] += spend_today.get(ag["id"], 0.0); p["pending"] += row["pending"]
        if row["last"] and (not p["last"] or row["last"] > p["last"]):
            p["last"] = row["last"]
    for own in list(req_by_owner) + list(personal_by_owner):
        if own not in people:
            people[own] = {"email": own, "agents": [], "runs": 0, "active": 0, "spend": 0.0, "today": 0.0, "pending": 0,
                           "last": None, "requests": req_by_owner.get(own, []), "personal": personal_by_owner.get(own, 0),
                           "admin": own.lower() in ADMIN_EMAILS}
    rows = sorted(people.values(), key=lambda p: (p["last"] or ""), reverse=True)
    for p in rows:
        p["agents"].sort(key=lambda a: (a["last"] or ""), reverse=True)
    totals = {"people": len(rows), "users": len(rows), "agents": sum(len(p["agents"]) for p in rows), "runs": sum(p["runs"] for p in rows),
              "active": sum(p["active"] for p in rows), "spend": sum(p["spend"] for p in rows),
              "today": sum(p["today"] for p in rows), "pending": len(pend), "requests": len(reqs),
              "daily_cap": float(os.environ.get("WARDEN_DAILY_BUDGET", "0") or 0)}
    return rows, totals

# ---------------- settings (admin) ----------------
def _settings_ctx():
    """The Google client, shown on the Catalog page."""
    gcid, gsec = _google_client()
    return dict(google_configured=bool(gcid and gsec), byo=bool(store.get_setting("google_client_id")),
                client_id_hint=(gcid[:14] + "…" + gcid[-18:]) if gcid and len(gcid) > 34 else (gcid or ""),
                redirect_uri=_oauth_redirect("google"), signin_redirect=_redirect_uri(),
                base_url=os.environ.get("WARDEN_BASE_URL", ""), signin_on=GOOGLE_ON,
                gpersonal=[e for e in cat.CATALOG if e.get("personal")],
                saved=request.args.get("saved", ""))

@app.route("/settings")
def settings():
    return redirect(url_for("catalog") + "#google")

@app.route("/settings", methods=["POST"])
def save_settings():
    f = request.form
    if f.get("section") == "verified":
        store.set_setting("google_verified", "1" if f.get("google_verified") == "1" else None)
        return redirect(url_for("catalog", saved="verified") + "#google")
    if f.get("clear"):
        store.set_setting("google_client_id", None); store.set_setting("google_client_secret", None)
    else:
        cid = (f.get("google_client_id") or "").strip(); sec = (f.get("google_client_secret") or "").strip()
        if cid: store.set_setting("google_client_id", cid)
        if sec: store.set_setting("google_client_secret", sec)
    return redirect(url_for("catalog", saved="1") + "#google")

# ---------------- OAuth connect flows ----------------
def _oauth_redirect(kind):
    """Google connector flows reuse the sign-in callback, which is already registered on
    the Google client, so connecting Gmail never needs a new redirect URI in Google Cloud.
    MCP-standard servers register Warden's redirect dynamically, so they get their own."""
    if kind == "google":
        return _redirect_uri()
    base = os.environ.get("WARDEN_BASE_URL", "").rstrip("/")
    return (base + "/connections/oauth/mcp/callback") if base else url_for("oauth_mcp_callback", _external=True)

def _finish_connection(cid, token_json, grant_to=None, resume=None, personal=False):
    """Store the OAuth token, connect, and (if this came from a request) grant and resume.
    Personal connectors are stored under the signed-in person."""
    entry = cat_by_id(cid)
    url = entry.get("run")
    # a personal-type source is always the person's own; a company system is the studio's when
    # the admin signs in, and the person's own when anyone else does
    owner = current_owner()          # every connection is the connecting user's own
    missing = oauth.missing_scopes(token_json)
    if missing:
        short = entry["name"].split(" (")[0]
        return redirect(url_for("connections", oauth_error="Google signed you in but did not grant %s access (%s was left unticked on the consent page). Connect again and tick the %s box."
                                % (short, ", ".join(m.split("/")[-1] for m in missing), short)) + "#" + cid)
    key = store.enable_connection(cid, "http", url=url, token=token_json, owner=owner,
                                  connected_by=owner, credential="signin", identity="")
    st = cm().connect_spec({"id": key, "transport": "http", "url": url, "token": token_json,
                            "owner": owner or "", "catalog_id": cid})
    if (st or {}).get("status") == "connected" and grant_to:
        _grant_and_resume(key, grant_to, resume)
        if resume:
            return redirect(url_for("run_view", rid=resume))
    if (st or {}).get("status") != "connected":
        # do not leave a half-connected personal source behind; the person can retry cleanly
        store.disable_connection(key); cm().disconnect(key)
        return redirect(url_for("connections", oauth_error="Signed in, but %s's MCP server refused the session: %s" % (entry["name"].split(" (")[0], (st or {}).get("error") or "unknown")) + "#" + cid)
    return redirect(url_for("connections", connected=cid) + "#" + cid)

@app.route("/connections/oauth/start", methods=["POST"])
def oauth_start():
    cid = request.form.get("id"); entry = cat_by_id(cid)
    if not entry or entry.get("provider") not in ("google", "mcp"):
        abort(404)
    if not is_admin() and cid in hidden_catalog():
        abort(403)
    state = secrets.token_urlsafe(20)
    ctx = {"cid": cid, "grant_to": request.form.get("grant_to") or "", "resume": request.form.get("resume") or "",
           "personal": bool(request.form.get("personal"))}
    if entry["provider"] == "google":
        gcid, gsec = _google_client()
        if not (gcid and gsec):
            return redirect(url_for("connections", oauth_error="Google connectors are not set up yet. An admin configures the Google client under Settings.") + "#" + cid)
        level = "write" if request.form.get("scope") == "write" else "read"
        scopes = (entry.get("scopes") or {}).get(level) or []
        ctx["scopes"] = scopes
        session["conn_oauth"] = {"state": state, **ctx}
        return redirect(oauth.google_authorize_url(gcid, _oauth_redirect("google"), scopes, state))
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
        gcid, gsec = _google_client()
        tok = oauth.google_exchange(gcid, gsec, _oauth_redirect("google"), request.args["code"], ctx.get("scopes") or [])
    except Exception as ex:
        return redirect(url_for("connections", oauth_error="Could not exchange the Google code: %s" % str(ex)[:160]) + "#" + ctx["cid"])
    return _finish_connection(ctx["cid"], tok, ctx.get("grant_to"), ctx.get("resume"), personal=ctx.get("personal"))

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
    return _finish_connection(ctx["cid"], tok, ctx.get("grant_to"), ctx.get("resume"), personal=ctx.get("personal"))

@app.route("/connections/grant", methods=["POST"])
def grant_connection():
    """Grant an already-connected server's tools to the agent that asked for it, and resume."""
    sid = request.form.get("id"); aid = request.form.get("grant_to"); rid = request.form.get("resume")
    ag = store.get_agent(aid)
    if not ag: abort(404)
    if AUTH_ON and (ag.get("owner") or "") != current_owner(): abort(403)
    row = store.get_connection(sid)
    if row and (row.get("owner") or "") and row.get("owner") != (ag.get("owner") or ""):
        abort(403)                       # a personal connection is only ever granted to its owner's agents
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
        r = _owned_run(request.form["source_run_id"])        # only your own conversations become cases
        store.add_case(sid, r["input"], source_run_id=r["id"])
    else:
        text = (request.form.get("input") or "").strip()
        if text: store.add_case(sid, text, expected=(request.form.get("expected") or "").strip())
    return redirect(url_for("suite", sid=sid) + "#cases")

@app.route("/evals/<sid>/case/<cid>/delete", methods=["POST"])
def delete_case(sid, cid):
    _owned_suite(sid)
    if not store.delete_case(cid, suite_id=sid): abort(404)
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
    _owned_suite(sid)
    if not store.delete_check(kid, suite_id=sid): abort(404)
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
    _owned_suite(er["suite_id"])
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
    if not store.delete_annotation(aid, owner=current_owner() if AUTH_ON else None): abort(404)
    return redirect(_safe_next(request.form.get("back")) or url_for("evals_home"))

@app.route("/healthz")
def healthz():
    """Public liveness check: enough for a load balancer, nothing about the deployment.
    Admins get the full picture (persistence, auth configuration) once signed in."""
    import paths
    out = {"ok": True, "version": VERSION_FULL, "commit": BUILD_COMMIT}
    if _authed() and is_admin():
        dd = store.DATA_ROOT
        out.update({"mode": rt.mode(), "servers": len(cm().connected_servers()),
                    "auth": {"on": AUTH_ON, "google": GOOGLE_ON, "password": bool(AUTH_PASSWORD),
                             "admins_set": bool(ADMIN_EMAILS), "allowlist_set": bool(ALLOWED_EMAILS or ALLOWED_DOMAINS),
                             "allowed_domains": sorted(ALLOWED_DOMAINS), "allowed_emails": sorted(ALLOWED_EMAILS),
                             "env_has_allowed_domains": "WARDEN_ALLOWED_DOMAINS" in os.environ,
                             "env_has_allowed_emails": "WARDEN_ALLOWED_EMAILS" in os.environ,
                             "secret_from_env": vault.from_env()},
                    "persistence": {"WARDEN_DATA_DIR_env": os.environ.get("WARDEN_DATA_DIR", "(unset)"),
                                    "requested_dir": paths.REQUESTED, "data_dir": dd, "using_fallback": paths.FALLBACK,
                                    "persisting": (not paths.FALLBACK), "writable": os.access(dd, os.W_OK),
                                    "agents_saved": len(store.list_agents())}})
    return out

try:
    _migrate_shared_connections()
except Exception as _mx:
    print("shared-connection migration skipped:", _mx)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False, threaded=True)
