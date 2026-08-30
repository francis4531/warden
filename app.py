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

WARDEN_VERSION = "0.3"

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
store.init()

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
    return {"pending": store.pending_approvals(), "mode": rt.mode(),
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
def home():
    servers = cm().connected_servers()
    return render_template("dashboard.html", agents=store.list_agents(), runs=store.list_runs(12),
                           pending=store.pending_approvals(), servers=servers,
                           tool_count=len(connected_tools()))

@app.route("/connections")
def connections():
    status = {s["id"]: s for s in cm().connected_servers()}
    return render_template("connections.html", catalog=cat.CATALOG, status=status,
                           enabled={c["id"] for c in store.enabled_connections()},
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL,
                           tools=connected_tools())

@app.route("/connections/enable", methods=["POST"])
def enable_connection():
    cid = request.form.get("id"); entry = cat.BY_ID.get(cid)
    if not entry: abort(404)
    transport = entry["transport"]
    token = request.form.get("token") or None
    command = request.form.get("command") or None
    url = request.form.get("url") or entry.get("run")
    store.enable_connection(cid, transport, command=command, url=url, token=token)
    st = cm().connect_spec({"id": cid, "transport": transport, "command": command, "url": url, "token": token})
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True, "status": (st or {}).get("status"), "error": (st or {}).get("error"),
                "tool_count": (st or {}).get("tool_count", 0)}
    return redirect(url_for("connections"))

@app.route("/connections/disable", methods=["POST"])
def disable_connection():
    cid = request.form.get("id")
    store.disable_connection(cid); cm().disconnect(cid)
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True}
    return redirect(url_for("connections"))

@app.route("/tool-risk", methods=["POST"])
def tool_risk():
    store.set_override(request.form.get("key"), request.form.get("risk"))
    return redirect(request.form.get("back") or url_for("connections"))

@app.route("/connlist")
def connlist():
    status = {s["id"]: s for s in cm().connected_servers()}
    return render_template("_connlist.html", catalog=cat.CATALOG, status=status,
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
    {"id": "research", "name": "Web Research Analyst",
     "instructions": "You research questions using the web and public documentation. Search, fetch, and read sources, then synthesize an answer with citations to the sources you used. If the sources do not support a claim, say so plainly. This agent is read-only by design and never needs to write anything.",
     "servers": ["deepwiki", "firecrawl", "exa", "fetch"], "tools": ["ask_question", "read_wiki_contents", "search", "scrape", "fetch"]},
]

@app.route("/new")
def new_agent():
    status = {s["id"]: s for s in cm().connected_servers()}
    groups = tools_by_server()
    connected_ids = set(groups.keys())
    catalog_meta = {c["id"]: {"name": c["name"], "connected": c["id"] in connected_ids}
                    for c in cat.CATALOG}
    return render_template("builder.html", groups=groups,
                           catalog=cat.CATALOG, status=status, enabled={c["id"] for c in store.enabled_connections()},
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL,
                           templates=AGENT_TEMPLATES, catalog_meta=catalog_meta)

@app.route("/agents", methods=["POST"])
def create_agent():
    name = request.form.get("name", "").strip() or "Untitled agent"
    instructions = request.form.get("instructions", "").strip()
    model = request.form.get("model", "").strip() or rt.MODEL_DEFAULT
    skills = request.form.getlist("skills")
    aid = store.create_agent(name, instructions, model, skills)
    return redirect(url_for("agent", aid=aid))

@app.route("/agent/<aid>")
def agent(aid):
    ag = store.get_agent(aid)
    if not ag: abort(404)
    idx = {t["key"]: t for t in connected_tools()}
    skills = ag["skills"] or []
    granted = [idx[k] for k in skills if k in idx]
    groups = {}
    for t in granted:
        groups.setdefault(t["server_name"], []).append(t)
    counts = {"total": len(granted), "servers": len(groups),
              "gated": sum(1 for t in granted if t["gate"] == "approval"),
              "auto": sum(1 for t in granted if t["gate"] != "approval")}
    missing = [k for k in skills if k not in idx]
    runs = [r for r in store.list_runs(50) if r["agent_id"] == aid]
    return render_template("agent.html", agent=ag, groups=groups, counts=counts,
                           missing=missing, runs=runs)

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
    if not store.get_agent(aid) or not user_input: abort(400)
    rid = store.create_run(aid, user_input)
    _advance_bg(rid)
    return redirect(url_for("run_view", rid=rid))

@app.route("/run/<rid>")
def run_view(rid):
    r = store.get_run(rid)
    if not r: abort(404)
    ag = store.get_agent(r["agent_id"])
    return render_template("run.html", run=r, agent=ag, audit=store.audit_for_run(rid),
                           approvals=store.approvals_for_run(rid))

def _fmt_event(e):
    d = e.get("detail") or {}
    kind = e["kind"]
    if kind in ("run_started", "user_message"):
        text = d.get("input") or d.get("text") or ""
    elif kind in ("final", "thought", "error"):
        text = d.get("text", "")
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
    return {"ts": (e["ts"] or "")[11:19], "kind": kind, "risk": e.get("risk"),
            "tool": (e["skill"] or "").split("__")[-1] if e.get("skill") else "",
            "text": text}

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

@app.route("/run/<rid>/events")
def run_events(rid):
    r = store.get_run(rid)
    if not r: abort(404)
    audit = store.audit_for_run(rid)
    pend = [{"id": a["id"], "tool": (a["skill"] or "").split("__")[-1], "risk": a["risk"],
             "parts": format_args(a["arguments"].get("input")),
             "approve": url_for("approval", apid=a["id"])}
            for a in store.approvals_for_run(rid) if a["status"] == "pending"]
    return {"status": r["status"], "events": [_fmt_event(e) for e in audit],
            "pending": pend, "back": url_for("run_view", rid=rid)}

@app.route("/run/<rid>/say", methods=["POST"])
def run_say(rid):
    r = store.get_run(rid)
    if not r: abort(404)
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
    decision = request.form.get("decision")
    if decision in ("approved", "denied"):
        store.decide_approval(apid, decision, by="operator"); _advance_bg(ap["run_id"])
    # AJAX callers get JSON; form callers get a redirect
    if request.headers.get("X-Requested-With") == "fetch":
        return {"ok": True}
    return redirect(request.form.get("back") or url_for("run_view", rid=ap["run_id"]))

@app.route("/approvals")
def approvals():
    return render_template("approvals.html", pending=store.pending_approvals())

@app.route("/architecture")
def architecture():
    servers = cm().connected_servers()
    return render_template("architecture.html", servers=servers, tools=connected_tools())

@app.route("/audit")
def audit():
    return render_template("audit.html", events=store.audit_all(300), integrity=store.verify_audit())

@app.route("/observability")
def observability():
    from collections import Counter, defaultdict
    events = store.audit_all(4000)
    runs = store.list_runs(500)
    agents = {a["id"]: a["name"] for a in store.list_agents()}

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

@app.route("/healthz")
def healthz():
    import paths
    dd = store.DATA_ROOT
    return {"ok": True, "mode": rt.mode(),
            "servers": len(cm().connected_servers()),
            "version": VERSION_FULL, "commit": BUILD_COMMIT,
            "persistence": {
                "WARDEN_DATA_DIR_env": os.environ.get("WARDEN_DATA_DIR", "(unset)"),
                "requested_dir": paths.REQUESTED,
                "data_dir": dd,
                "using_fallback": paths.FALLBACK,
                "persisting": (not paths.FALLBACK),
                "writable": os.access(dd, os.W_OK),
                "build_json_exists": os.path.exists(os.path.join(dd, "build.json")),
                "agents_saved": len(store.list_agents()),
            }}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False, threaded=True)
