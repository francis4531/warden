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

@app.route("/")
def home():
    servers = cm().connected_servers()
    return render_template("dashboard.html", agents=store.list_agents(), runs=store.list_runs(12),
                           pending=store.pending_approvals(), servers=servers)

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

@app.route("/new")
def new_agent():
    status = {s["id"]: s for s in cm().connected_servers()}
    return render_template("builder.html", groups=tools_by_server(),
                           catalog=cat.CATALOG, status=status, enabled={c["id"] for c in store.enabled_connections()},
                           mlabel=cat.MAINTAINER_LABEL, slabel=cat.STATUS_LABEL)

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
    runs = [r for r in store.list_runs(50) if r["agent_id"] == aid]
    return render_template("agent.html", agent=ag, idx=idx, runs=runs)

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
        text = "-> " + _json.dumps(d["result"])[:300]
    elif "input" in d:
        text = _json.dumps(d["input"])[:300]
    else:
        text = ""
    return {"ts": (e["ts"] or "")[11:19], "kind": kind, "risk": e.get("risk"),
            "tool": (e["skill"] or "").split("__")[-1] if e.get("skill") else "",
            "text": text}

@app.route("/run/<rid>/events")
def run_events(rid):
    r = store.get_run(rid)
    if not r: abort(404)
    audit = store.audit_for_run(rid)
    pend = [{"id": a["id"], "tool": (a["skill"] or "").split("__")[-1], "risk": a["risk"],
             "input": a["arguments"].get("input"),
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
    return render_template("audit.html", events=store.audit_all(300))

@app.route("/healthz")
def healthz():
    return {"ok": True, "mode": rt.mode(), "servers": len(cm().connected_servers())}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False, threaded=True)
