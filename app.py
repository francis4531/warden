"""
Warden, an enterprise AI agent studio where every agent is governed by default.
Connect MCP servers, build an agent from their tools, run it against a live model, and
gate high-risk actions behind human approval with a full audit trail.
"""
import os
from flask import Flask, request, redirect, url_for, render_template, abort
import store, governance as gov, agent_runtime as rt
import connection_manager as cmod
import catalog as cat

app = Flask(__name__)
store.init()

def cm():
    c = cmod.manager(); c.ensure_started(store.enabled_connections()); return c

@app.context_processor
def inject_globals():
    return {"pending": store.pending_approvals(), "mode": rt.mode()}

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
    cm().connect_spec({"id": cid, "transport": transport, "command": command, "url": url, "token": token})
    return redirect(url_for("connections"))

@app.route("/connections/disable", methods=["POST"])
def disable_connection():
    cid = request.form.get("id")
    store.disable_connection(cid); cm().disconnect(cid)
    return redirect(url_for("connections"))

@app.route("/tool-risk", methods=["POST"])
def tool_risk():
    store.set_override(request.form.get("key"), request.form.get("risk"))
    return redirect(request.form.get("back") or url_for("connections"))

@app.route("/new")
def new_agent():
    return render_template("builder.html", groups=tools_by_server())

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

@app.route("/run", methods=["POST"])
def run():
    aid = request.form.get("agent_id"); user_input = request.form.get("input", "").strip()
    if not store.get_agent(aid) or not user_input: abort(400)
    rid = store.create_run(aid, user_input); rt.advance(rid)
    return redirect(url_for("run_view", rid=rid))

@app.route("/run/<rid>")
def run_view(rid):
    r = store.get_run(rid)
    if not r: abort(404)
    ag = store.get_agent(r["agent_id"])
    return render_template("run.html", run=r, agent=ag, audit=store.audit_for_run(rid),
                           approvals=store.approvals_for_run(rid))

@app.route("/approval/<apid>", methods=["POST"])
def approval(apid):
    ap = store.get_approval(apid)
    if not ap: abort(404)
    decision = request.form.get("decision")
    if decision in ("approved", "denied"):
        store.decide_approval(apid, decision, by="operator"); rt.advance(ap["run_id"])
    return redirect(request.form.get("back") or url_for("run_view", rid=ap["run_id"]))

@app.route("/approvals")
def approvals():
    return render_template("approvals.html", pending=store.pending_approvals())

@app.route("/audit")
def audit():
    return render_template("audit.html", events=store.audit_all(300))

@app.route("/healthz")
def healthz():
    return {"ok": True, "mode": rt.mode(), "servers": len(cm().connected_servers())}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False, threaded=True)
