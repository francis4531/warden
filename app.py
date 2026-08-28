"""
Warden, an enterprise AI agent studio where every agent is governed by default.
Flask app: build an agent, run it against a live model over MCP tools, and gate
high-risk actions behind human approval with a full audit trail.
"""
import os
from flask import Flask, request, redirect, url_for, render_template, abort
import store, governance as gov, agent_runtime as rt, mcp_client

app = Flask(__name__)
store.init()

@app.context_processor
def inject_globals():
    return {"pending": store.pending_approvals(), "mode": rt.mode()}

def _catalog():
    """All skills the MCP server exposes, annotated with governance risk, for the builder."""
    out = []
    for t in mcp_client.list_tools():
        m = gov.skill_meta(t["name"])
        out.append({"name": t["name"], "description": t["description"],
                    "risk": m["risk"], "gate": m["gate"], "label": m["label"], "kind": m["kind"]})
    return out

@app.route("/")
def home():
    return render_template("dashboard.html", mode=rt.mode(), agents=store.list_agents(),
                           runs=store.list_runs(12), pending=store.pending_approvals())

@app.route("/new")
def new_agent():
    return render_template("builder.html", mode=rt.mode(), catalog=_catalog())

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
    cat = {c["name"]: c for c in _catalog()}
    runs = [r for r in store.list_runs(50) if r["agent_id"] == aid]
    return render_template("agent.html", mode=rt.mode(), agent=ag, catalog=cat, runs=runs)

@app.route("/run", methods=["POST"])
def run():
    aid = request.form.get("agent_id")
    user_input = request.form.get("input", "").strip()
    if not store.get_agent(aid) or not user_input:
        abort(400)
    rid = store.create_run(aid, user_input)
    rt.advance(rid)
    return redirect(url_for("run_view", rid=rid))

@app.route("/run/<rid>")
def run_view(rid):
    r = store.get_run(rid)
    if not r: abort(404)
    ag = store.get_agent(r["agent_id"])
    return render_template("run.html", mode=rt.mode(), run=r, agent=ag,
                           audit=store.audit_for_run(rid),
                           approvals=store.approvals_for_run(rid),
                           skill_meta=gov.skill_meta)

@app.route("/approval/<apid>", methods=["POST"])
def approval(apid):
    ap = store.get_approval(apid)
    if not ap: abort(404)
    decision = request.form.get("decision")
    if decision in ("approved", "denied"):
        store.decide_approval(apid, decision, by="operator")
        rt.advance(ap["run_id"])
    back = request.form.get("back")
    return redirect(back or url_for("run_view", rid=ap["run_id"]))

@app.route("/approvals")
def approvals():
    return render_template("approvals.html", mode=rt.mode(), pending=store.pending_approvals(),
                           skill_meta=gov.skill_meta)

@app.route("/audit")
def audit():
    return render_template("audit.html", mode=rt.mode(), events=store.audit_all(300))

@app.route("/healthz")
def healthz():
    return {"ok": True, "mode": rt.mode()}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False, threaded=True)
