"""
The Warden runtime. Runs an agent in a perceive -> decide -> act loop against a live
Anthropic model, invoking tools across one or more connected MCP servers via the
connection manager. Governance is enforced here: each tool's risk is resolved
(override > known registry > auto-classification) and high-risk tools pause the run
for human approval. Live model calls when ANTHROPIC_API_KEY is set; otherwise a
deterministic sandbox planner drives the same flow offline.
"""
import os, json, re
import connection_manager as cmod
import governance as gov
import store

MODEL_DEFAULT = os.environ.get("WARDEN_MODEL", "claude-sonnet-4-5")
SANDBOX = not bool(os.environ.get("ANTHROPIC_API_KEY"))

def mode():
    return "sandbox" if SANDBOX else "live"

def _cm():
    cm = cmod.manager()
    cm.ensure_started(store.enabled_connections())
    return cm

def tool_index():
    """model_key -> {tool, desc, server} across all connected servers."""
    idx = {}
    for t in _cm().all_tools():
        idx[t["key"]] = {"tool": t["tool"], "desc": t["description"], "server": t["server_name"]}
    return idx

def risk_for(key, idx=None):
    idx = idx or tool_index()
    info = idx.get(key, {"tool": key, "desc": ""})
    return gov.meta(key, info["tool"], info["desc"], store.get_override(key))

def tools_for(agent):
    allowed = set(agent.get("skills") or [])
    out = []
    for t in _cm().all_tools():
        if t["key"] in allowed:
            out.append({"name": t["key"], "description": t["description"],
                        "input_schema": t["input_schema"]})
    return out

# ---- model dispatch ----
def _call_model(system, messages, tools):
    if SANDBOX:
        return _sandbox_model(messages, tools)
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(model=MODEL_DEFAULT, max_tokens=1024,
                                  system=system, messages=messages, tools=tools)
    return {"stop_reason": resp.stop_reason, "content": [_b2d(b) for b in resp.content]}

def _b2d(b):
    if b.type == "text": return {"type": "text", "text": b.text}
    if b.type == "tool_use": return {"type": "tool_use", "id": b.id, "name": b.name, "input": b.input}
    return {"type": b.type}

# ---- sandbox planner (offline). Emits the same message shapes, using real tool keys. ----
def _find_key(tools, bare):
    for t in tools:
        if t["name"].endswith("__" + bare) or t["name"] == bare:
            return t["name"]
    return None

def _sandbox_model(messages, tools):
    text_in = json.dumps(messages).lower()
    called = set()
    for m in messages:
        for blk in (m.get("content") or []) if isinstance(m.get("content"), list) else []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                called.add(blk["name"])
    mm = re.search(r"ac-?\d{4}", text_in)
    acct = ("AC-" + mm.group(0)[-4:]) if mm else None
    money = any(w in text_in for w in ["refund","charged twice","double charge","duplicate","make it right","money back"])
    def tu(key, inp):
        return {"stop_reason":"tool_use","content":[{"type":"tool_use","id":"sbx_"+key,"name":key,"input":inp}]}
    k_lookup=_find_key(tools,"lookup_customer"); k_kb=_find_key(tools,"search_knowledge")
    k_refund=_find_key(tools,"issue_refund")
    if k_lookup and k_lookup not in called and acct: return tu(k_lookup,{"account_id":acct})
    if k_kb and k_kb not in called and money: return tu(k_kb,{"query":"refund policy"})
    if k_refund and k_refund not in called and money and acct:
        return tu(k_refund,{"account_id":acct,"amount":4200,"reason":"duplicate charge verified against ledger"})
    # filesystem scenario
    k_list=_find_key(tools,"list_files"); k_write=_find_key(tools,"write_file")
    wants_file = any(w in text_in for w in ["file","note","write","summary","save"])
    if k_list and k_list not in called and wants_file:
        return tu(k_list,{"subdir":""})
    if k_write and k_write not in called and wants_file:
        fn=re.search(r"([\w\-/]+\.\w{1,5})", text_in)
        name=fn.group(1) if fn else "note.txt"
        return tu(k_write,{"path":name,"content":"Written by a Warden agent after human approval."})
    final="[sandbox] Done. "
    was_gated = any(("issue_refund" in c or "write_file" in c) for c in called)
    final += "Gated action executed after human approval; every step is in the audit log." if was_gated else "Reviewed and no gated action was required."
    return {"stop_reason":"end_turn","content":[{"type":"text","text":final}]}

# ---- the loop ----
def advance(run_id):
    run = store.get_run(run_id); agent = store.get_agent(run["agent_id"])
    system = (agent["instructions"] or "") + \
        "\n\nYou operate under Warden governance. High-impact actions may require human " \
        "approval before they execute; use the tools available and Warden gates what needs a human."
    tools = tools_for(agent); idx = tool_index(); messages = run["transcript"]
    if not messages:
        messages = [{"role":"user","content":run["input"]}]
        store.audit(run_id, agent["id"], "run_started", detail={"input":run["input"],"mode":mode()})
    for _ in range(12):
        last = messages[-1] if messages else None
        if last and last["role"]=="assistant" and _has_tool_use(last):
            if _execute_tool_turn(run_id, agent, last, messages, idx) == "paused":
                store.update_run(run_id, status="awaiting_approval", transcript=messages)
                return store.get_run(run_id)
        resp = _call_model(system, messages, tools)
        messages.append({"role":"assistant","content":resp["content"]})
        for blk in resp["content"]:
            if blk.get("type")=="text" and blk.get("text"):
                store.audit(run_id, agent["id"], "thought", detail={"text":blk["text"]})
        if resp["stop_reason"]!="tool_use":
            final=" ".join(b.get("text","") for b in resp["content"] if b.get("type")=="text").strip()
            store.audit(run_id, agent["id"], "final", detail={"text":final})
            store.update_run(run_id, status="done", transcript=messages)
            return store.get_run(run_id)
    store.audit(run_id, agent["id"], "error", detail={"text":"loop bound reached"})
    store.update_run(run_id, status="error", transcript=messages)
    return store.get_run(run_id)

def _has_tool_use(msg):
    return any(isinstance(b,dict) and b.get("type")=="tool_use" for b in msg["content"])

def _execute_tool_turn(run_id, agent, assistant_msg, messages, idx):
    blocks=[b for b in assistant_msg["content"] if b.get("type")=="tool_use"]
    for b in blocks:
        m = risk_for(b["name"], idx)
        if m["gate"]=="approval":
            ap=_approval_for(run_id,b["id"])
            if ap is None:
                store.create_approval(run_id, agent["id"], b["name"], m["risk"],
                                      {"tool_use_id":b["id"],"input":b["input"]})
                store.audit(run_id, agent["id"], "approval_request", skill=b["name"],
                            risk=m["risk"], detail={"input":b["input"]})
    for b in blocks:
        if risk_for(b["name"], idx)["gate"]=="approval":
            ap=_approval_for(run_id,b["id"])
            if ap and ap["status"]=="pending":
                return "paused"
    results=[]
    for b in blocks:
        m=risk_for(b["name"], idx); gated=m["gate"]=="approval"
        ap=_approval_for(run_id,b["id"]) if gated else None
        if gated and ap and ap["status"]=="denied":
            rtext=json.dumps({"denied":True,"note":"A human approver denied this action. Do not retry; explain and stop."})
            store.audit(run_id, agent["id"], "denied", skill=b["name"], risk=m["risk"], detail={"input":b["input"]})
        else:
            rtext=_cm().call_by_key(b["name"], b["input"])
            store.audit(run_id, agent["id"], "tool_result_gated" if gated else "tool_result",
                        skill=b["name"], risk=m["risk"], detail={"input":b["input"],"result":_safe(rtext)})
        results.append({"type":"tool_result","tool_use_id":b["id"],"content":rtext})
    messages.append({"role":"user","content":results})
    store.update_run(run_id, transcript=messages)
    return "executed"

def _approval_for(run_id, tool_use_id):
    for ap in store.approvals_for_run(run_id):
        if ap["arguments"].get("tool_use_id")==tool_use_id:
            return ap
    return None

def _safe(t):
    try: return json.loads(t)
    except Exception: return t
