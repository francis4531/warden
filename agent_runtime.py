"""
The Warden runtime. Runs an agent in a perceive -> decide -> act loop against a live
Anthropic model, invoking tools across one or more connected MCP servers via the
connection manager. Governance is enforced here: each tool's risk is resolved
(override > known registry > auto-classification) and high-risk tools pause the run
for human approval. Live model calls when ANTHROPIC_API_KEY is set; otherwise a
deterministic sandbox planner drives the same flow offline.
"""
import os, json, re, time
import connection_manager as cmod
import governance as gov
import policy
import store

MODEL_DEFAULT = os.environ.get("WARDEN_MODEL", "claude-sonnet-4-5")
MAX_TOKENS = int(os.environ.get("WARDEN_MAX_TOKENS", "4096"))
SANDBOX = not bool(os.environ.get("ANTHROPIC_API_KEY"))

# ---- teams ----
# A lead agent (one with members) gets a single virtual tool, delegate(member, task). Each
# call spawns a member run under the member's own grants, policies, and budget; the lead
# never sees a member's tools. Delegation is governed like any other tool: it has a risk
# tier, it can be gated or denied by policy, and every hand-off is on the audit record.
DELEGATE_KEY = "team__delegate"
MAX_DEPTH = int(os.environ.get("WARDEN_MAX_DELEGATION_DEPTH", "1"))      # lead -> member only
MAX_DELEGATIONS = int(os.environ.get("WARDEN_MAX_DELEGATIONS", "8"))     # per lead run

# Estimated USD price per 1M tokens (input, output). Approximate list prices, editable;
# used only to estimate cost for the observability view. Matched by substring of model id.
PRICES = {"opus": (15.0, 75.0), "sonnet": (3.0, 15.0), "haiku": (0.80, 4.0)}
def _cost(model, inp, out):
    rate = (3.0, 15.0)
    m = (model or "").lower()
    for k, v in PRICES.items():
        if k in m:
            rate = v; break
    return round(inp / 1e6 * rate[0] + out / 1e6 * rate[1], 6)

def rate_for(model):
    m = (model or MODEL_DEFAULT).lower()
    for k, v in PRICES.items():
        if k in m:
            return v
    return (3.0, 15.0)

def _run_cost(run_id, tree=True):
    """Model spend for a run. With tree=True (the default) a lead's cost includes every
    member run it delegated to, so a team budget covers the whole team's work."""
    ids = store.run_tree_ids(run_id) if tree else [run_id]
    total = 0.0
    for rid in ids:
        for e in store.audit_for_run(rid):
            if e["kind"] == "model_call" and isinstance(e["detail"], dict):
                total += e["detail"].get("cost", 0) or 0
    return round(total, 6)

def tree_usage(run_id):
    """Cost, tokens, and model-call count across a run and all its member runs."""
    cost = 0.0; tokens = 0; calls = 0
    for rid in store.run_tree_ids(run_id):
        for e in store.audit_for_run(rid):
            if e["kind"] == "model_call" and isinstance(e["detail"], dict):
                d = e["detail"]; calls += 1
                cost += d.get("cost", 0) or 0
                tokens += (d.get("input_tokens", 0) or 0) + (d.get("output_tokens", 0) or 0)
    return {"cost": round(cost, 6), "tokens": tokens, "calls": calls}

def mode():
    return "sandbox" if SANDBOX else "live"

def _cm():
    cm = cmod.manager()
    cm.ensure_started(store.enabled_connections())
    return cm

def tool_index():
    """model_key -> {tool, desc, server} across all connected servers, plus the team
    delegate tool (virtual, served by the runtime rather than an MCP server)."""
    idx = {}
    for t in _cm().all_tools():
        idx[t["key"]] = {"tool": t["tool"], "desc": t["description"], "server": t["server_name"]}
    idx[DELEGATE_KEY] = {"tool": "delegate", "desc": "Hand a task to a team member agent.", "server": "Team"}
    return idx

def members_of(agent):
    """Resolved member agents of a lead, in the order they were added. Members that no
    longer exist are skipped; a lead never lists itself."""
    out = []
    for mid in (agent.get("members") or []):
        if mid == agent["id"]:
            continue
        m = store.get_agent(mid)
        if m and (m.get("owner") or "") == (agent.get("owner") or ""):
            out.append(m)
    return out

def delegate_tool(agent):
    """The delegate tool definition for this lead, with its members as the enum so the
    model can only hand work to agents that are actually on the team."""
    mem = members_of(agent)
    if not mem:
        return None
    names = [m["name"] for m in mem]
    lines = []
    for m in mem:
        n_ask = sum(1 for k in (m.get("skills") or []) if risk_for(k)["gate"] == "approval")
        lines.append("- %s: %s (%d tools, %d need human approval)" % (
            m["name"], (m.get("instructions") or "")[:140].replace("\n", " "), len(m.get("skills") or []), n_ask))
    desc = ("Delegate a task to a member of your team. The member runs on its own with its own "
            "tools and governance and returns a written result; you do not get its tools. Give a "
            "complete, self-contained task with all the facts the member needs. Members:\n" + "\n".join(lines))
    return {"name": DELEGATE_KEY, "description": desc,
            "input_schema": {"type": "object", "required": ["member", "task"],
                             "properties": {"member": {"type": "string", "enum": names,
                                                       "description": "Which team member to hand this to."},
                                            "task": {"type": "string",
                                                     "description": "The task, with every fact the member needs."}}}}

def risk_for(key, idx=None):
    idx = idx or tool_index()
    info = idx.get(key, {"tool": key, "desc": ""})
    return gov.meta(key, info["tool"], info["desc"], store.get_override(key))

def _pol_ctx(run_id, tool_key, risk):
    """Context for policy conditions: how many times this tool already ran in the run,
    plus wall-clock and the tool's risk tier."""
    from datetime import datetime, timezone
    name = tool_key.split("__")[-1]
    count = sum(1 for e in store.audit_for_run(run_id)
                if e["kind"] in ("tool_result", "tool_result_gated", "delegation")
                and (e["skill"] or "").split("__")[-1] == name)
    n = datetime.now(timezone.utc)
    return {"count": count, "hour": n.hour, "weekday": n.weekday(), "risk": risk}

def decide(run_id, agent_id, key, args, idx=None):
    """Combine the risk-tier default with the policy engine. Returns
    {effect: allow|gate|deny, risk, policy}. A policy can escalate, de-escalate, or deny;
    with no matching policy the risk tier decides (HIGH gates, else auto)."""
    m = risk_for(key, idx)
    base = "gate" if m["gate"] == "approval" else "allow"
    pol = policy.evaluate(agent_id, key, args, _pol_ctx(run_id, key, m["risk"]))
    eff = pol["effect"]
    if eff == "deny":
        return {"effect": "deny", "risk": m["risk"], "policy": pol["name"]}
    if eff == "require_approval":
        return {"effect": "gate", "risk": m["risk"], "policy": pol["name"]}
    if eff == "allow":
        return {"effect": "allow", "risk": m["risk"], "policy": pol["name"]}
    return {"effect": base, "risk": m["risk"], "policy": None}

def tools_for(agent, depth=0):
    allowed = set(agent.get("skills") or [])
    out = []
    for t in _cm().all_tools():
        if t["key"] in allowed:
            out.append({"name": t["key"], "description": t["description"],
                        "input_schema": t["input_schema"]})
    if depth < MAX_DEPTH:
        dt = delegate_tool(agent)
        if dt:
            out.append(dt)
    return out

# ---- model dispatch ----
def _repair(messages):
    """Guarantee the API invariant: every assistant tool_use is answered by a tool_result
    in the very next message. If a tool crashed, a response was truncated, or a follow-up
    landed on a dangling turn, backfill synthetic 'interrupted' results so the request is
    valid. Turns a hard 400 into a graceful continuation the model can reason about."""
    i = 0
    while i < len(messages):
        m = messages[i]
        if m.get("role") == "assistant" and isinstance(m.get("content"), list):
            ids = [b["id"] for b in m["content"]
                   if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id")]
            if ids:
                nxt = messages[i + 1] if i + 1 < len(messages) else None
                answered = set()
                if nxt and nxt.get("role") == "user" and isinstance(nxt.get("content"), list):
                    answered = {b.get("tool_use_id") for b in nxt["content"]
                                if isinstance(b, dict) and b.get("type") == "tool_result"}
                missing = [t for t in ids if t not in answered]
                if missing:
                    fills = [{"type": "tool_result", "tool_use_id": t,
                              "content": json.dumps({"error": "interrupted",
                                  "note": "This tool did not complete. Do not assume it ran."})}
                             for t in missing]
                    if nxt and nxt.get("role") == "user" and isinstance(nxt.get("content"), list):
                        nxt["content"] = fills + nxt["content"]
                    else:
                        messages.insert(i + 1, {"role": "user", "content": fills})
        i += 1

_TRANSIENT = ("rate", "overloaded", "timeout", "timedout", "internal", "unavailable", "connection")
def _is_transient(ex):
    code = getattr(ex, "status_code", None)
    if code in (408, 409, 429, 500, 502, 503, 504, 529):
        return True
    return any(w in (type(ex).__name__ + " " + str(ex)).lower() for w in _TRANSIENT)

def _friendly_error(ex):
    code = getattr(ex, "status_code", None)
    if code == 401 or "authentication" in str(ex).lower():
        return "The model rejected the API key. Check ANTHROPIC_API_KEY."
    if code == 429 or "rate" in str(ex).lower():
        return "The model is rate-limited right now. Try again in a moment."
    if code and 500 <= code < 600:
        return "The model service had a temporary error. Try again in a moment."
    if code == 400:
        return "The model rejected the request. This run hit a malformed-request error; the transcript has been repaired, please retry."
    return "The run hit an error talking to the model: " + str(ex)[:200]

def _call_model(system, messages, tools):
    t0 = time.time()
    if SANDBOX:
        r = _sandbox_model(messages, tools)
        r["usage"] = {"input_tokens": 0, "output_tokens": 0}
        r["model"] = "sandbox"; r["latency_ms"] = int((time.time() - t0) * 1000)
        return r
    import anthropic
    client = anthropic.Anthropic()
    last = None
    for attempt in range(3):
        try:
            resp = client.messages.create(model=MODEL_DEFAULT, max_tokens=MAX_TOKENS,
                                          system=system, messages=messages, tools=tools)
            return {"stop_reason": resp.stop_reason, "content": [_b2d(b) for b in resp.content],
                    "usage": {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens},
                    "model": MODEL_DEFAULT, "latency_ms": int((time.time() - t0) * 1000)}
        except Exception as ex:
            last = ex
            if _is_transient(ex) and attempt < 2:
                time.sleep(1.5 * (attempt + 1)); continue
            raise last

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
    # Intent comes from the user's actual request, not the accumulating transcript,
    # so a completed refund doesn't spuriously trigger a file-write gate.
    user_text = ""; user_raw = ""
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            user_raw = m["content"]; user_text = user_raw.lower(); break
    called = set()
    for m in messages:
        for blk in (m.get("content") or []) if isinstance(m.get("content"), list) else []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                called.add(blk["name"])
    mm = re.search(r"ac-?\d{4}", user_text)
    acct = ("AC-" + mm.group(0)[-4:]) if mm else None
    money = any(w in user_text for w in ["refund","charged twice","double charge","duplicate","make it right","money back"])
    def tu(key, inp):
        return {"stop_reason":"tool_use","content":[{"type":"tool_use","id":"sbx_"+key,"name":key,"input":inp}]}
    # team lead: hand the request to each member in turn, then summarize what came back
    k_del = _find_key(tools, "delegate")
    if k_del:
        dt = next(t for t in tools if t["name"] == k_del)
        names = dt["input_schema"]["properties"]["member"]["enum"]
        done = []
        for m in messages:
            for blk in (m.get("content") or []) if isinstance(m.get("content"), list) else []:
                if isinstance(blk, dict) and blk.get("type") == "tool_use" and blk["name"] == k_del:
                    done.append(blk["input"].get("member"))
        for n in names:
            if n not in done:
                return {"stop_reason":"tool_use","content":[{"type":"tool_use","id":"sbx_del_%d" % len(done),
                        "name":k_del,"input":{"member":n,"task":user_raw.strip() or "Handle this request."}}]}
        results = []
        for m in messages:
            for blk in (m.get("content") or []) if isinstance(m.get("content"), list) else []:
                if isinstance(blk, dict) and blk.get("type") == "tool_result" and str(blk.get("tool_use_id","")).startswith("sbx_del_"):
                    r = _safe(blk.get("content"))
                    if isinstance(r, dict):
                        results.append(r.get("result") if "result" in r else ("hand-off denied" if r.get("denied") else json.dumps(r)))
                    else:
                        results.append(str(r))
        summary = "[sandbox] Team lead summary. " + " ".join("Member reported: %s" % (r or "")[:160] for r in results)
        return {"stop_reason":"end_turn","content":[{"type":"text","text":summary}]}
    k_lookup=_find_key(tools,"lookup_customer"); k_kb=_find_key(tools,"search_knowledge")
    k_refund=_find_key(tools,"issue_refund")
    if k_lookup and k_lookup not in called and acct: return tu(k_lookup,{"account_id":acct})
    if k_kb and k_kb not in called and money: return tu(k_kb,{"query":"refund policy"})
    if k_refund and k_refund not in called and money and acct:
        return tu(k_refund,{"account_id":acct,"amount":4200,"reason":"duplicate charge verified against ledger"})
    # filesystem scenario
    k_list=_find_key(tools,"list_files"); k_write=_find_key(tools,"write_file")
    wants_file = any(w in user_text for w in ["file","note","write","summary","save"])
    if k_list and k_list not in called and wants_file:
        return tu(k_list,{"subdir":""})
    if k_write and k_write not in called and wants_file:
        fn=re.search(r"([\w\-/]+\.\w{1,5})", text_in)
        name=fn.group(1) if fn else "note.txt"
        return tu(k_write,{"path":name,"content":"Written by a Warden agent after human approval."})
    final="[sandbox] Done. "
    was_gated = any(("issue_refund" in c or "write_file" in c) for c in called)
    was_held = '"held": true' in text_in or '"held":true' in text_in
    was_denied = '"denied": true' in text_in or '"denied":true' in text_in
    if was_denied:
        final += "The high-risk action was denied by a human approver and was not executed. I have stopped there."
    elif was_held:
        final += "The high-risk action is held for human approval and has not been executed; nothing further happens until a person decides."
    elif was_gated:
        final += "Gated action executed after human approval; every step is in the audit log."
    else:
        final += "Reviewed and no gated action was required."
    return {"stop_reason":"end_turn","content":[{"type":"text","text":final}]}

# ---- the loop ----
import threading
_run_locks = {}        # run_id -> Lock, serializes advance() per run
_rerun = set()         # run_ids asked to advance again while already advancing
_guard = threading.Lock()

def advance(run_id):
    """Serialize advancing a single run. Concurrent triggers (e.g. several approvals
    decided at once) must not run the loop on the same transcript in parallel, or the
    model gets an assistant turn whose tool_use blocks aren't all answered yet (API 400).
    Only one thread advances a run at a time; triggers that arrive mid-advance cause
    exactly one more pass afterward, so the latest decisions are always picked up."""
    with _guard:
        lock = _run_locks.setdefault(run_id, threading.Lock())
        if lock.locked():
            _rerun.add(run_id)          # someone is already advancing; ask them to loop
            return store.get_run(run_id)
    with lock:
        while True:
            result = _advance_once(run_id)
            with _guard:
                if run_id in _rerun:
                    _rerun.discard(run_id)
                    continue            # a decision landed during the pass; go again
                break
    # a member run that finished (or failed) hands control back to the lead that delegated
    # to it, unless the lead is the one driving this call right now (synchronous delegation)
    parent = result.get("parent_run_id") if result else None
    if parent and result.get("status") in ("done", "error") and not _driving.get(parent):
        try:
            advance(parent)
        except Exception as ex:
            store.audit(parent, None, "error", detail={"text": "Could not resume the lead after a member finished: " + str(ex)[:160]})
            store.update_run(parent, status="error")
    return result

_driving = {}   # parent run_id -> True while its own thread is running member runs

def _advance_once(run_id):
    run = store.get_run(run_id); agent = store.get_agent(run["agent_id"])
    depth = int(run.get("depth") or 0)
    system = (agent["instructions"] or "") + \
        "\n\nYou operate under Warden governance. High-impact actions may require human " \
        "approval before they execute; use the tools available and Warden gates what needs a human."
    tools = tools_for(agent, depth); idx = tool_index(); messages = run["transcript"]
    if any(t["name"] == DELEGATE_KEY for t in tools):
        system += ("\n\nYou lead a team. Use delegate to hand well-defined tasks to members; each member "
                   "works under its own tool grants and approvals, and you only receive its written result. "
                   "Delegate when a member is better placed to do the work, do the rest yourself, and finish "
                   "with a clear summary of what was done and by whom.")
    if depth > 0:
        system += ("\n\nYou are working as a team member on a task delegated by your lead. Do the task with "
                   "your own tools and reply with a complete, factual written result the lead can act on.")
    if not messages:
        messages = [{"role":"user","content":run["input"]}]
        store.audit(run_id, agent["id"], "run_started", detail={"input":run["input"],"mode":mode(),
                    **({"parent_run_id": run["parent_run_id"], "depth": depth} if run.get("parent_run_id") else {})})
    budget = float(agent.get("budget_usd") or 0)
    # a member run also answers to its lead's budget: the lead's cap covers the whole tree
    root = store.root_run(run) if run.get("parent_run_id") else None
    root_agent = store.get_agent(root["agent_id"]) if root else None
    root_budget = float(root_agent.get("budget_usd") or 0) if root_agent else 0.0
    daily_cap = float(os.environ.get("WARDEN_DAILY_BUDGET", "0") or 0)
    for _ in range(12):
        last = messages[-1] if messages else None
        if last and last["role"]=="assistant" and _has_tool_use(last):
            if _execute_tool_turn(run_id, agent, last, messages, idx) == "paused":
                store.update_run(run_id, status="awaiting_approval", transcript=messages)
                return store.get_run(run_id)
        if daily_cap > 0:
            from datetime import datetime, timezone
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if store.cost_since(today) >= daily_cap:
                store.audit(run_id, agent["id"], "budget_stop",
                            detail={"text": "Run stopped: this studio reached its shared daily budget of "
                                            "$%.2f across all users. It resets tomorrow (UTC)."
                                            % daily_cap, "budget": daily_cap, "spent": store.cost_since(today),
                                            "scope": "daily"})
                store.update_run(run_id, status="done", transcript=messages)
                return store.get_run(run_id)
        if budget > 0:
            spent = _run_cost(run_id)
            if spent >= budget:
                team = bool(store.child_runs(run_id))
                store.audit(run_id, agent["id"], "budget_stop",
                            detail={"text": "Run stopped: it reached its budget of $%.2f (spent $%.4f%s). "
                                            "Nothing further ran. Raise the agent's budget to continue."
                                            % (budget, spent, " across the team" if team else ""),
                                    "budget": budget, "spent": spent, "scope": "team" if team else "run"})
                store.update_run(run_id, status="done", transcript=messages)
                return store.get_run(run_id)
        if root_budget > 0:
            spent = _run_cost(root["id"])
            if spent >= root_budget:
                store.audit(run_id, agent["id"], "budget_stop",
                            detail={"text": "Run stopped: the team reached its lead's budget of $%.2f (spent $%.4f "
                                            "across the team). Nothing further ran." % (root_budget, spent),
                                    "budget": root_budget, "spent": spent, "scope": "team"})
                store.update_run(run_id, status="done", transcript=messages)
                return store.get_run(run_id)
        _repair(messages)   # never send an unanswered tool_use to the API
        try:
            resp = _call_model(system, messages, tools)
        except Exception as ex:
            store.audit(run_id, agent["id"], "error", detail={"text": _friendly_error(ex)})
            store.update_run(run_id, status="error", transcript=messages)
            return store.get_run(run_id)
        u = resp.get("usage", {})
        store.audit(run_id, agent["id"], "model_call",
                    detail={"model": resp.get("model"), "input_tokens": u.get("input_tokens", 0),
                            "output_tokens": u.get("output_tokens", 0), "latency_ms": resp.get("latency_ms", 0),
                            "cost": _cost(resp.get("model"), u.get("input_tokens", 0), u.get("output_tokens", 0))})
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

def _child_for(run_id, tool_use_id):
    for ch in store.child_runs(run_id):
        if ch.get("parent_tool_use_id") == tool_use_id:
            return ch
    return None

def _final_text(child):
    for e in reversed(store.audit_for_run(child["id"])):
        if e["kind"] == "final" and isinstance(e["detail"], dict):
            return e["detail"].get("text", "")
        if e["kind"] in ("error", "budget_stop") and isinstance(e["detail"], dict):
            return "[" + e["kind"].replace("_", " ") + "] " + e["detail"].get("text", "")
    return ""

def _start_delegation(run_id, agent, run, b, d):
    """Create the member run for one delegate call. Returns (child, error_text)."""
    inp = b["input"] if isinstance(b["input"], dict) else {}
    want = str(inp.get("member") or "").strip()
    task = str(inp.get("task") or "").strip()
    mem = members_of(agent)
    member = next((m for m in mem if m["name"] == want), None) or \
             next((m for m in mem if m["id"] == want), None)
    if member is None:
        return None, json.dumps({"error": "unknown_member", "member": want,
                                 "note": "Not on this team. Members: " + ", ".join(m["name"] for m in mem)})
    if not task:
        return None, json.dumps({"error": "empty_task", "note": "Give the member a complete task."})
    n = len(store.child_runs(run_id))
    if n >= MAX_DELEGATIONS:
        store.audit(run_id, agent["id"], "policy_denied", skill=DELEGATE_KEY, risk=d["risk"],
                    detail={"input": inp, "outcome": "denied",
                            "policy": "team delegation cap (%d per run)" % MAX_DELEGATIONS})
        return None, json.dumps({"denied": True, "by": "policy", "policy": "team delegation cap",
                                 "note": "This run already delegated %d times, the cap. Finish with what you have." % n})
    depth = int(run.get("depth") or 0) + 1
    cid = store.create_run(member["id"], task, parent_run_id=run_id, parent_tool_use_id=b["id"], depth=depth,
                           eval_run_id=run.get("eval_run_id"))
    store.audit(run_id, agent["id"], "delegation", skill=DELEGATE_KEY, risk=d["risk"],
                detail={"member": member["name"], "member_id": member["id"], "task": task,
                        "child_run": cid, "input": inp, **({"policy": d["policy"]} if d["policy"] else {})})
    return store.get_run(cid), None

def _run_children(run_id, children):
    """Advance member runs that still have work, in parallel, and wait for them to either
    finish or pause for a human. The lead's thread drives them, so a member finishing here
    must not also try to resume the lead (see advance())."""
    todo = [c for c in children if c["status"] == "running"]
    if not todo:
        return
    _driving[run_id] = True
    try:
        if len(todo) == 1:
            advance(todo[0]["id"])
        else:
            ths = [threading.Thread(target=advance, args=(c["id"],), daemon=True) for c in todo]
            for t in ths: t.start()
            for t in ths: t.join()
    finally:
        _driving.pop(run_id, None)

EVAL_HOLD_NOTE = ("This action requires human approval. This is an evaluation run, so it was recorded "
                  "as held and NOT executed. Continue as you would if it were pending review: do not "
                  "claim it happened, and finish with what you would tell the requester.")

def _execute_tool_turn(run_id, agent, assistant_msg, messages, idx):
    run = store.get_run(run_id)
    in_eval = bool(run.get("eval_run_id"))
    blocks=[b for b in assistant_msg["content"] if b.get("type")=="tool_use"]
    for b in blocks:
        d = decide(run_id, agent["id"], b["name"], b["input"], idx)
        if d["effect"]=="gate" and in_eval:
            continue                      # evals never execute or queue gated actions
        if d["effect"]=="gate":
            ap=_approval_for(run_id,b["id"])
            if ap is None:
                store.create_approval(run_id, agent["id"], b["name"], d["risk"],
                                      {"tool_use_id":b["id"],"input":b["input"],"policy":d["policy"]})
                store.audit(run_id, agent["id"], "approval_request", skill=b["name"],
                            risk=d["risk"], detail={"input":b["input"], "policy":d["policy"]})
    for b in blocks:
        if not in_eval and decide(run_id, agent["id"], b["name"], b["input"], idx)["effect"]=="gate":
            ap=_approval_for(run_id,b["id"])
            if ap and ap["status"]=="pending":
                return "paused"
    # delegations: start member runs for every delegate call that is allowed (or approved),
    # drive them together, and pause the lead if any member is now waiting on a human
    deleg_err = {}
    children = []
    for b in blocks:
        if b["name"] != DELEGATE_KEY:
            continue
        d = decide(run_id, agent["id"], b["name"], b["input"], idx)
        if d["effect"] == "deny":
            continue
        if d["effect"] == "gate":
            if in_eval:
                continue                  # a gated hand-off is held like any other gated action
            ap = _approval_for(run_id, b["id"])
            if not ap or ap["status"] != "approved":
                continue
        ch = _child_for(run_id, b["id"])
        if ch is None:
            ch, err = _start_delegation(run_id, agent, run, b, d)
            if err:
                deleg_err[b["id"]] = err; continue
        children.append(ch)
    if children:
        _run_children(run_id, children)
        for ch in children:
            if store.get_run(ch["id"])["status"] in ("awaiting_approval", "running"):
                return "paused"
    results=[]
    for b in blocks:
        d=decide(run_id, agent["id"], b["name"], b["input"], idx)
        gated=d["effect"]=="gate"
        ap=_approval_for(run_id,b["id"]) if gated else None
        if d["effect"]=="deny":
            rtext=json.dumps({"denied":True,"by":"policy","policy":d["policy"],
                              "note":"A governance policy blocked this action. Do not retry; explain that it is not permitted."})
            store.audit(run_id, agent["id"], "policy_denied", skill=b["name"], risk=d["risk"],
                        detail={"input":b["input"],"outcome":"denied","policy":d["policy"]})
        elif gated and in_eval:
            rtext=json.dumps({"held":True,"by":"evaluation","note":EVAL_HOLD_NOTE})
            store.audit(run_id, agent["id"], "eval_held", skill=b["name"], risk=d["risk"],
                        detail={"input":b["input"],"outcome":"held","policy":d["policy"]})
        elif gated and ap and ap["status"]=="denied":
            rtext=json.dumps({"denied":True,"note":"A human approver denied this action. Do not retry; explain and stop."})
            store.audit(run_id, agent["id"], "denied", skill=b["name"], risk=d["risk"],
                        detail={"input":b["input"],"outcome":"denied"})
        elif b["name"] == DELEGATE_KEY and not (gated and in_eval):
            if b["id"] in deleg_err:
                rtext = deleg_err[b["id"]]
            else:
                ch = store.get_run(_child_for(run_id, b["id"])["id"])
                member = store.get_agent(ch["agent_id"]) or {"name": "member"}
                text = _final_text(ch)
                cost = _run_cost(ch["id"])
                status = "done" if ch["status"] == "done" else "failed"
                store.audit(run_id, agent["id"], "delegation_result", skill=DELEGATE_KEY, risk=d["risk"],
                            detail={"member": member["name"], "member_id": ch["agent_id"], "child_run": ch["id"],
                                    "input": b["input"], "result": text[:2000], "outcome": "ok" if status == "done" else "error",
                                    "cost": cost, "steps": sum(1 for e in store.audit_for_run(ch["id"])
                                                               if e["kind"] in ("tool_result", "tool_result_gated", "denied", "policy_denied"))})
                rtext = json.dumps({"member": member["name"], "status": status, "result": text})
        else:
            t0=time.time()
            try:
                rtext=_cm().call_by_key(b["name"], b["input"])
            except Exception as ex:
                rtext=json.dumps({"error":"tool_failed","message":str(ex)[:300],
                                  "note":"This tool raised an error. Do not assume it ran; explain or try another approach."})
            parsed=_safe(rtext)
            outcome="error" if isinstance(parsed, dict) and parsed.get("error") else "ok"
            det={"input":b["input"],"result":parsed,
                 "latency_ms":int((time.time()-t0)*1000),"outcome":outcome}
            if d["policy"]:                      # policy explicitly allowed this (e.g. below a threshold)
                det["policy"]=d["policy"]
            store.audit(run_id, agent["id"], "tool_result_gated" if gated else "tool_result",
                        skill=b["name"], risk=d["risk"], detail=det)
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
