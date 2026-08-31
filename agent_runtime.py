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

def _pol_ctx(run_id, tool_key, risk):
    """Context for policy conditions: how many times this tool already ran in the run,
    plus wall-clock and the tool's risk tier."""
    from datetime import datetime, timezone
    name = tool_key.split("__")[-1]
    count = sum(1 for e in store.audit_for_run(run_id)
                if e["kind"] in ("tool_result", "tool_result_gated")
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

def tools_for(agent):
    allowed = set(agent.get("skills") or [])
    out = []
    for t in _cm().all_tools():
        if t["key"] in allowed:
            out.append({"name": t["key"], "description": t["description"],
                        "input_schema": t["input_schema"]})
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
    user_text = ""
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            user_text = m["content"].lower(); break
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
    final += "Gated action executed after human approval; every step is in the audit log." if was_gated else "Reviewed and no gated action was required."
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
    return result

def _advance_once(run_id):
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

def _execute_tool_turn(run_id, agent, assistant_msg, messages, idx):
    blocks=[b for b in assistant_msg["content"] if b.get("type")=="tool_use"]
    for b in blocks:
        d = decide(run_id, agent["id"], b["name"], b["input"], idx)
        if d["effect"]=="gate":
            ap=_approval_for(run_id,b["id"])
            if ap is None:
                store.create_approval(run_id, agent["id"], b["name"], d["risk"],
                                      {"tool_use_id":b["id"],"input":b["input"],"policy":d["policy"]})
                store.audit(run_id, agent["id"], "approval_request", skill=b["name"],
                            risk=d["risk"], detail={"input":b["input"], "policy":d["policy"]})
    for b in blocks:
        if decide(run_id, agent["id"], b["name"], b["input"], idx)["effect"]=="gate":
            ap=_approval_for(run_id,b["id"])
            if ap and ap["status"]=="pending":
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
        elif gated and ap and ap["status"]=="denied":
            rtext=json.dumps({"denied":True,"note":"A human approver denied this action. Do not retry; explain and stop."})
            store.audit(run_id, agent["id"], "denied", skill=b["name"], risk=d["risk"],
                        detail={"input":b["input"],"outcome":"denied"})
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
