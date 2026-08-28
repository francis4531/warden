"""
The Warden runtime. Runs an agent in a perceive -> decide -> act loop against a live
Anthropic model, invoking tools over MCP. Governance is enforced here: before any
tool runs, its risk is checked; high-risk skills pause the run and open an approval,
and the run only resumes once a human decides.

Real model calls happen when ANTHROPIC_API_KEY is set. Without a key the runtime uses
a deterministic sandbox planner that emits the same message shapes, so the full
governance flow is demonstrable and testable offline. The UI badges which mode is live.
"""
import os
import json
import mcp_client
import governance as gov
import store

MODEL_DEFAULT = os.environ.get("WARDEN_MODEL", "claude-sonnet-4-5")
SANDBOX = not bool(os.environ.get("ANTHROPIC_API_KEY"))

def mode():
    return "sandbox" if SANDBOX else "live"

# ---- tool schema: MCP discovery -> Anthropic tools, filtered to the agent's skills ----
def tools_for(agent):
    allowed = set(agent.get("skills") or [])
    out = []
    for t in mcp_client.list_tools():
        if t["name"] in allowed:
            out.append({"name": t["name"], "description": t["description"],
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
    return {"stop_reason": resp.stop_reason,
            "content": [_block_to_dict(b) for b in resp.content]}

def _block_to_dict(b):
    if b.type == "text":
        return {"type": "text", "text": b.text}
    if b.type == "tool_use":
        return {"type": "tool_use", "id": b.id, "name": b.name, "input": b.input}
    return {"type": b.type}

# ---- deterministic sandbox planner (no key). Mimics a tool-using agent. ----
def _sandbox_model(messages, tools):
    names = {t["name"] for t in tools}
    text_in = json.dumps(messages).lower()
    called = set()
    for m in messages:
        for blk in (m.get("content") or []) if isinstance(m.get("content"), list) else []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                called.add(blk["name"])
    import re
    acct = None
    mm = re.search(r"ac-?\d{4}", text_in)
    if mm:
        acct = mm.group(0).upper().replace("AC", "AC-").replace("AC--", "AC-")
        if not acct.startswith("AC-"):
            acct = "AC-" + acct[-4:]
    wants_money = any(w in text_in for w in ["refund", "double charge", "charged twice",
                                             "duplicate", "make it right", "money back"])
    def tu(name, inp):
        return {"stop_reason": "tool_use",
                "content": [{"type": "tool_use", "id": "sbx_" + name, "name": name, "input": inp}]}
    if "lookup_customer" in names and "lookup_customer" not in called and acct:
        return tu("lookup_customer", {"account_id": acct})
    if "search_knowledge" in names and "search_knowledge" not in called and wants_money:
        return tu("search_knowledge", {"query": "refund policy"})
    if "issue_refund" in names and "issue_refund" not in called and wants_money and acct:
        return tu("issue_refund", {"account_id": acct, "amount": 4200,
                                   "reason": "duplicate charge verified against ledger"})
    if "create_ticket" in names and "create_ticket" not in called and acct and not wants_money:
        return tu("create_ticket", {"subject": f"Follow up on {acct}",
                                     "body": "Auto-opened by agent."})
    final = "[sandbox] Done. "
    if "issue_refund" in called:
        final += "Refund was issued after human approval and every step is in the audit log."
    elif "create_ticket" in called:
        final += "A ticket was opened and logged."
    elif acct:
        final += f"Reviewed account {acct}."
    else:
        final += "No action was required."
    return {"stop_reason": "end_turn", "content": [{"type": "text", "text": final}]}

# ---- the loop ----
def advance(run_id):
    """Drive a run forward until it finishes or pauses for approval."""
    run = store.get_run(run_id)
    agent = store.get_agent(run["agent_id"])
    system = (agent["instructions"] or "") + \
        "\n\nYou operate under Warden governance. High-impact actions may require human " \
        "approval before they execute; proceed with the tools available and Warden will " \
        "gate anything that needs a human."
    tools = tools_for(agent)
    messages = run["transcript"]

    if not messages:
        messages = [{"role": "user", "content": run["input"]}]
        store.audit(run_id, agent["id"], "run_started", detail={"input": run["input"], "mode": mode()})

    for _ in range(12):  # safety bound on loop iterations
        # If the last message is an assistant tool_use turn awaiting execution, handle it.
        last = messages[-1] if messages else None
        if last and last["role"] == "assistant" and _has_tool_use(last):
            outcome = _execute_tool_turn(run_id, agent, last, messages)
            if outcome == "paused":
                store.update_run(run_id, status="awaiting_approval", transcript=messages)
                return store.get_run(run_id)
            # else executed; fall through to call model again
        # Call the model for the next step.
        resp = _call_model(system, messages, tools)
        assistant_msg = {"role": "assistant", "content": resp["content"]}
        messages.append(assistant_msg)
        for blk in resp["content"]:
            if blk.get("type") == "text" and blk.get("text"):
                store.audit(run_id, agent["id"], "thought", detail={"text": blk["text"]})
        if resp["stop_reason"] != "tool_use":
            final = " ".join(b.get("text", "") for b in resp["content"] if b.get("type") == "text").strip()
            store.audit(run_id, agent["id"], "final", detail={"text": final})
            store.update_run(run_id, status="done", transcript=messages)
            return store.get_run(run_id)
        # loop back: next iteration will execute the tool_use turn we just appended

    store.audit(run_id, agent["id"], "error", detail={"text": "loop bound reached"})
    store.update_run(run_id, status="error", transcript=messages)
    return store.get_run(run_id)

def _has_tool_use(msg):
    return any(isinstance(b, dict) and b.get("type") == "tool_use" for b in msg["content"])

def _execute_tool_turn(run_id, agent, assistant_msg, messages):
    """Execute every tool_use in an assistant turn, gating high-risk ones.
    Returns 'paused' if approval is still pending, else 'executed'."""
    blocks = [b for b in assistant_msg["content"] if b.get("type") == "tool_use"]
    # First pass: ensure every gated block has an approval decision.
    for b in blocks:
        if gov.requires_approval(b["name"]):
            ap = _approval_for(run_id, b["id"])
            if ap is None:
                store.create_approval(run_id, agent["id"], b["name"], gov.risk_of(b["name"]),
                                      {"tool_use_id": b["id"], "input": b["input"]})
                store.audit(run_id, agent["id"], "approval_request", skill=b["name"],
                            risk=gov.risk_of(b["name"]), detail={"input": b["input"]})
            elif ap["status"] == "pending":
                pass  # still waiting
        # if not gated, nothing to check
    # If any gated block is still pending, pause the whole turn.
    for b in blocks:
        if gov.requires_approval(b["name"]):
            ap = _approval_for(run_id, b["id"])
            if ap and ap["status"] == "pending":
                return "paused"
    # All clear (auto skills, plus gated skills now approved/denied). Execute in order.
    tool_results = []
    for b in blocks:
        meta = gov.skill_meta(b["name"])
        gated = gov.requires_approval(b["name"])
        ap = _approval_for(run_id, b["id"]) if gated else None
        if gated and ap and ap["status"] == "denied":
            result_text = json.dumps({"denied": True,
                "note": "A human approver denied this action. Do not retry; explain and stop."})
            store.audit(run_id, agent["id"], "denied", skill=b["name"], risk=meta["risk"],
                        detail={"input": b["input"]})
        else:
            result_text = mcp_client.call_tool(b["name"], b["input"])
            store.audit(run_id, agent["id"],
                        "tool_result_gated" if gated else "tool_result",
                        skill=b["name"], risk=meta["risk"],
                        detail={"input": b["input"], "result": _safe(result_text)})
        tool_results.append({"type": "tool_result", "tool_use_id": b["id"], "content": result_text})
    messages.append({"role": "user", "content": tool_results})
    store.update_run(run_id, transcript=messages)
    return "executed"

def _approval_for(run_id, tool_use_id):
    for ap in store.approvals_for_run(run_id):
        if ap["arguments"].get("tool_use_id") == tool_use_id:
            return ap
    return None

def _safe(text):
    try:
        return json.loads(text)
    except Exception:
        return text
