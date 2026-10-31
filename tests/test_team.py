"""Team delegation: a lead hands tasks to member agents, each member runs under its own
grants and approvals, and the lead gets back only the written result."""
import json, threading
from conftest import K


def _team(store, rt, owner, members, lead_budget=0):
    mids = [store.create_agent(n, instr, rt.MODEL_DEFAULT, skills, owner=owner) for n, instr, skills in members]
    lid = store.create_agent("Lead " + owner, "lead the team", rt.MODEL_DEFAULT, [], owner=owner,
                             members=mids, budget_usd=lead_budget)
    return lid, mids


def _kinds(store, rid):
    return [e["kind"] for e in store.audit_for_run(rid)]


def test_lead_delegates_to_each_member_and_summarizes(warden):
    store, rt = warden["store"], warden["rt"]
    lid, (m1, m2) = _team(store, rt, "t1@x.com", [("Lookup", "finds customers", [K("lookup_customer")]),
                                                  ("Docs", "searches the knowledge base", [K("search_knowledge")])])
    rid = store.create_run(lid, "Look up customer AC-1001")
    r = rt.advance(rid)
    assert r["status"] == "done"
    kids = store.child_runs(rid)
    assert sorted(k["agent_id"] for k in kids) == sorted([m1, m2])
    assert all(k["depth"] == 1 and k["parent_run_id"] == rid and k["status"] == "done" for k in kids)
    ev = store.audit_for_run(rid)
    assert [e["detail"]["member"] for e in ev if e["kind"] == "delegation"] == ["Lookup", "Docs"]
    results = [e["detail"] for e in ev if e["kind"] == "delegation_result"]
    assert len(results) == 2 and all(d["outcome"] == "ok" and d["result"] for d in results)
    final = [e for e in ev if e["kind"] == "final"][-1]["detail"]["text"]
    assert final.count("Member reported") == 2
    # the member did its own work under its own grants; the lead ran no member tool itself
    assert "tool_result" in _kinds(store, next(k["id"] for k in kids if k["agent_id"] == m1))
    assert "tool_result" not in _kinds(store, rid)


def test_member_approval_pauses_the_lead_until_decided(warden):
    store, rt = warden["store"], warden["rt"]
    lid, (mid,) = _team(store, rt, "t2@x.com", [("Billing", "handles refunds",
                                                [K("lookup_customer"), K("search_knowledge"), K("issue_refund")])])
    rid = store.create_run(lid, "Customer AC-1001 was charged twice, refund them")
    r = rt.advance(rid)
    child = store.child_runs(rid)[0]
    assert r["status"] == "awaiting_approval" and child["status"] == "awaiting_approval", "the whole team waits"
    pending = [a for a in store.approvals_for_run(child["id"]) if a["status"] == "pending"]
    assert len(pending) == 1 and pending[0]["skill"] == K("issue_refund")
    assert not any(a["status"] == "pending" for a in store.approvals_for_run(rid)), "the gate is on the member's run"
    store.decide_approval(pending[0]["id"], "approved", by="t2@x.com")
    rt.advance(child["id"])                       # what the approval route does; the member then resumes the lead
    assert store.get_run(child["id"])["status"] == "done"
    assert store.get_run(rid)["status"] == "done"
    assert "tool_result_gated" in _kinds(store, child["id"])
    res = [e for e in store.audit_for_run(rid) if e["kind"] == "delegation_result"][-1]["detail"]
    assert res["outcome"] == "ok" and "approval" in res["result"]


def test_member_denied_action_is_reported_to_the_lead(warden):
    store, rt = warden["store"], warden["rt"]
    lid, (mid,) = _team(store, rt, "t3@x.com", [("Billing3", "handles refunds",
                                                [K("lookup_customer"), K("search_knowledge"), K("issue_refund")])])
    rid = store.create_run(lid, "Customer AC-1001 was charged twice, refund them")
    rt.advance(rid)
    child = store.child_runs(rid)[0]
    ap = [a for a in store.approvals_for_run(child["id"]) if a["status"] == "pending"][0]
    store.decide_approval(ap["id"], "denied", by="t3@x.com")
    rt.advance(child["id"])
    assert store.get_run(rid)["status"] == "done"
    assert "tool_result_gated" not in _kinds(store, child["id"]) and "denied" in _kinds(store, child["id"])
    res = [e for e in store.audit_for_run(rid) if e["kind"] == "delegation_result"][-1]["detail"]
    assert "denied" in res["result"]


def _scripted(rt, monkeypatch, lead_replies, member_reply=None):
    """Lead calls come from lead_replies in order; member calls answer with member_reply."""
    n = {"lead": 0, "member": 0}
    lock = threading.Lock()
    def fake(system, messages, tools, model=None, **kw):
        lead = any(t["name"] == rt.DELEGATE_KEY for t in tools)
        with lock:
            if lead:
                r = lead_replies[min(n["lead"], len(lead_replies) - 1)]; n["lead"] += 1
            else:
                n["member"] += 1
        if lead:
            return {"usage": {}, "model": "fake", **(r(messages) if callable(r) else r)}
        return {"usage": {}, "model": "fake", **(member_reply or
                {"stop_reason": "end_turn", "content": [{"type": "text", "text": "member done: " + messages[0]["content"]}]})}
    monkeypatch.setattr(rt, "_call_model", fake)
    return n


def _deleg(i, member, task):
    return {"type": "tool_use", "id": "d%d" % i, "name": "team__delegate", "input": {"member": member, "task": task}}


def _results(messages):
    return {b["tool_use_id"]: json.loads(b["content"]) for m in messages if m["role"] == "user" and isinstance(m["content"], list)
            for b in m["content"] if b.get("type") == "tool_result"}


def test_parallel_hand_offs_in_one_turn_all_come_back(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    lid, _ = _team(store, rt, "t4@x.com", [("A4", "a", []), ("B4", "b", [])])
    seen = {}
    def finish(messages):
        seen.update(_results(messages))
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "all done"}]}
    _scripted(rt, monkeypatch, [{"stop_reason": "tool_use", "content": [_deleg(1, "A4", "task one"), _deleg(2, "B4", "task two")]}, finish])
    rid = store.create_run(lid, "split this")
    assert rt.advance(rid)["status"] == "done"
    assert seen["d1"] == {"member": "A4", "status": "done", "result": "member done: task one"}
    assert seen["d2"]["result"] == "member done: task two"
    assert len(store.child_runs(rid)) == 2


def test_unknown_member_and_empty_task_start_no_run(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    lid, _ = _team(store, rt, "t5@x.com", [("Real5", "r", [])])
    seen = {}
    def finish(messages):
        seen.update(_results(messages))
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}]}
    _scripted(rt, monkeypatch, [{"stop_reason": "tool_use", "content": [_deleg(1, "Nobody", "x"), _deleg(2, "Real5", "  ")]}, finish])
    rid = store.create_run(lid, "go")
    assert rt.advance(rid)["status"] == "done"
    assert seen["d1"]["error"] == "unknown_member" and "Real5" in seen["d1"]["note"]
    assert seen["d2"]["error"] == "empty_task"
    assert store.child_runs(rid) == []


def test_delegation_cap_is_enforced(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    monkeypatch.setattr(rt, "MAX_DELEGATIONS", 2)
    lid, _ = _team(store, rt, "t6@x.com", [("M6", "m", [])])
    seen = {}
    def finish(messages):
        seen.update(_results(messages))
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}]}
    _scripted(rt, monkeypatch, [{"stop_reason": "tool_use", "content": [_deleg(i, "M6", "job %d" % i) for i in range(1, 4)]}, finish])
    rid = store.create_run(lid, "lots")
    rt.advance(rid)
    assert len(store.child_runs(rid)) == 2
    assert seen["d3"]["denied"] and seen["d3"]["policy"] == "team delegation cap"
    assert any(e["kind"] == "policy_denied" and e["skill"] == rt.DELEGATE_KEY for e in store.audit_for_run(rid))


def test_members_cannot_delegate_further_and_teams_stay_within_one_owner(warden):
    store, rt = warden["store"], warden["rt"]
    sub = store.create_agent("Sub7", "s", rt.MODEL_DEFAULT, [], owner="t7@x.com")
    mid = store.create_agent("Mid7", "m", rt.MODEL_DEFAULT, [], owner="t7@x.com", members=[sub])
    other = store.create_agent("Other7", "o", rt.MODEL_DEFAULT, [], owner="someone-else@x.com")
    lid = store.create_agent("Lead7", "l", rt.MODEL_DEFAULT, [], owner="t7@x.com", members=[mid, other, "missing"])
    lead = store.get_agent(lid)
    assert [m["name"] for m in rt.members_of(lead)] == ["Mid7"], "another owner's agent and a deleted one are skipped"
    dt = next(t for t in rt.tools_for(lead, 0) if t["name"] == rt.DELEGATE_KEY)
    assert dt["input_schema"]["properties"]["member"]["enum"] == ["Mid7"]
    names = [t["name"] for t in rt.tools_for(store.get_agent(mid), depth=1)]
    assert rt.DELEGATE_KEY not in names, "a member working for a lead cannot hand work on"
    assert rt.DELEGATE_KEY in [t["name"] for t in rt.tools_for(store.get_agent(mid), depth=0)]


def test_failed_member_reaches_the_lead_as_failed(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    lid, _ = _team(store, rt, "t8@x.com", [("Broken8", "b", [])])
    seen = {}
    def finish(messages):
        seen.update(_results(messages))
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "reported"}]}
    _scripted(rt, monkeypatch, [{"stop_reason": "tool_use", "content": [_deleg(1, "Broken8", "do it")]}, finish])
    real = rt._call_model
    def fake(system, messages, tools, model=None, **kw):
        if not any(t["name"] == rt.DELEGATE_KEY for t in tools):
            raise RuntimeError("boom")
        return real(system, messages, tools, model=model, **kw)
    monkeypatch.setattr(rt, "_call_model", fake)
    rid = store.create_run(lid, "go")
    assert rt.advance(rid)["status"] == "done"
    assert seen["d1"]["status"] == "failed" and seen["d1"]["result"].startswith("[error]")
    res = [e for e in store.audit_for_run(rid) if e["kind"] == "delegation_result"][-1]["detail"]
    assert res["outcome"] == "error"


def test_lead_budget_covers_the_whole_team(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    lid, _ = _team(store, rt, "t9@x.com", [("Spender9", "s", [])], lead_budget=0.01)
    calls = {"member": 0}
    def fake(system, messages, tools, model=None, **kw):
        if any(t["name"] == rt.DELEGATE_KEY for t in tools):
            if any(m["role"] == "user" and isinstance(m["content"], list) for m in messages):
                return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "lead done"}], "usage": {}, "model": "fake"}
            return {"stop_reason": "tool_use", "content": [_deleg(1, "Spender9", "spend")], "usage": {}, "model": "fake"}
        calls["member"] += 1
        # every member step costs about $0.03 at Sonnet rates, over the lead's $0.01 cap
        return {"stop_reason": "tool_use", "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 10000, "output_tokens": 0},
                "content": [{"type": "tool_use", "id": "x%d" % calls["member"], "name": rt.REQUEST_KEY,
                             "input": {"need": "n", "keywords": "zzz-nothing"}}]}
    monkeypatch.setattr(rt, "_call_model", fake)
    rid = store.create_run(lid, "go")
    r = rt.advance(rid)
    child = store.child_runs(rid)[0]
    assert calls["member"] == 1, "the member stopped after the first step that took the team over budget"
    stop = [e for e in store.audit_for_run(child["id"]) if e["kind"] == "budget_stop"][-1]["detail"]
    assert stop["scope"] == "team" and stop["budget"] == 0.01
    assert r["status"] in ("done",) and child["status"] == "done"
