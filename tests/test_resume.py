"""Conversations interrupted by a deploy or restart are picked up again at boot, without
running a call that may already have changed something a second time."""
import json
from conftest import K


def _interrupted(store, rt, name, skills, task, transcript, owner):
    aid = store.create_agent(name, "x", rt.MODEL_DEFAULT, skills, owner=owner)
    rid = store.create_run(aid, task)
    store.audit(rid, aid, "run_started", detail={"input": task})
    store.update_run(rid, status="running", transcript=transcript)
    return aid, rid


def _kinds(store, rid):
    return [e["kind"] for e in store.audit_for_run(rid)]


def test_run_stopped_mid_model_call_is_resumed(warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid = _interrupted(store, rt, "R1", [], "hello", [{"role": "user", "content": "hello"}], "r1@x.com")
    resumed, failed = rt.recover_interrupted(background=False)
    assert rid in resumed and rid not in failed
    r = store.get_run(rid)
    assert r["status"] == "done" and "resumed" in _kinds(store, rid) and "final" in _kinds(store, rid)
    assert not any(e["kind"] == "error" for e in store.audit_for_run(rid))


def test_interrupted_read_is_run_again(warden):
    store, rt = warden["store"], warden["rt"]
    call = {"type": "tool_use", "id": "sbx_" + K("lookup_customer"), "name": K("lookup_customer"), "input": {"account_id": "AC-1001"}}
    aid, rid = _interrupted(store, rt, "R2", [K("lookup_customer")], "Look up AC-1001",
                            [{"role": "user", "content": "Look up AC-1001"}, {"role": "assistant", "content": [call]}], "r2@x.com")
    rt.recover_interrupted(background=False)
    r = store.get_run(rid)
    assert r["status"] == "done"
    assert [e["detail"]["how"] for e in store.audit_for_run(rid) if e["kind"] == "resumed"] == ["rerun"]
    assert _kinds(store, rid).count("tool_result") == 1, "the read ran (once) after the restart"


def test_interrupted_write_is_not_run_again(warden):
    store, rt = warden["store"], warden["rt"]
    call = {"type": "tool_use", "id": "w1", "name": K("create_ticket"), "input": {"subject": "x", "body": "y"}}
    aid, rid = _interrupted(store, rt, "R3", [K("create_ticket")], "open a ticket",
                            [{"role": "user", "content": "open a ticket"}, {"role": "assistant", "content": [call]}], "r3@x.com")
    rt.recover_interrupted(background=False)
    r = store.get_run(rid)
    assert r["status"] == "done"
    assert "tool_result" not in _kinds(store, rid), "a write that may have happened is never repeated"
    answer = r["transcript"][2]["content"][0]
    assert answer["tool_use_id"] == "w1" and "may or may not have taken effect" in answer["content"]
    assert [e["detail"]["how"] for e in store.audit_for_run(rid) if e["kind"] == "resumed"] == ["answered"]


def test_write_that_finished_before_the_restart_keeps_its_recorded_result(warden):
    store, rt = warden["store"], warden["rt"]
    w = {"type": "tool_use", "id": "w2", "name": K("create_ticket"), "input": {"subject": "x"}}
    rd = {"type": "tool_use", "id": "r2", "name": K("lookup_customer"), "input": {"account_id": "AC-1001"}}
    aid, rid = _interrupted(store, rt, "R4", [K("create_ticket"), K("lookup_customer")], "ticket and lookup",
                            [{"role": "user", "content": "ticket and lookup"}, {"role": "assistant", "content": [w, rd]}], "r4@x.com")
    # the write finished and was audited, then the process died before the turn was saved
    store.audit(rid, aid, "tool_result", skill=K("create_ticket"), risk="MED",
                detail={"input": w["input"], "result": {"ticket": "T-77"}, "tool_use_id": "w2", "outcome": "ok"})
    rt.recover_interrupted(background=False)
    r = store.get_run(rid)
    answers = {b["tool_use_id"]: b["content"] for b in r["transcript"][2]["content"]}
    assert "T-77" in answers["w2"], "the recorded result is handed back"
    assert "call it again" in answers["r2"], "the unfinished read is reported, not silently dropped"
    assert _kinds(store, rid).count("tool_result") == 1 and r["status"] == "done"


def test_resumes_stop_after_repeated_restarts(warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid = _interrupted(store, rt, "R5", [], "hello", [{"role": "user", "content": "hello"}], "r5@x.com")
    for _ in range(rt.MAX_RESUMES):
        store.audit(rid, aid, "resumed", detail={"how": "model", "text": "x"})
    resumed, failed = rt.recover_interrupted(background=False)
    assert rid in failed and store.get_run(rid)["status"] == "error"
    assert "times in a row" in [e for e in store.audit_for_run(rid) if e["kind"] == "error"][-1]["detail"]["text"]
    # a new message from the user starts a fresh count
    store.audit(rid, aid, "user_message", detail={"text": "again"})
    tr = store.get_run(rid)["transcript"]; tr.append({"role": "user", "content": "again"})
    store.update_run(rid, status="running", transcript=tr)
    resumed, failed = rt.recover_interrupted(background=False)
    assert rid in resumed and store.get_run(rid)["status"] == "done"


def test_team_lead_and_member_are_resumed_together(warden):
    store, rt = warden["store"], warden["rt"]
    owner = "r6@x.com"
    mid = store.create_agent("Ticketer", "opens tickets", rt.MODEL_DEFAULT, [K("create_ticket")], owner=owner)
    lid = store.create_agent("Lead6", "leads", rt.MODEL_DEFAULT, [], owner=owner, members=[mid])
    lrid = store.create_run(lid, "open a ticket")
    store.audit(lrid, lid, "run_started", detail={"input": "open a ticket"})
    deleg = {"type": "tool_use", "id": "sbx_del_0", "name": rt.DELEGATE_KEY, "input": {"member": "Ticketer", "task": "open a ticket"}}
    store.update_run(lrid, status="running", transcript=[{"role": "user", "content": "open a ticket"},
                                                          {"role": "assistant", "content": [deleg]}])
    crid = store.create_run(mid, "open a ticket", parent_run_id=lrid, parent_tool_use_id="sbx_del_0", depth=1)
    w = {"type": "tool_use", "id": "w6", "name": K("create_ticket"), "input": {"subject": "x"}}
    store.update_run(crid, status="running", transcript=[{"role": "user", "content": "open a ticket"},
                                                         {"role": "assistant", "content": [w]}])
    resumed, failed = rt.recover_interrupted(background=False)
    assert set(resumed) >= {lrid, crid} and not failed
    assert store.get_run(crid)["status"] == "done" and store.get_run(lrid)["status"] == "done"
    assert "tool_result" not in _kinds(store, crid), "the member's interrupted write was not repeated"
    assert "delegation_result" in _kinds(store, lrid) and len(store.child_runs(lrid)) == 1, "no second hand-off"
