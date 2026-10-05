"""The governance promises, each as a test that failed before v0.16."""
import json, time
from conftest import login, K, ADMIN, ALICE, BOB


def _billing_agent(store, rt, owner):
    return store.create_agent("Billing " + owner, "resolve billing", rt.MODEL_DEFAULT,
                              [K("lookup_customer"), K("search_knowledge"), K("issue_refund"), K("create_ticket")],
                              owner=owner)


def _paused_refund(store, rt, owner, acct="AC-1001"):
    aid = _billing_agent(store, rt, owner)
    rid = store.create_run(aid, "Customer %s was charged twice, refund them" % acct)
    r = rt.advance(rid)
    assert r["status"] == "awaiting_approval"
    aps = [a for a in store.approvals_for_run(rid) if a["status"] == "pending"]
    assert len(aps) == 1 and aps[0]["skill"] == K("issue_refund")
    return aid, rid, aps[0]


def _wait(store, rid, until=("done", "error", "awaiting_approval"), secs=5):
    for _ in range(secs * 10):
        if store.get_run(rid)["status"] in until:
            return store.get_run(rid)
        time.sleep(0.1)
    return store.get_run(rid)


# ---- 1. admin overrides reach every user's copy of a catalog server ----
def test_override_applies_to_user_connections(warden):
    store, rt = warden["store"], warden["rt"]
    store.set_override("google_gmail__search", "HIGH")
    key = store.conn_key("google_gmail", BOB) + "__search"
    assert rt.override_key(key) == "google_gmail__search"
    assert rt.risk_for(key)["risk"] == "HIGH"
    store.set_override("builtin_enterprise__search_knowledge", "HIGH")
    assert rt.risk_for(K("search_knowledge"))["gate"] == "approval"
    # cleanup so other tests see defaults
    store.set_override("builtin_enterprise__search_knowledge", "LOW")


def test_tool_risk_route_validates(client, warden):
    login(client, ADMIN, hat="admin")
    assert client.post("/tool-risk", data={"key": "nonsense", "risk": "HIGH"}).status_code == 400
    assert client.post("/tool-risk", data={"key": "x__y", "risk": "WHATEVER"}).status_code == 400
    r = client.post("/tool-risk", data={"key": "google_gmail__send", "risk": "high"})
    assert r.status_code == 302
    assert warden["store"].get_override("google_gmail__send") == "HIGH"


# ---- 3. a pending hold stays a hold whatever changes underneath it ----
def test_hold_survives_risk_change(warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid, ap = _paused_refund(store, rt, "hold@x.com")
    store.set_override("builtin_enterprise__issue_refund", "LOW")
    try:
        r = rt.advance(rid)
        assert r["status"] == "awaiting_approval", "lowering the tier must not execute a held call"
        assert store.get_approval(ap["id"])["status"] == "pending"
        kinds = [e["kind"] for e in store.audit_for_run(rid)]
        assert "tool_result" not in [e["kind"] for e in store.audit_for_run(rid) if e["skill"] == K("issue_refund")]
    finally:
        store.set_override("builtin_enterprise__issue_refund", "HIGH")


# ---- 4. what the approver saw is what runs ----
def test_approval_executes_snapshot_not_transcript(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid, ap = _paused_refund(store, rt, "snap@x.com", acct="AC-1002")
    run = store.get_run(rid); tr = run["transcript"]
    for m in tr:
        if m["role"] == "assistant":
            for b in m["content"]:
                if b.get("type") == "tool_use" and b["name"] == K("issue_refund"):
                    b["input"]["amount"] = 999999
    store.update_run(rid, transcript=tr)
    login(client, "snap@x.com")
    r = client.post("/approval/" + ap["id"], data={"decision": "approved"}, headers={"X-Requested-With": "fetch"})
    assert r.status_code == 200
    _wait(store, rid, until=("done", "error"))
    ev = store.audit_for_run(rid)
    assert any(e["kind"] == "approval_mismatch" for e in ev)
    assert not any(e["kind"] == "tool_result_gated" and e["skill"] == K("issue_refund") for e in ev)


# ---- 5. decisions are evidence: on the chain, once ----
def test_decision_is_audited_and_final(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid, ap = _paused_refund(store, rt, "once@x.com", acct="AC-1003")
    login(client, "once@x.com")
    r = client.post("/approval/" + ap["id"], data={"decision": "approved"}, headers={"X-Requested-With": "fetch"})
    assert r.status_code == 200
    _wait(store, rid, until=("done", "error"))
    ev = store.audit_for_run(rid)
    dec = [e for e in ev if e["kind"] == "approval_decided"]
    assert len(dec) == 1 and dec[0]["detail"]["decision"] == "approved" and dec[0]["detail"]["by"] == "once@x.com"
    assert any(e["kind"] == "tool_result_gated" and e["skill"] == K("issue_refund") for e in ev)
    calls_before = sum(1 for e in ev if e["kind"] == "model_call")
    # flipping it afterwards is refused and does not re-advance the run
    r = client.post("/approval/" + ap["id"], data={"decision": "denied"}, headers={"X-Requested-With": "fetch"})
    assert r.status_code == 409
    time.sleep(0.5)
    assert store.get_approval(ap["id"])["status"] == "approved"
    assert sum(1 for e in store.audit_for_run(rid) if e["kind"] == "model_call") == calls_before
    assert store.verify_audit()["ok"]


def test_deny_is_audited(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid, ap = _paused_refund(store, rt, "deny@x.com", acct="AC-1004")
    login(client, "deny@x.com")
    assert client.post("/approval/" + ap["id"], data={"decision": "denied"}, headers={"X-Requested-With": "fetch"}).status_code == 200
    _wait(store, rid, until=("done", "error"))
    ev = store.audit_for_run(rid)
    assert any(e["kind"] == "approval_decided" and e["detail"]["decision"] == "denied" for e in ev)
    assert any(e["kind"] == "denied" for e in ev)
    assert not any(e["kind"] == "tool_result_gated" for e in ev)


# ---- 6. admins see everything and act on nothing ----
def test_admin_cannot_approve_grant_or_disconnect(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid, ap = _paused_refund(store, rt, ALICE, acct="AC-1005")
    login(client, ADMIN, hat="admin")
    assert client.post("/approval/" + ap["id"], data={"decision": "approved"}).status_code == 404
    assert client.post("/connections/grant", data={"id": "builtin_enterprise", "grant_to": aid, "resume": rid}).status_code == 403
    # a personal connection row belonging to alice
    cid = store.enable_connection("deepwiki", "http", url="https://mcp.deepwiki.com/mcp",
                                  owner=ALICE, connected_by=ALICE, credential="none") or store.conn_key("deepwiki", ALICE)
    assert client.post("/connections/disable", data={"id": cid}).status_code == 403
    assert store.get_connection(cid) is not None
    assert store.get_approval(ap["id"])["status"] == "pending"
    skills_before = store.get_agent(aid)["skills"]
    assert K("issue_refund") in skills_before
