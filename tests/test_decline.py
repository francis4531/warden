"""Declining a connection request: owner or admin says no, the agent is told and carries on."""
import time
from conftest import login, K, ADMIN, BOB


def _request_run(store, rt, owner):
    aid = store.create_agent("Inbox Helper", "triage mail", rt.MODEL_DEFAULT, [K("lookup_customer")], owner=owner)
    rid = store.create_run(aid, "Go through my inbox and tell me which emails need a reply today")
    rt.advance(rid)
    reqs = [e for e in store.audit_for_run(rid) if e["kind"] == "connection_request"]
    assert reqs, "the sandbox planner should have asked for a mail source"
    return aid, rid, reqs[0]["detail"]["need"]


def _settle(store, rid, secs=6):
    for _ in range(secs * 10):
        if store.get_run(rid)["status"] in ("done", "error", "awaiting_approval"):
            return store.get_run(rid)
        time.sleep(0.1)
    return store.get_run(rid)


def test_owner_can_decline_and_agent_continues(client, warden):
    store, rt, A = warden["store"], warden["rt"], warden["app"]
    aid, rid, need = _request_run(store, rt, "dec@x.com")
    login(client, "dec@x.com")
    with A.app.test_request_context():
        assert any(not q["fulfilled"] for q in A._open_requests(rid, aid))
    r = client.post("/requests/decline", data={"run_id": rid, "need": need})
    assert r.status_code == 200 and r.get_json()["ok"]
    run = _settle(store, rid)
    ev = store.audit_for_run(rid)
    dec = [e for e in ev if e["kind"] == "connection_declined"]
    assert len(dec) == 1 and dec[0]["detail"]["by"] == "dec@x.com" and dec[0]["detail"]["role"] == "owner"
    with A.app.test_request_context():
        qs = A._open_requests(rid, aid)
        assert all(q["fulfilled"] for q in qs) and qs[0]["declined"]["by"] == "dec@x.com"
    assert run["status"] in ("done", "error")
    # the agent did not simply ask again
    assert sum(1 for e in ev if e["kind"] == "connection_request") == 1
    assert any(e["kind"] == "final" for e in ev)
    # declining twice is refused
    assert client.post("/requests/decline", data={"run_id": rid, "need": need}).status_code == 409


def test_admin_can_decline_but_not_a_stranger(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid, need = _request_run(store, rt, "own2@x.com")
    login(client, BOB)
    assert client.post("/requests/decline", data={"run_id": rid, "need": need}).status_code == 404
    login(client, ADMIN, hat="admin")
    assert client.post("/requests/decline", data={"run_id": rid, "need": need}).get_json()["ok"]
    _settle(store, rid)
    dec = [e for e in store.audit_for_run(rid) if e["kind"] == "connection_declined"]
    assert dec and dec[0]["detail"]["role"] == "admin" and dec[0]["detail"]["by"] == ADMIN
    # no new request appears on the admin's approvals page for this run
    html = client.get("/approvals").data.decode()
    assert need[:40] not in html
