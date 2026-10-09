"""Connecting from inside the conversation: the card carries the real controls, a key or one
click resumes the chat in place, and a failure brings you back to the chat with the reason."""
import time
from conftest import login, K, ADMIN


def _req_run(store, rt, owner, source_ids, need="read my email and the Stripe invoices", scratch=False):
    if scratch:
        aid = store.ensure_assistant(owner, rt.ASSISTANT_NAME, rt.ASSISTANT_INSTRUCTIONS, rt.MODEL_DEFAULT, [])
    else:
        aid = store.create_agent("Helper", "x", rt.MODEL_DEFAULT, [], owner=owner)
    rid = store.create_run(aid, "do the thing")
    store.update_run(rid, status="done", transcript=[{"role": "user", "content": "do the thing"}])
    store.audit(rid, aid, "connection_request", skill=rt.REQUEST_KEY, risk="LOW",
                detail={"need": need, "keywords": "email stripe",
                        "matches": [{"id": i, "name": i, "source": "catalog"} for i in source_ids]})
    return aid, rid


def _events(client, rid):
    return client.get("/run/%s/events" % rid).get_json()


def test_card_carries_the_real_controls_for_each_kind_of_source(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid = _req_run(store, rt, "ci1@x.com", ["google_gmail", "stripe", "deepwiki", "linear"])
    login(client, "ci1@x.com")
    d = _events(client, rid)
    cards = {m["id"]: m.get("card", "") for q in d["requests"] for m in q["matches"]}
    g = cards["google_gmail"]
    assert "/connections/oauth/start" in g and 'name="scope"' in g and 'value="read" checked' in g and "Read and write" in g
    assert 'name="grant_to" value="%s"' % aid in g and 'name="resume" value="%s"' % rid in g, "connecting grants to this agent and resumes this chat"
    s = cards["stripe"]
    assert "/connections/enable" in s and 'name="token"' in s and "dashboard.stripe.com/apikeys" in s and "connform" in s
    assert 'name="resume" value="%s"' % rid in s
    dw = cards["deepwiki"]
    assert "/connections/enable" in dw and 'name="token"' not in dw, "no credential needed: one click"
    lin = cards["linear"]
    assert "Sign in with Linear" in lin and "/connections/oauth/start" in lin


def test_an_admin_looking_in_gets_no_controls(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid = _req_run(store, rt, "ci2@x.com", ["stripe"])
    login(client, ADMIN)
    d = _events(client, rid)
    assert d["readonly"] and all("card" not in m for q in d["requests"] for m in q["matches"])


def test_a_connected_source_offers_grant_not_a_second_connect(client, warden, monkeypatch):
    store, rt, A = warden["store"], warden["rt"], warden["app"]
    aid, rid = _req_run(store, rt, "ci3@x.com", ["deepwiki"])
    key = store.conn_key("deepwiki", "ci3@x.com")
    monkeypatch.setattr(A.cm(), "connected_servers", lambda: [{"id": key, "name": "deepwiki", "status": "connected", "owner": "ci3@x.com", "catalog_id": "deepwiki"}])
    login(client, "ci3@x.com")
    m = _events(client, rid)["requests"][0]["matches"][0]
    assert m["connected"] and not m["granted"] and "card" not in m


def test_one_click_connect_grants_the_tools_and_resumes_the_chat(client, warden, monkeypatch):
    store, rt, A = warden["store"], warden["rt"], warden["app"]
    me = "ci4@x.com"
    aid, rid = _req_run(store, rt, me, ["deepwiki"], scratch=True)
    key = store.conn_key("deepwiki", me)
    cm = A.cm()
    monkeypatch.setattr(cm, "connect_spec", lambda spec: {"status": "connected", "tool_count": 1})
    monkeypatch.setattr(cm, "all_tools", lambda: [{"key": key + "__ask_question", "server_id": key, "tool": "ask_question", "description": "d",
                                                   "input_schema": {"type": "object"}, "server_name": "deepwiki", "owner": me}])
    login(client, me)
    r = client.post("/connections/enable", data={"id": "deepwiki", "grant_to": aid, "resume": rid})
    j = r.get_json()
    assert j["ok"] and j["status"] == "connected" and j["granted"] and j["resume_url"].endswith("/run/" + rid)
    assert key + "__ask_question" in store.get_agent(aid)["skills"]
    assert any(c["id"] == key and c["owner"] == me for c in store.enabled_connections(me))
    ev = store.audit_for_run(rid)
    assert any(e["kind"] == "connection_granted" for e in ev), "the grant is on the audit trail"
    tr = store.get_run(rid)["transcript"]
    assert "now connected" in tr[-1]["content"] or "now connected" in str(tr), "the agent is told to continue"
    for _ in range(60):
        if store.get_run(rid)["status"] != "running":
            break
        time.sleep(0.1)
    store.disable_connection(key)


def test_a_bad_key_leaves_no_half_connected_row_and_says_why(client, warden, monkeypatch):
    store, rt, A = warden["store"], warden["rt"], warden["app"]
    me = "ci5@x.com"
    aid, rid = _req_run(store, rt, me, ["stripe"])
    monkeypatch.setattr(A.cm(), "connect_spec", lambda spec: {"status": "error", "error": "401 invalid key"})
    login(client, me)
    j = client.post("/connections/enable", data={"id": "stripe", "token": "sk_bad", "grant_to": aid, "resume": rid}).get_json()
    assert j["ok"] and j["status"] == "error" and "401" in j["error"] and not j["granted"] and j["resume_url"] is None
    assert not [c for c in store.enabled_connections(me) if c["catalog_id"] == "stripe"]
    # without JavaScript the failure comes back to the chat, not to Connections
    login(client, me, csrf_exempt=False)
    with client.session_transaction() as sess:
        tok = sess.setdefault("csrf", "tok-ci5")
    r = client.post("/connections/enable", data={"id": "stripe", "token": "sk_bad", "grant_to": aid, "resume": rid, "csrf": tok})
    assert r.status_code == 302 and "/run/%s" % rid in r.headers["Location"] and "connect_error=" in r.headers["Location"]


def test_a_refused_sign_in_returns_to_the_conversation_with_the_reason(client, warden):
    store, rt = warden["store"], warden["rt"]
    me = "ci6@x.com"
    aid, rid = _req_run(store, rt, me, ["google_gmail"])
    login(client, me)
    with client.session_transaction() as s:
        s["conn_oauth"] = {"state": "abc", "cid": "google_gmail", "grant_to": aid, "resume": rid, "personal": True}
    r = client.get("/connections/oauth/google/callback?state=abc&error=access_denied")
    assert r.status_code == 302 and "/run/%s" % rid in r.headers["Location"] and "access_denied" in r.headers["Location"]
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "That did not connect." in page and "access_denied" in page
    # someone else's conversation id is never a place to send a person
    login(client, "ci7@x.com")
    with client.session_transaction() as s:
        s["conn_oauth"] = {"state": "abc", "cid": "google_gmail", "grant_to": aid, "resume": rid, "personal": True}
    r = client.get("/connections/oauth/google/callback?state=abc&error=access_denied")
    assert r.status_code == 302 and "/connections" in r.headers["Location"] and "/run/" not in r.headers["Location"]


def test_the_error_banner_is_escaped(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid, rid = _req_run(store, rt, "ci8@x.com", ["stripe"])
    login(client, "ci8@x.com")
    page = client.get("/run/%s?connect_error=%%3Cscript%%3Ealert(1)%%3C/script%%3E" % rid).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_needs_you_and_connections_send_you_to_the_chat(client, warden):
    store, rt = warden["store"], warden["rt"]
    me = "ci9@x.com"
    aid, rid = _req_run(store, rt, me, ["google_gmail"], scratch=True)
    login(client, me)
    home = client.get("/app").get_data(as_text=True)
    assert "Your quick chat needs" in home and 'href="/run/%s"' % rid in home and "Connect in the chat" in home
    conns = client.get("/connections").get_data(as_text=True)
    assert "connect it in the conversation" in conns and "/connections?connect=" not in conns.split("Your connections")[0]


def test_the_agent_is_told_the_card_does_it_in_the_conversation(warden):
    rt = warden["rt"]
    ag = {"name": "X", "skills": []}
    text = rt.situational_context(ag, [], {})
    assert "right there, in the conversation" in text and "Needs you" in text and "left navigation" not in text
