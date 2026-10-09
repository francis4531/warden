"""Chat first: say what you need with no agent set up, then keep a good chat as an agent."""
import io, time
from conftest import login, K, ADMIN


def _wait(store, rid, until=("done", "error", "awaiting_approval"), secs=6):
    end = time.time() + secs
    while time.time() < end:
        r = store.get_run(rid)
        if r["status"] in until:
            return r
        time.sleep(0.1)
    return store.get_run(rid)


def _rid(resp):
    return resp.headers["Location"].rstrip("/").split("/")[-1]


def _chat(client, text="Find the customer Acme and tell me their plan", **extra):
    return client.post("/chat/start", data={"input": text, **extra}, content_type="multipart/form-data")


def test_home_opens_on_the_chat_box(client, warden):
    login(client, "home1@x.com")
    html = client.get("/app").get_data(as_text=True)
    assert "What do you need done?" in html and 'action="/chat/start"' in html and 'name="files"' in html
    assert "No agents yet, and you do not need one to start" in html
    assert "Welcome" not in html and "Connect what it needs" not in html


def test_chat_start_uses_a_hidden_assistant_that_is_reused(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "qc1@x.com")
    r1 = _chat(client)
    assert r1.status_code == 302
    rid1 = _rid(r1)
    run1 = _wait(store, rid1)
    ag = store.get_agent(run1["agent_id"])
    assert ag["scratch"] == 1 and ag["owner"] == "qc1@x.com" and ag["name"] == rt.ASSISTANT_NAME
    assert store.list_agents("qc1@x.com") == [], "the assistant is never listed as one of the person's agents"
    assert [a["id"] for a in store.list_agents("qc1@x.com", include_scratch=True)] == [ag["id"]]
    rid2 = _rid(_chat(client, "And what about Globex?"))
    assert store.get_run(rid2)["agent_id"] == ag["id"], "one assistant per person"
    html = client.get("/app").get_data(as_text=True)
    assert "No agents yet" in html, "quick chats do not turn into rows in the agent table"
    assert "Quick chat" in html and "Find the customer Acme" in html, "but they are in Recent"


def test_assistant_holds_the_persons_connected_tools(client, warden):
    store = warden["store"]
    login(client, "qc2@x.com")
    run = _wait(store, _rid(_chat(client)))
    ag = store.get_agent(run["agent_id"])
    assert K("lookup_customer") in ag["skills"] and K("issue_refund") in ag["skills"]


def test_quick_chat_reads_freely_but_asks_before_changing_anything(warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.ensure_assistant("qc3@x.com", rt.ASSISTANT_NAME, rt.ASSISTANT_INSTRUCTIONS, rt.MODEL_DEFAULT,
                                 [K("lookup_customer"), K("create_ticket"), K("issue_refund")])
    rid = store.create_run(aid, "x")
    assert rt.decide(rid, aid, K("lookup_customer"), {})["effect"] == "allow"
    d = rt.decide(rid, aid, K("create_ticket"), {"title": "t"})
    assert d["effect"] == "gate" and d["policy"] == rt.QUICK_CHAT_RULE, "a MED write that runs freely in an agent is held in a quick chat"
    assert rt.decide(rid, aid, K("issue_refund"), {"amount": 5})["effect"] == "gate"
    # the same tool in an ordinary agent is unchanged
    ag2 = store.create_agent("Plain", "x", rt.MODEL_DEFAULT, [K("create_ticket")], owner="qc3@x.com")
    assert rt.decide(store.create_run(ag2, "x"), ag2, K("create_ticket"), {"title": "t"})["effect"] == "allow"


def test_a_quick_chat_write_is_held_for_approval_end_to_end(client, warden):
    store = warden["store"]
    login(client, "qc4@x.com")
    run = _wait(store, _rid(_chat(client, "Open a support ticket titled printer broken")))
    held = [a for a in store.approvals_for_run(run["id"]) if a["status"] == "pending"]
    if held:        # the sandbox planner chose to write: it must not have executed
        assert run["status"] == "awaiting_approval"
        assert not [e for e in store.audit_for_run(run["id"]) if e["kind"] == "tool_result" and "create_ticket" in (e["skill"] or "")]


def test_other_people_cannot_open_or_keep_my_chat(client, warden):
    store = warden["store"]
    login(client, "qc5@x.com")
    rid = _rid(_chat(client))
    _wait(store, rid)
    login(client, "qc6@x.com")
    assert client.get("/run/%s/keep" % rid).status_code == 404
    assert client.post("/run/%s/keep/draft" % rid).status_code == 404
    assert client.post("/agents/simple", data={"name": "Steal", "instructions": "x", "from_run": rid}).status_code == 404
    login(client, ADMIN)           # an admin may look read-only, never keep on someone's behalf
    assert client.get("/run/%s" % rid).status_code == 200
    assert client.get("/run/%s/keep" % rid).status_code == 404


def test_keep_draft_uses_the_tools_the_chat_used(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "keep1@x.com")
    aid = store.ensure_assistant("keep1@x.com", rt.ASSISTANT_NAME, rt.ASSISTANT_INSTRUCTIONS, rt.MODEL_DEFAULT,
                                 [K("lookup_customer"), K("create_ticket"), K("search_knowledge")])
    rid = store.create_run(aid, "Look up Acme and open a ticket if they are overdue")
    store.update_run(rid, status="done", transcript=[
        {"role": "user", "content": "Look up Acme and open a ticket if they are overdue"},
        {"role": "assistant", "content": [{"type": "text", "text": "Acme is overdue by 12 days."}]}])
    store.audit(rid, aid, "tool_result", skill=K("lookup_customer"), risk="LOW", detail={"input": {}, "result": {}, "outcome": "ok"})
    store.audit(rid, aid, "approval_request", skill=K("create_ticket"), risk="MED", detail={"input": {"title": "overdue"}})
    d = client.post("/run/%s/keep/draft" % rid).get_json()
    keys = [t["key"] for t in d["tools"]]
    assert keys == [K("lookup_customer"), K("create_ticket")], "exactly the tools used, in the order used"
    assert d["name"] and d["instructions"] and d["sandbox"] is True
    assert K("search_knowledge") not in keys, "an unused connected tool is not kept"


def test_keep_saves_an_agent_with_the_task_ready_to_run(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "keep2@x.com")
    aid = store.ensure_assistant("keep2@x.com", rt.ASSISTANT_NAME, rt.ASSISTANT_INSTRUCTIONS, rt.MODEL_DEFAULT,
                                 [K("lookup_customer"), K("create_ticket")])
    rid = store.create_run(aid, "Check Acme's plan & open a ticket <if> overdue")
    store.update_run(rid, status="done", transcript=[{"role": "user", "content": "x"}])
    page = client.get("/run/%s/keep" % rid)
    assert page.status_code == 200 and "Turn this chat into an agent" in page.get_data(as_text=True)
    r = client.post("/agents/simple", data={"name": "Account Checker", "instructions": "Check plans.", "from_run": rid,
                                            "skills": [K("lookup_customer"), K("create_ticket"), "bogus__tool"],
                                            "stance__" + K("create_ticket"): "ask"})
    assert r.status_code == 302 and "/agent/" in r.headers["Location"] and "task=" in r.headers["Location"]
    new = [a for a in store.list_agents("keep2@x.com")]
    assert len(new) == 1 and new[0]["name"] == "Account Checker" and not new[0]["scratch"]
    assert new[0]["skills"] == [K("lookup_customer"), K("create_ticket")], "unknown tool keys are dropped"
    assert any(p["agent_id"] == new[0]["id"] and p["effect"] == "require_approval" for p in store.list_policies())
    created = [e for e in store.audit_all(300) if e["kind"] == "agent_created" and e["agent_id"] == new[0]["id"]]
    assert created and created[0]["detail"]["how"] == "kept_from_chat" and created[0]["detail"]["from_run"] == rid
    html = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "Kept from your quick chat" in html and "Check Acme&#39;s plan &amp; open a ticket &lt;if&gt; overdue" in html, "prefilled and escaped"
    # the assistant is untouched and still hidden
    assert store.get_agent(aid)["scratch"] == 1 and len(store.list_agents("keep2@x.com")) == 1


def test_keep_on_an_ordinary_conversation_goes_back_to_it(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "keep3@x.com")
    aid = store.create_agent("Ordinary", "x", rt.MODEL_DEFAULT, [], owner="keep3@x.com")
    rid = store.create_run(aid, "hello")
    r = client.get("/run/%s/keep" % rid)
    assert r.status_code == 302 and r.headers["Location"].endswith("/run/%s" % rid)
    assert client.post("/run/%s/keep/draft" % rid).status_code == 400
    # from_run pointing at an ordinary conversation is ignored, not an escape hatch
    r = client.post("/agents/simple", data={"name": "Plain Copy", "instructions": "x", "from_run": rid})
    assert r.status_code == 302 and "task=" not in r.headers["Location"]


def test_run_page_for_a_quick_chat_offers_keep_and_hides_the_agent_link(client, warden):
    store = warden["store"]
    login(client, "keep4@x.com")
    rid = _rid(_chat(client))
    _wait(store, rid)
    html = client.get("/run/%s" % rid).get_data(as_text=True)
    assert "Quick chat" in html and 'id="keepbar"' in html and "/keep" in html
    assert "/agent/ag-" not in html, "no link into the hidden assistant's agent page"
    aid = store.create_agent("Normal", "x", warden["rt"].MODEL_DEFAULT, [], owner="keep4@x.com")
    rid2 = store.create_run(aid, "hi")
    assert 'id="keepbar"' not in client.get("/run/%s" % rid2).get_data(as_text=True)


def test_chat_with_a_file_and_file_only(client, warden):
    store = warden["store"]
    login(client, "qc7@x.com")
    r = client.post("/chat/start", data={"input": "", "files": (io.BytesIO(b"region,amount\nwest,42\n"), "sales.csv")}, content_type="multipart/form-data")
    assert r.status_code == 302
    run = store.get_run(_rid(r))
    first = run["transcript"][0]
    assert isinstance(first["content"], list) and any("west,42" in b.get("text", "") for b in first["content"])
    assert client.post("/chat/start", data={"input": ""}, content_type="multipart/form-data").status_code == 400


def test_quick_chats_count_toward_totals_and_admin_sees_them_without_agents(client, warden):
    store, A = warden["store"], warden["app"]
    login(client, "qc8@x.com")
    rid = _rid(_chat(client))
    _wait(store, rid)
    rows = A._agent_rows("qc8@x.com", include_scratch=True)
    assert len(rows) == 1 and rows[0]["scratch"] == 1 and rows[0]["runs"] == 1
    assert A._agent_rows("qc8@x.com") == []
    with A.app.test_request_context():
        people, totals = A._studio_summary()
    me = next(p for p in people if p["email"] == "qc8@x.com")
    assert me["agents"] == [] and me["runs"] >= 1, "the studio sees the activity but not a fake agent"


def test_assistant_follows_connections_and_survives_retirement(client, warden):
    store, rt, A = warden["store"], warden["rt"], warden["app"]
    login(client, "qc9@x.com")
    _wait(store, _rid(_chat(client)))
    ag = store.list_agents("qc9@x.com", include_scratch=True)[0]
    store.update_agent(ag["id"], ag["name"], ag["instructions"], ag["model"], ag["skills"] + ["fetch__fetch", "stale__tool"])
    A._retire_reference_tools()          # runs at boot: strips grants to retired servers, scratch agents included
    after = store.get_agent(ag["id"])
    assert "fetch__fetch" not in after["skills"] and "stale__tool" in after["skills"]
    _wait(store, _rid(_chat(client, "again")))
    assert "stale__tool" not in store.get_agent(ag["id"])["skills"], "the next chat re-syncs grants to what is really connected"
    assert len(store.list_agents("qc9@x.com", include_scratch=True)) == 1
