"""The agent builder: pages render for users and admins, the form round-trips, the connect
panel is per user."""
from conftest import login, K, ADMIN, BOB


def test_builder_renders_for_user_and_admin(client, warden):
    login(client, BOB)
    html = client.get("/new/advanced").data.decode()
    assert "What it can touch" in html and 'name="skills"' in html and "Start from" in html
    assert "@playwright/mcp" not in html, "stdio servers are not offered to users"
    assert "Search the MCP Registry" not in html
    login(client, ADMIN, hat="agents")
    html = client.get("/new/advanced").data.decode()
    assert "Search the MCP Registry" in html and "@playwright/mcp" in html


def test_connlist_is_per_user(client, warden):
    store = warden["store"]
    store.enable_connection("deepwiki", "http", url="https://mcp.deepwiki.com/mcp", owner="other@x.com", connected_by="other@x.com", credential="none")
    login(client, BOB)
    html = client.get("/connlist").data.decode()
    assert html.count('data-id="deepwiki"') == 1
    assert "Disconnect" not in html.split('data-id="deepwiki"')[1].split("</div>\n</div>")[0], "another user's connection is not yours to disconnect"


def test_create_and_edit_round_trip(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "build@x.com")
    r = client.post("/agents", data={"name": "Triage", "instructions": "triage things", "budget_usd": "$0.75",
                                     "skills": [K("lookup_customer"), K("issue_refund")], "model": ""})
    assert r.status_code == 302
    aid = r.headers["Location"].rstrip("/").split("/")[-1]
    ag = store.get_agent(aid)
    assert ag["budget_usd"] == 0.75 and set(ag["skills"]) == {K("lookup_customer"), K("issue_refund")}
    assert ag["model"] == rt.MODEL_DEFAULT
    html = client.get("/agent/%s/edit" % aid).data.decode()
    assert 'value="Triage"' in html and 'value="0.75"' in html
    r = client.post("/agent/%s/update" % aid, data={"name": "Triage v2", "instructions": "x", "budget_usd": "nonsense",
                                                     "skills": [K("lookup_customer")], "model": "claude-haiku-4-5"})
    assert r.status_code == 302
    ag = store.get_agent(aid)
    assert ag["name"] == "Triage v2" and ag["budget_usd"] == 0 and ag["skills"] == [K("lookup_customer")] and ag["model"] == "claude-haiku-4-5"


def test_team_template_creates_members(client, warden):
    store = warden["store"]
    login(client, "team@x.com")
    r = client.post("/agents", data={"name": "Billing Desk", "instructions": "lead", "template": "billing_desk",
                                     "skills": [K("lookup_customer")]})
    aid = r.headers["Location"].rstrip("/").split("/")[-1]
    ag = store.get_agent(aid)
    assert len(ag.get("members") or []) == 2
    for mid in ag["members"]:
        assert store.get_agent(mid)["owner"] == "team@x.com"


def test_agent_page_owner_and_admin_views(client, warden):
    from conftest import login, ADMIN
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("Page Check", "Read things and answer.", "", [], owner="pc@x.com")
    rid = store.create_run(aid, "first question"); store.update_run(rid, status="done")
    login(client, "pc@x.com")
    h = client.get("/agent/%s" % aid).get_data(as_text=True)
    assert "Start a conversation" in h and "Delete" in h and "Waiting on you" in h and "first question" in h
    login(client, ADMIN, hat="admin")
    h = client.get("/agent/%s" % aid).get_data(as_text=True)
    assert "Admin view, read-only" in h and "Start a conversation" not in h and "pc@x.com" in h
    assert 'action="/agent/%s/delete"' % aid not in h


def test_reference_servers_are_gone_and_sample_is_sandbox_only(warden, monkeypatch):
    import catalog
    ids = {c["id"] for c in catalog.CATALOG}
    assert not ids & {"fetch", "filesystem", "git", "memory"}
    assert catalog.sample_on()                               # tests run in sandbox
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert not catalog.sample_on()                           # live: no sample server
    monkeypatch.setenv("WARDEN_SAMPLE_TOOLS", "1")
    assert catalog.sample_on()                               # unless asked for


def test_live_templates_are_real_systems(client, warden, monkeypatch):
    import catalog
    A = warden["app"]
    login(client, "tpl@x.com")
    monkeypatch.setattr(catalog, "sample_on", lambda: False)
    html = client.get("/new/advanced").data.decode()
    assert "Billing Resolver (Stripe)" in html and "Ticket Triage (Linear)" in html
    assert "Refund Auditor (read-only)" not in html          # sample-only template hidden
    for t in A.AGENT_TEMPLATES:
        if not t.get("sample"):
            assert "builtin_enterprise" not in t["servers"] and "fetch" not in t["servers"]


def test_retire_reference_tools_strips_grants(warden, monkeypatch):
    import catalog
    A, store, rt = warden["app"], warden["store"], warden["rt"]
    aid = store.create_agent("Mixed", "x", rt.MODEL_DEFAULT,
                             [K("lookup_customer"), "fetch~abcd1234__fetch", "deepwiki__ask_question"], owner="mix@x.com")
    monkeypatch.setattr(catalog, "sample_on", lambda: False)
    changed = A._retire_reference_tools()
    assert changed.get("Mixed") == 2
    assert store.get_agent(aid)["skills"] == ["deepwiki__ask_question"]
    assert any(e["kind"] == "reference_tools_retired" for e in store.audit_all(20))
    assert store.verify_audit()["ok"]
