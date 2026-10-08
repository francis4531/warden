"""The agent builder: pages render for users and admins, the form round-trips, the connect
panel is per user."""
from conftest import login, K, ADMIN, BOB


def test_builder_renders_for_user_and_admin(client, warden):
    login(client, BOB)
    html = client.get("/new/advanced").data.decode()
    assert "What it can touch" in html and 'name="skills"' in html and "Start from" in html
    assert "mcp-server-fetch" not in html, "stdio servers are not offered to users"
    assert "Search the MCP Registry" not in html
    login(client, ADMIN, hat="agents")
    html = client.get("/new/advanced").data.decode()
    assert "Search the MCP Registry" in html and "mcp-server-fetch" in html


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
