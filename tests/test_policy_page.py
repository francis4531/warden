"""Policies in plain language: a sentence becomes one rule, rules read back as sentences."""
from conftest import login, K, ADMIN, BOB


def test_policies_page_is_admin_only_and_reads_back_as_sentences(client, warden):
    store = warden["store"]
    pid = store.create_policy("cap", "require_approval", tool="issue_refund", field="amount", op=">", value="500", priority=100)
    login(client, BOB)
    assert client.get("/policies").status_code in (302, 403)
    login(client, ADMIN, hat="admin")
    html = client.get("/policies").data.decode()
    assert "issue refund asks a human first, when amount is over 500" in html
    assert "Draft the rule" in html and "Advanced: write a rule field by field" in html
    store.delete_policy(pid)


def test_draft_endpoint_turns_sentences_into_rules(client, warden):
    login(client, ADMIN, hat="admin")
    d = client.post("/policies/draft", data={"sentence": "Require approval for refunds over $500"}).get_json()
    assert (d["tool"], d["field"], d["op"], d["value"], d["effect"]) == ("issue_refund", "amount", ">", "500", "require_approval")
    assert d["summary"].startswith("Any agent: issue refund asks a human first")
    d = client.post("/policies/draft", data={"sentence": "No more than 3 refunds in one conversation"}).get_json()
    assert (d["field"], d["op"], d["value"], d["effect"]) == ("__count__", ">=", "4", "deny")
    d = client.post("/policies/draft", data={"sentence": "Auto-run refunds under $100"}).get_json()
    assert (d["field"], d["op"], d["value"], d["effect"]) == ("amount", "<=", "100", "allow")
    d = client.post("/policies/draft", data={"sentence": "Block any high-risk action at the weekend"}).get_json()
    assert d["effect"] == "deny" and d["tool"] == "*" and d["field"] == "__risk__"
    assert client.post("/policies/draft", data={"sentence": "no"}).status_code == 400
    login(client, BOB)
    assert client.post("/policies/draft", data={"sentence": "Require approval for refunds over $500"}).status_code == 403


def test_drafted_rule_names_an_agent_and_is_enforced(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("Night Desk", "x", rt.MODEL_DEFAULT, [K("issue_refund")], owner="n@x.com")
    login(client, ADMIN, hat="admin")
    d = client.post("/policies/draft", data={"sentence": "Never let Night Desk issue a refund"}).get_json()
    assert d["agent_id"] == aid and d["tool"] == "issue_refund" and d["effect"] == "deny"
    r = client.post("/policies/create", data={k: d[k] for k in ("name", "agent_id", "tool", "field", "op", "value", "effect", "priority")})
    assert r.status_code == 302
    assert rt.decide("r", aid, K("issue_refund"), {"amount": 5}, rt.tool_index())["effect"] == "deny"
    other = store.create_agent("Day Desk", "x", rt.MODEL_DEFAULT, [K("issue_refund")], owner="n@x.com")
    assert rt.decide("r", other, K("issue_refund"), {"amount": 5}, rt.tool_index())["effect"] == "gate"
    for p in store.list_policies():
        if p["agent_id"] == aid: store.delete_policy(p["id"])
