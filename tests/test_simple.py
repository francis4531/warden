"""The simple builder: one sentence to an agent, stances to policies, first task to a run."""
import time
from conftest import login, K, BOB


def test_new_is_simple_and_advanced_still_exists(client):
    login(client, BOB)
    assert "What should it do for you?" in client.get("/new").data.decode()
    assert "What it can touch" in client.get("/new/advanced").data.decode()


def test_draft_returns_a_card(client, warden):
    login(client, BOB)
    r = client.post("/draft", data={"sentence": "Handle refund requests from customers who were charged twice"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["name"] and d["instructions"] and d["summary"].endswith(".")
    keys = {t["key"] for t in d["tools"]}
    assert K("lookup_customer") in keys and K("issue_refund") in keys
    assert any(t["gate"] == "approval" for t in d["tools"])
    assert all(n["id"] for n in d["needs"]) and len(d["needs"]) <= 2
    assert client.post("/draft", data={"sentence": "hi"}).status_code == 400


def test_draft_names_sources_the_sentence_mentions(client):
    login(client, BOB)
    d = client.post("/draft", data={"sentence": "Go through my inbox each morning and tell me what needs a reply"}).get_json()
    assert any(n["id"] == "google_gmail" for n in d["needs"])
    assert all(n["url"].startswith("/connections?connect=") for n in d["needs"])


def test_create_simple_with_stances_and_first_task(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "simple@x.com")
    r = client.post("/agents/simple", data={
        "name": "Billing Resolver", "instructions": "You handle refunds.",
        "skills": [K("lookup_customer"), K("create_ticket"), K("issue_refund")],
        "stance__" + K("issue_refund"): "never", "stance__" + K("create_ticket"): "ask",
        "first": "Customer AC-1001 was charged twice, refund them"})
    assert r.status_code == 302 and "/run/" in r.headers["Location"]
    rid = r.headers["Location"].rstrip("/").split("/")[-1]
    for _ in range(50):
        if store.get_run(rid)["status"] in ("done", "error", "awaiting_approval"):
            break
        time.sleep(0.1)
    run = store.get_run(rid)
    ag = store.get_agent(run["agent_id"])
    assert ag["owner"] == "simple@x.com" and set(ag["skills"]) == {K("lookup_customer"), K("create_ticket"), K("issue_refund")}
    pols = [p for p in store.list_policies() if p["agent_id"] == ag["id"]]
    assert {(p["tool"], p["effect"]) for p in pols} == {(K("issue_refund"), "deny"), (K("create_ticket"), "require_approval")}
    ev = store.audit_for_run(rid)
    assert any(e["kind"] == "policy_denied" and e["skill"] == K("issue_refund") for e in ev), "never means never, even when the planner tries"
    assert not store.approvals_for_run(rid)
    assert any(e["kind"] == "agent_created" and e["detail"]["how"] == "simple" for e in store.audit_all(50))


def test_high_tool_cannot_be_relaxed_from_the_card(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "relax@x.com")
    r = client.post("/agents/simple", data={"name": "R", "instructions": "x", "skills": [K("issue_refund")],
                                            "stance__" + K("issue_refund"): "own"})
    aid = r.headers["Location"].rstrip("/").split("/")[-1]
    assert not [p for p in store.list_policies() if p["agent_id"] == aid], "'own' on a HIGH tool writes no policy"
    assert rt.decide("r1", aid, K("issue_refund"), {"amount": 1}, rt.tool_index())["effect"] == "gate"
