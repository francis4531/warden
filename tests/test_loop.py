"""Model selection and cost, loop limits, telemetry scrubbing, sandbox labelling."""
import json, sqlite3
from conftest import login, K


# ---- 17. model and cost ----
def test_agent_model_is_used(warden):
    rt = warden["rt"]
    assert rt.model_for({"model": "claude-haiku-4-5"}) == "claude-haiku-4-5"
    assert rt.model_for({"model": ""}) == rt.MODEL_DEFAULT
    assert rt.model_for({}) == rt.MODEL_DEFAULT


def test_prices_match_by_longest_prefix_and_include_cache(warden):
    rt = warden["rt"]
    assert rt._rate4("claude-opus-5-5") == (4.0, 20.0, 5.0, 0.20)
    assert rt._rate4("claude-opus-5") == (5.0, 25.0, 6.25, 0.50)
    assert rt._rate4("claude-opus-4-1-20250805") == (15.0, 75.0, 18.75, 1.50)
    assert rt._rate4("claude-haiku-4-5-20251001") == (1.0, 5.0, 1.25, 0.10)
    assert rt._rate4("claude-sonnet-9-9")[:2] == (3.0, 15.0), "unknown sonnet falls back to the family"
    # 1M input at $3 + 1M output at $15 + 1M cache write at $3.75 + 1M cache read at $0.30
    assert rt._cost("claude-sonnet-4-6", 1_000_000, 1_000_000, 1_000_000, 1_000_000) == 22.05
    assert rt.rate_for("claude-sonnet-4-6") == (3.0, 15.0)


def test_model_call_records_cache_tokens(warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("M", "x", rt.MODEL_DEFAULT, [K("lookup_customer")], owner="m@x.com")
    rid = store.create_run(aid, "Look up customer AC-1001")
    rt.advance(rid)
    mc = [e for e in store.audit_for_run(rid) if e["kind"] == "model_call"]
    assert mc and "cache_read_tokens" in mc[0]["detail"] and "cache_write_tokens" in mc[0]["detail"]


# ---- 18. loop limits ----
def test_call_ceiling_holds_across_resumes(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    monkeypatch.setattr(rt, "MAX_CALLS_PER_RUN", 3)
    aid = store.create_agent("L", "x", rt.MODEL_DEFAULT, [K("lookup_customer"), K("search_knowledge")], owner="l@x.com")
    rid = store.create_run(aid, "Look up customer AC-1001 and tell me their plan")
    rt.advance(rid)
    for _ in range(4):                     # keep resuming the same conversation
        r = store.get_run(rid); tr = r["transcript"]; tr.append({"role": "user", "content": "and again?"})
        store.update_run(rid, status="running", transcript=tr); rt.advance(rid)
    calls = sum(1 for e in store.audit_for_run(rid) if e["kind"] == "model_call")
    assert calls <= 3
    assert any(e["kind"] == "budget_stop" and e["detail"].get("scope") == "calls" for e in store.audit_for_run(rid))


def test_trim_keeps_task_and_pairs(warden):
    rt = warden["rt"]
    msgs = [{"role": "user", "content": "the task"}]
    for i in range(20):
        msgs.append({"role": "assistant", "content": [{"type": "tool_use", "id": "t%d" % i, "name": "x", "input": {"q": "y" * 400}}]})
        msgs.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t%d" % i, "content": "z" * 400}]})
    before = len(msgs)
    dropped = rt._trim(msgs, budget=1000)
    assert dropped > 0 and dropped % 2 == 0 and len(msgs) == before - dropped
    assert msgs[0]["role"] == "user" and msgs[0]["content"].startswith("the task") and "omitted" in msgs[0]["content"]
    assert msgs[1]["role"] == "assistant" and msgs[2]["role"] == "user"
    assert rt._est_tokens(msgs) <= 1000 or len(msgs) < 4
    assert rt._trim([{"role": "user", "content": "short"}], budget=1000) == 0


def test_max_tokens_is_continued_not_final(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("T", "x", rt.MODEL_DEFAULT, [], owner="t@x.com")
    rid = store.create_run(aid, "write something long")
    calls = {"n": 0}
    def fake(system, messages, tools, model=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"stop_reason": "max_tokens", "content": [{"type": "text", "text": "first half"}], "usage": {}, "model": "fake"}
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "second half"}], "usage": {}, "model": "fake"}
    monkeypatch.setattr(rt, "_call_model", fake)
    r = rt.advance(rid)
    assert r["status"] == "done" and calls["n"] == 2
    ev = store.audit_for_run(rid)
    assert any(e["kind"] == "continued" for e in ev)
    assert [e for e in ev if e["kind"] == "final"][-1]["detail"]["text"] == "second half"


def test_orphaned_runs_are_failed_at_boot(warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("O", "x", rt.MODEL_DEFAULT, [], owner="o@x.com")
    rid = store.create_run(aid, "hang")
    store.update_run(rid, status="running")
    ids = store.fail_orphaned_runs()
    assert rid in ids and store.get_run(rid)["status"] == "error"
    assert any(e["kind"] == "error" and "restarted" in e["detail"]["text"] for e in store.audit_for_run(rid))


# ---- 20. telemetry ----
def test_telemetry_scrubs_values_and_matches_keys_by_word():
    import telemetry as t
    assert t._sensitive("card_number") and t._sensitive("apiKey") and t._sensitive("customer_email")
    assert not t._sensitive("discard") and not t._sensitive("shipping") and not t._sensitive("tokens")
    out = t.redact({"query": "mail bob@x.com, card 4111 1111 1111 1111, ssn 123-45-6789, key sk-ant-abcdefghijklmnop, call 408-555-1212",
                    "password": "hunter2", "nested": ["carol@y.org"]})
    assert out["password"] == "[redacted]"
    assert "bob@x.com" not in out["query"] and "4111" not in out["query"] and "123-45-6789" not in out["query"]
    assert "sk-ant" not in out["query"] and "408-555" not in out["query"]
    assert out["nested"] == ["[email]"]


def test_telemetry_payloads_off_by_default_and_span_name_has_no_user_text(warden):
    import telemetry as t
    store, rt = warden["store"], warden["rt"]
    assert t._preview({"a": 1}) is None
    aid = store.create_agent("S", "x", rt.MODEL_DEFAULT, [K("lookup_customer")], owner="s@x.com")
    rid = store.create_run(aid, "Look up customer AC-1001 whose email is bob@x.com")
    rt.advance(rid)
    otlp = t.to_otlp(rid)
    blob = json.dumps(otlp)
    assert "bob@x.com" not in blob
    assert "run " + rid in blob


# ---- 21. sandbox note ----
def test_sandbox_note_says_tools_are_real(client):
    login(client, "n@x.com")
    html = client.get("/app").data.decode()
    assert "a connected system is really called" in html
