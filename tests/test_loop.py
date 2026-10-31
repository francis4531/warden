"""Model selection and cost, loop limits, telemetry scrubbing, sandbox labelling."""
import json, sqlite3
from conftest import login, K, ADMIN


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
    def fake(system, messages, tools, model=None, **kw):
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


def test_interrupted_eval_runs_are_failed_at_boot(warden):
    """Evaluation runs are not resumed (their suite runner is gone); see test_resume.py."""
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("O", "x", rt.MODEL_DEFAULT, [], owner="o@x.com")
    rid = store.create_run(aid, "hang", eval_run_id="ev_x")
    store.update_run(rid, status="running")
    resumed, failed = rt.recover_interrupted(background=False)
    assert rid in failed and rid not in resumed and store.get_run(rid)["status"] == "error"
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


# ---- model call retries, output limit, refusals ----
class _Busy(Exception):
    def __init__(self, code, retry_after=None):
        super().__init__("Error code: %d" % code)
        self.status_code = code
        self.response = type("R", (), {"headers": {"retry-after": retry_after} if retry_after else {}})()


def _fake_client(monkeypatch, rt, outcomes):
    """Point _call_model at a fake Anthropic client that raises or answers from `outcomes` in
    order, and record the waits instead of sleeping."""
    import anthropic, types
    sleeps, calls = [], {"n": 0}
    def create(**kw):
        o = outcomes[min(calls["n"], len(outcomes) - 1)]; calls["n"] += 1
        if isinstance(o, Exception):
            raise o
        u = types.SimpleNamespace(input_tokens=1, output_tokens=1, server_tool_use=None,
                                  cache_creation_input_tokens=0, cache_read_input_tokens=0)
        return types.SimpleNamespace(stop_reason="end_turn", stop_details=None, usage=u,
                                     content=[types.SimpleNamespace(type="text", text=o, citations=None)])
    class Fake:
        def __init__(self, **kw): self.messages = types.SimpleNamespace(create=create)
    monkeypatch.setattr(rt, "SANDBOX", False)
    monkeypatch.setattr(anthropic, "Anthropic", Fake)
    monkeypatch.setattr(rt.time, "sleep", lambda s: sleeps.append(s))
    return sleeps, calls


def test_overloaded_model_is_retried_for_about_a_minute(warden, monkeypatch):
    rt = warden["rt"]
    sleeps, calls = _fake_client(monkeypatch, rt, [_Busy(529)] * 5 + ["ok"])
    seen = []
    r = rt._call_model("s", [{"role": "user", "content": "hi"}], [], on_retry=lambda a, w, ex: seen.append(a))
    assert r["content"][0]["text"] == "ok" and calls["n"] == 6 and seen == [1, 2, 3, 4, 5]
    assert sleeps[0] < 3 and sleeps[3] > 12, "backoff grows from about 2s to about 16s"
    # a model that stays overloaded is given up on once about a minute of waiting is spent
    sleeps, calls = _fake_client(monkeypatch, rt, [_Busy(529)])
    try:
        rt._call_model("s", [{"role": "user", "content": "hi"}], [])
        assert False, "should give up"
    except _Busy:
        pass
    assert 40 < sum(sleeps) <= rt.MODEL_RETRY_SECONDS and calls["n"] == len(sleeps) + 1
    assert "about a minute" in rt._friendly_error(_Busy(529))


def test_retry_honours_retry_after_and_never_retries_a_bad_request(warden, monkeypatch):
    rt = warden["rt"]
    sleeps, calls = _fake_client(monkeypatch, rt, [_Busy(429, "7"), "ok"])
    rt._call_model("s", [{"role": "user", "content": "hi"}], [])
    assert sleeps == [7.0]
    sleeps, calls = _fake_client(monkeypatch, rt, [_Busy(400)])
    try:
        rt._call_model("s", [{"role": "user", "content": "hi"}], [])
    except _Busy:
        pass
    assert calls["n"] == 1 and sleeps == []
    bad = _Busy(400); bad.args = ("invalid request: the field is not accurate (internal check)",)
    assert not rt._is_transient(bad), "words in a 400's message do not make it retryable"


def test_retries_show_in_the_conversation(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    _fake_client(monkeypatch, rt, [_Busy(529), "done now"])
    aid = store.create_agent("R", "x", rt.MODEL_DEFAULT, [], owner="r@x.com")
    rid = store.create_run(aid, "hello")
    r = rt.advance(rid)
    ev = store.audit_for_run(rid)
    assert r["status"] == "done"
    assert [e for e in ev if e["kind"] == "model_retry"][0]["detail"]["text"].startswith("the model is busy (overloaded)")
    assert [e for e in ev if e["kind"] == "final"][-1]["detail"]["text"] == "done now"


def test_tool_call_cut_off_at_output_limit_is_not_run_or_final(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("C", "x", rt.MODEL_DEFAULT, [K("lookup_customer")], owner="c@x.com")
    rid = store.create_run(aid, "look up AC-1001")
    calls, seen = {"n": 0}, []
    def fake(system, messages, tools, model=None, **kw):
        calls["n"] += 1; seen.append(json.dumps(messages))
        if calls["n"] == 1:
            return {"stop_reason": "max_tokens", "usage": {}, "model": "fake",
                    "content": [{"type": "text", "text": "Looking it up."},
                                {"type": "tool_use", "id": "cut1", "name": K("lookup_customer"), "input": {}}]}
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "retried fine"}], "usage": {}, "model": "fake"}
    monkeypatch.setattr(rt, "_call_model", fake)
    r = rt.advance(rid)
    ev = store.audit_for_run(rid)
    assert r["status"] == "done" and calls["n"] == 2
    assert not any(e["kind"] in ("tool_call", "tool_result", "approval_request") for e in ev), "the cut-off call never ran"
    assert "cut1" not in seen[1] and "output limit" in seen[1]
    assert any(e["kind"] == "continued" and "not run" in e["detail"]["text"] for e in ev)
    assert [e for e in ev if e["kind"] == "final"][-1]["detail"]["text"] == "retried fine"


def test_repeated_cut_off_tool_calls_stop_with_an_error(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("C2", "x", rt.MODEL_DEFAULT, [K("lookup_customer")], owner="c2@x.com")
    rid = store.create_run(aid, "write a huge record")
    calls = {"n": 0}
    def fake(system, messages, tools, model=None, **kw):
        calls["n"] += 1
        return {"stop_reason": "max_tokens", "usage": {}, "model": "fake",
                "content": [{"type": "tool_use", "id": "c%d" % calls["n"], "name": K("lookup_customer"), "input": {}}]}
    monkeypatch.setattr(rt, "_call_model", fake)
    r = rt.advance(rid)
    assert r["status"] == "error" and calls["n"] == rt.MAX_CUT_CALLS + 1
    err = [e for e in store.audit_for_run(rid) if e["kind"] == "error"][-1]["detail"]["text"]
    assert "cut off at the output limit" in err and not any(e["kind"] == "final" for e in store.audit_for_run(rid))
    for m in r["transcript"]:
        if m["role"] == "assistant":
            assert m["content"] and not rt._has_tool_use(m), "no cut-off call is left for a resume to run"


def test_refusal_is_reported_and_the_conversation_can_continue(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("F", "x", rt.MODEL_DEFAULT, [], owner="f@x.com")
    rid = store.create_run(aid, "something the model declines")
    answers = [{"stop_reason": "refusal", "content": [{"type": "text", "text": "partial"}], "usage": {}, "model": "fake",
                "stop_details": {"category": "cyber", "explanation": "x"}},
               {"stop_reason": "end_turn", "content": [{"type": "text", "text": "happy to help"}], "usage": {}, "model": "fake"}]
    seen = []
    def fake(system, messages, tools, model=None, **kw):
        seen.append(messages[:]); return answers[len(seen) - 1]
    monkeypatch.setattr(rt, "_call_model", fake)
    r = rt.advance(rid)
    ev = store.audit_for_run(rid)
    ref = [e for e in ev if e["kind"] == "refused"]
    assert r["status"] == "done" and ref and "declined" in ref[0]["detail"]["text"] and "cyber" in ref[0]["detail"]["text"]
    assert not any(e["kind"] in ("final", "thought") for e in ev), "no empty or partial answer is presented"
    assert all(m["role"] != "assistant" for m in r["transcript"]), "the refused turn is not kept"
    assert rt._final_text(r).startswith("[refused] The model declined"), "a team lead gets a labelled result, not empty text"
    tr = r["transcript"]; tr.append({"role": "user", "content": "ok, something else"})
    store.update_run(rid, status="running", transcript=tr)
    r = rt.advance(rid)
    assert r["status"] == "done" and [e for e in store.audit_for_run(rid) if e["kind"] == "final"][-1]["detail"]["text"] == "happy to help"


# ---- web tools refused by the provider ----
def _web_client(monkeypatch, rt, refuse=True):
    """A fake client that refuses any request carrying the built-in web tools."""
    import anthropic, types
    sent = []
    def create(**kw):
        names = [t.get("name") for t in kw.get("tools") or []]
        sent.append({"web": "web_search" in names, "system": " ".join(b["text"] for b in kw["system"])})
        if refuse and "web_search" in names:
            raise _Busy(400).with_message("web_search is not enabled for this organization")
        u = types.SimpleNamespace(input_tokens=1, output_tokens=1, server_tool_use=None,
                                  cache_creation_input_tokens=0, cache_read_input_tokens=0)
        return types.SimpleNamespace(stop_reason="end_turn", stop_details=None, usage=u,
                                     content=[types.SimpleNamespace(type="text", text="answered", citations=None)])
    class Fake:
        def __init__(self, **kw): self.messages = types.SimpleNamespace(create=create)
    monkeypatch.setattr(rt, "SANDBOX", False)
    monkeypatch.setattr(anthropic, "Anthropic", Fake)
    monkeypatch.setattr(rt.time, "sleep", lambda s: None)
    return sent

def _with_message(self, msg):
    self.args = (msg,); return self
_Busy.with_message = _with_message


def test_web_refusal_reruns_the_step_without_web_and_flags_the_admin(warden, monkeypatch, client):
    store, rt = warden["store"], warden["rt"]
    store.set_setting("web_refused", None)
    sent = _web_client(monkeypatch, rt)
    aid = store.create_agent("W", "x", rt.MODEL_DEFAULT, [], owner="w@x.com")
    rid = store.create_run(aid, "what is new on the web")
    r = rt.advance(rid)
    ev = store.audit_for_run(rid)
    assert r["status"] == "done" and [e for e in ev if e["kind"] == "final"][-1]["detail"]["text"] == "answered"
    assert [x["web"] for x in sent] == [True, False], "refused once, then the same step ran without web tools"
    assert "unavailable for this step" in sent[1]["system"]
    assert [e["kind"] for e in ev].count("web_unavailable") == 1
    flag = rt.web_refusal()
    assert flag and "not enabled" in flag["message"]
    # later steps skip the web tools for a while instead of failing first every time
    tr = r["transcript"]; tr.append({"role": "user", "content": "and again"})
    store.update_run(rid, status="running", transcript=tr); rt.advance(rid)
    assert [x["web"] for x in sent] == [True, False, False]
    assert [e["kind"] for e in store.audit_for_run(rid)].count("web_unavailable") == 1, "flagged once per conversation"
    # the admin sees it on the Overview
    login(client, ADMIN, hat="admin")
    page = client.get("/app").get_data(as_text=True)
    assert "Model provider refused the web tools" in page and "not enabled" in page
    # once the recheck window passes and the provider takes them, the flag clears itself
    sent2 = _web_client(monkeypatch, rt, refuse=False)
    monkeypatch.setattr(rt, "WEB_REFUSAL_RECHECK_SECONDS", 0)
    rt._call_model("s", [{"role": "user", "content": "hi"}], [])
    assert sent2[0]["web"] and rt.web_refusal() is None


def test_admin_saving_web_access_clears_the_refusal_flag(warden, client):
    store, rt = warden["store"], warden["rt"]
    store.set_setting("web_refused", json.dumps({"ts": 1, "at": "2026-10-31T10:00", "message": "no"}))
    login(client, ADMIN, hat="admin")
    client.post("/catalog/web", data={"search": "1", "fetch": "1", "max_uses": "5"})
    assert rt.web_refusal() is None
