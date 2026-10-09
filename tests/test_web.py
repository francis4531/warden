"""Built-in web access: settings, tool definitions, whole-block transcript handling, audit, cost."""
import json
import anthropic
from conftest import login, ADMIN


def _set(store, **kw):
    store.set_setting("web_tools", json.dumps(kw))


def test_web_defaults_and_tool_params(warden, monkeypatch):
    rt, store = warden["rt"], warden["store"]
    store.set_setting("web_tools", "")
    w = rt.web_settings()
    assert w["search"] and w["fetch"] and w["max_uses"] == 5
    assert rt.web_tools_param() == [], "sandbox has no model to run server tools"
    monkeypatch.setattr(rt, "SANDBOX", False)
    names = [t["name"] for t in rt.web_tools_param()]
    assert names == ["web_search", "web_fetch"]
    _set(store, search=False, fetch=True)
    assert [t["name"] for t in rt.web_tools_param()] == ["web_fetch"]
    _set(store, search=False, fetch=False)
    assert rt.web_tools_param() == []


def test_domain_lists_allow_wins_over_block(warden, monkeypatch):
    rt, store = warden["rt"], warden["store"]
    monkeypatch.setattr(rt, "SANDBOX", False)
    _set(store, search=True, fetch=True, allowed_domains=["sec.gov"], blocked_domains=["x.com"])
    for t in rt.web_tools_param():
        assert t["allowed_domains"] == ["sec.gov"] and "blocked_domains" not in t
    _set(store, search=True, fetch=True, allowed_domains=[], blocked_domains=["x.com"])
    for t in rt.web_tools_param():
        assert t["blocked_domains"] == ["x.com"] and "allowed_domains" not in t


def test_server_tool_blocks_survive_the_transcript(warden):
    """The next turn is rejected if a search call, its result, or citations are dropped."""
    rt = warden["rt"]
    use = anthropic.types.ServerToolUseBlock.model_validate(
        {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {"query": "agent frameworks"}})
    res = anthropic.types.WebSearchToolResultBlock.model_validate(
        {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
         "content": [{"type": "web_search_result", "title": "T", "url": "https://a.example/x", "encrypted_content": "abc", "page_age": None}]})
    txt = anthropic.types.TextBlock.model_validate(
        {"type": "text", "text": "Answer", "citations": [{"type": "web_search_result_location", "cited_text": "c", "url": "https://a.example/x", "title": "T", "encrypted_index": "ei"}]})
    d_use, d_res, d_txt = rt._b2d(use), rt._b2d(res), rt._b2d(txt)
    assert d_use["type"] == "server_tool_use" and d_use["input"] == {"query": "agent frameworks"}
    assert d_res["type"] == "web_search_tool_result" and d_res["content"][0]["encrypted_content"] == "abc"
    assert d_txt["citations"][0]["url"] == "https://a.example/x"


def test_web_calls_are_audited_priced_and_pause_turn_continues(warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("Web", "research", rt.MODEL_DEFAULT, [], owner="web@x.com")
    rid = store.create_run(aid, "compare agent frameworks")
    calls = []
    first = {"stop_reason": "pause_turn", "model": "claude-sonnet-4-6", "latency_ms": 1,
             "usage": {"input_tokens": 0, "output_tokens": 0, "web_searches": 2},
             "content": [{"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {"query": "agent frameworks 2026"}},
                         {"type": "web_search_tool_result", "tool_use_id": "s1",
                          "content": [{"type": "web_search_result", "title": "Frameworks", "url": "https://a.example/f", "encrypted_content": "e"}]},
                         {"type": "server_tool_use", "id": "s2", "name": "web_fetch", "input": {"url": "https://a.example/f"}},
                         {"type": "web_fetch_tool_result", "tool_use_id": "s2", "content": {"type": "web_fetch_tool_result_error", "error_code": "url_not_accessible"}}]}
    second = {"stop_reason": "end_turn", "model": "claude-sonnet-4-6", "latency_ms": 1,
              "usage": {"input_tokens": 0, "output_tokens": 0},
              "content": [{"type": "text", "text": "Here is the comparison, per https://a.example/f"}]}
    def fake(system, messages, tools, model=None):
        calls.append([m["role"] for m in messages])
        return first if len(calls) == 1 else second
    monkeypatch.setattr(rt, "_call_model", fake)
    rt.advance(rid)
    ev = store.audit_for_run(rid)
    kinds = [e["kind"] for e in ev]
    assert "web_search" in kinds and "web_fetch" in kinds and kinds[-1] == "final"
    ws = next(e for e in ev if e["kind"] == "web_search")
    assert ws["detail"]["query"] == "agent frameworks 2026" and ws["detail"]["results"][0]["url"] == "https://a.example/f"
    assert "failed: url_not_accessible" in next(e for e in ev if e["kind"] == "web_fetch")["detail"]["text"]
    cost = sum(e["detail"]["cost"] for e in ev if e["kind"] == "model_call")
    assert abs(cost - 0.02) < 1e-9, "two searches at $0.01, no tokens"
    assert calls[1][-1] == "assistant", "a paused turn is sent back as is to continue it"


def test_admin_web_settings_route(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "plain@x.com")
    assert client.post("/catalog/web", data={"search": "1"}).status_code in (403, 404)
    login(client, ADMIN, hat="admin")
    r = client.post("/catalog/web", data={"search": "1", "allowed": "https://SEC.gov/, docs.python.org\nnot a domain", "max_uses": "99"})
    assert r.status_code == 302
    w = rt.web_settings()
    assert w["search"] and not w["fetch"] and w["allowed_domains"] == ["sec.gov", "docs.python.org"] and w["max_uses"] == 20
    try:
        assert any(e["kind"] == "web_settings_changed" for e in store.audit_all(10))
        assert "Web access" in client.get("/catalog").get_data(as_text=True)
    finally:
        _set(store, search=True, fetch=True)                    # leave defaults for other tests


def test_agent_page_lists_web_tools_only_when_live(client, warden, monkeypatch):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("W2", "x", rt.MODEL_DEFAULT, [], owner="w2@x.com")
    login(client, "w2@x.com")
    assert "web_search" not in client.get("/agent/%s" % aid).get_data(as_text=True)
    monkeypatch.setattr(rt, "SANDBOX", False)
    h = client.get("/agent/%s" % aid).get_data(as_text=True)
    assert "web_search" in h and "web_fetch" in h
