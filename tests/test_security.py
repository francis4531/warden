"""The security floor: session secret, CSRF, open redirect, audit chain, eval IDORs, env."""
import os, json, threading, sqlite3
from flask.sessions import SecureCookieSessionInterface
from conftest import login, K, ADMIN, ALICE, BOB


# ---- 2. no built-in session secret ----
def test_session_key_is_not_a_default(warden):
    A = warden["app"]
    assert A.app.secret_key != b"dev-insecure-change-me" and A.app.secret_key != "dev-insecure-change-me"
    assert len(A.app.secret_key) >= 32
    import vault
    assert A.app.secret_key != vault._key(), "session key must differ from the vault key"
    assert vault.derive("session") != vault.derive("audit")


def test_forged_cookie_with_old_default_is_rejected(warden, client):
    A = warden["app"]
    saved = A.app.secret_key
    try:
        A.app.secret_key = "dev-insecure-change-me"
        forged = SecureCookieSessionInterface().get_signing_serializer(A.app).dumps({"auth": True, "email": ADMIN, "hat": "admin"})
    finally:
        A.app.secret_key = saved
    client.set_cookie("session", forged)
    r = client.get("/studio")
    assert r.status_code in (302, 404)   # bounced to login, not an admin page


def test_cookie_flags(warden):
    cfg = warden["app"].app.config
    assert cfg["SESSION_COOKIE_SAMESITE"] == "Lax" and cfg["SESSION_COOKIE_HTTPONLY"]


# ---- 7. CSRF ----
def test_post_without_token_is_refused(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "csrf@x.com", csrf_exempt=False)
    aid = store.create_agent("C", "x", rt.MODEL_DEFAULT, [], owner="csrf@x.com")
    r = client.post("/agent/%s/delete" % aid, data={})
    assert r.status_code == 403
    assert store.get_agent(aid) is not None


def test_post_with_token_or_fetch_header_is_accepted(client, warden):
    store, rt = warden["store"], warden["rt"]
    login(client, "csrf2@x.com", csrf_exempt=False)
    client.get("/")                       # renders a page, which mints the token
    with client.session_transaction() as s:
        tok = s["csrf"]
    aid = store.create_agent("C2", "x", rt.MODEL_DEFAULT, [], owner="csrf2@x.com")
    assert client.post("/agent/%s/delete" % aid, data={"csrf": tok}).status_code in (200, 302)
    assert store.get_agent(aid) is None
    aid = store.create_agent("C3", "x", rt.MODEL_DEFAULT, [], owner="csrf2@x.com")
    assert client.post("/agent/%s/delete" % aid, headers={"X-CSRF": tok}).status_code in (200, 302)
    aid = store.create_agent("C4", "x", rt.MODEL_DEFAULT, [], owner="csrf2@x.com")
    assert client.post("/agent/%s/delete" % aid, headers={"X-Requested-With": "fetch"}).status_code in (200, 302)


def test_every_post_form_carries_the_token():
    import glob, re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for p in glob.glob(os.path.join(root, "templates", "*.html")):
        s = open(p).read()
        for m in re.finditer(r'<form\b[^>]*method="post"[^>]*>', s, flags=re.I):
            tail = s[m.end(): m.end() + 120]
            assert 'name="csrf"' in tail, "%s: form at %d lacks the csrf field" % (os.path.basename(p), m.start())


# ---- 11. open redirect ----
def test_login_next_cannot_leave_the_site(client, warden):
    A = warden["app"]
    assert A._safe_next("//evil.com/x") == ""
    assert A._safe_next("/evil.com") == "/evil.com"
    assert A._safe_next("https://evil.com") == ""
    assert A._safe_next("/\\evil.com") == ""
    client.get("/login")
    with client.session_transaction() as s:
        tok = s.get("csrf")
    r = client.post("/login", data={"password": "pw", "next": "//evil.com/x", "csrf": tok})
    assert r.status_code == 302 and not r.headers["Location"].startswith("//")


# ---- 8. audit chain ----
def test_audit_chain_survives_concurrent_writers(warden):
    store = warden["store"]
    def w(i):
        for j in range(25):
            store.audit(None, None, "test_concurrency", detail={"t": i, "j": j})
    ths = [threading.Thread(target=w, args=(i,)) for i in range(8)]
    for t in ths: t.start()
    for t in ths: t.join()
    v = store.verify_audit()
    assert v["ok"], v


def test_audit_detects_tail_deletion_and_edit(warden):
    store = warden["store"]
    store.audit(None, None, "test_tail", detail={"a": 1})
    store.audit(None, None, "test_tail", detail={"a": 2})
    assert store.verify_audit()["ok"]
    c = sqlite3.connect(store.DB)
    last = c.execute("SELECT id FROM audit ORDER BY rowid DESC LIMIT 1").fetchone()[0]
    c.execute("DELETE FROM audit WHERE id=?", (last,)); c.commit()
    v = store.verify_audit()
    assert not v["ok"] and v["reason"] == "head"
    # restore by appending: the chain re-heads
    store.audit(None, None, "test_tail", detail={"a": 3})
    assert store.verify_audit()["ok"]
    first = c.execute("SELECT id FROM audit ORDER BY rowid LIMIT 1").fetchone()[0]
    c.execute("UPDATE audit SET detail='{\"x\":\"tampered\"}' WHERE id=?", (first,)); c.commit(); c.close()
    v = store.verify_audit()
    assert not v["ok"] and v["broken_at"] == first


def test_audit_links_are_keyed(warden):
    """A database editor without the studio secret cannot recompute a link."""
    import hashlib
    store = warden["store"]
    store.audit(None, None, "test_keyed", detail={"k": 1})
    c = sqlite3.connect(store.DB); c.row_factory = sqlite3.Row
    d = dict(c.execute("SELECT * FROM audit ORDER BY rowid DESC LIMIT 1").fetchone()); c.close()
    payload = store._audit_payload(d["id"], d["run_id"], d["agent_id"], d["ts"], d["kind"], d["skill"], d["risk"], d["detail"])
    plain = hashlib.sha256(((d["prev_hash"] or "") + "\n" + payload).encode()).hexdigest()
    assert d["hash"] != plain


# ---- 9. eval and annotation IDORs ----
def test_eval_children_are_owner_scoped(client, warden):
    store, rt = warden["store"], warden["rt"]
    a_ag = store.create_agent("A", "x", rt.MODEL_DEFAULT, [], owner=ALICE)
    a_su = store.create_suite(a_ag, ALICE, "alice suite")
    a_case = store.add_case(a_su, "hello")
    a_chk = store.add_check(a_su, "code", "c", {"check": "mentions", "value": "x"})
    a_run = store.create_run(a_ag, "alice private input")
    a_ann = store.annotate(a_run, a_ag, ALICE, "good", "", "")
    b_ag = store.create_agent("B", "x", rt.MODEL_DEFAULT, [], owner=BOB)
    b_su = store.create_suite(b_ag, BOB, "bob suite")
    login(client, BOB)
    H = {"X-Requested-With": "fetch"}
    assert client.post("/evals/%s/case/%s/delete" % (b_su, a_case), headers=H).status_code == 404
    assert len(store.list_cases(a_su)) == 1
    assert client.post("/evals/%s/check/%s/delete" % (b_su, a_chk), headers=H).status_code == 404
    assert len(store.list_checks(a_su)) == 1
    assert client.post("/evals/%s/case" % b_su, data={"source_run_id": a_run}, headers=H).status_code == 404
    assert store.list_cases(b_su) == []
    assert client.post("/annotations/%s/delete" % a_ann, headers=H).status_code == 404
    assert any(x["id"] == a_ann for x in store.list_annotations(ALICE))


# ---- 12. spawned servers get a minimal environment ----
def test_child_env_has_no_studio_secrets(warden, monkeypatch):
    import connection_manager as cm
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "gsec")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_env")
    env = cm._child_env("github", {"catalog_id": "github"})
    assert "ANTHROPIC_API_KEY" not in env and "GOOGLE_CLIENT_SECRET" not in env and "WARDEN_SECRET_KEY" not in env
    assert "GITHUB_TOKEN" not in env, "a token in the studio's environment is never handed to a connection"
    assert "PATH" in env
    env = cm._child_env("github", {"catalog_id": "github", "token": "ghp_mine"})
    assert env.get("GITHUB_TOKEN") == "ghp_mine"


def test_http_connections_never_read_tokens_from_env(monkeypatch):
    import connection_manager as cm
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_env")
    url, headers = cm._http_params("github", {"catalog_id": "github"})
    assert "ghp_env" not in json.dumps(headers or {})


# ---- 19. healthz says little to strangers ----
def test_healthz_is_minimal_when_anonymous(client):
    r = client.get("/healthz").get_json()
    assert set(r) == {"ok", "version", "commit"}


def test_every_outbound_request_identifies_warden():
    """Providers' edges (Atlassian's, for one) answer 403 to Python's default user agent."""
    import oauth, connection_manager as cm
    r = oauth._req("https://example.invalid/x")
    assert r.get_header("User-agent", "").startswith("Warden/")
    url, headers = cm._http_params("github", {"catalog_id": "github", "token": "ghp_x"})
    assert headers["User-Agent"].startswith("Warden/") and headers["Authorization"] == "Bearer ghp_x"
