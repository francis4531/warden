"""The admin Users page groups users by the domain of their email address."""
from conftest import login, ADMIN


def _make(store, rt, owner, runs=1):
    aid = store.create_agent("Helper", "x", rt.MODEL_DEFAULT, [], owner=owner)
    for _ in range(runs):
        store.create_run(aid, "hello")
    return aid


def test_domains_are_grouped_counted_and_labelled(warden):
    A, store, rt = warden["app"], warden["store"], warden["rt"]
    _make(store, rt, "dom1@acme-corp.test", runs=2)
    _make(store, rt, "dom2@acme-corp.test", runs=1)
    _make(store, rt, "dom3@Acme-Corp.test", runs=0)       # case never splits a domain
    _make(store, rt, "dom4@gmail.com", runs=1)
    with A.app.test_request_context():
        rows, _ = A._studio_summary()
        doms = {d["domain"]: d for d in A._domain_summary(rows)}
    acme = doms["acme-corp.test"]
    assert len(acme["users"]) == 3 and acme["agents"] == 3 and acme["runs"] == 3
    assert acme["users"] == sorted(acme["users"]) and not acme["personal"]
    assert doms["gmail.com"]["personal"] and len(doms["gmail.com"]["users"]) >= 1


def test_the_most_users_come_first_and_unowned_is_not_counted(warden):
    A, store, rt = warden["app"], warden["store"], warden["rt"]
    store.create_agent("Orphan", "x", rt.MODEL_DEFAULT, [], owner="")
    _make(store, rt, "dom5@big-co.test"); _make(store, rt, "dom6@big-co.test")
    _make(store, rt, "dom7@big-co.test"); _make(store, rt, "dom8@solo-co.test")
    with A.app.test_request_context():
        rows, _ = A._studio_summary()
        out = A._domain_summary(rows)
    names = [d["domain"] for d in out]
    assert "unowned" not in names and all("." in n for n in names)
    assert names.index("big-co.test") < names.index("solo-co.test")


def test_the_users_page_shows_the_domain_table_to_admins_only(client, warden):
    store, rt = warden["store"], warden["rt"]
    _make(store, rt, "dom9@shown-co.test")
    login(client, ADMIN, hat="admin")
    page = client.get("/studio").get_data(as_text=True)
    assert "By email domain" in page and "shown-co.test" in page
    assert "Anyone who only opens a page is not recorded" in page
    login(client, "dom9@shown-co.test")
    r = client.get("/studio")
    assert r.status_code in (302, 404, 403), "a regular user never sees the domain view"
