"""Files dropped into a conversation: reading, limits, framing, routes."""
import io, zipfile
from werkzeug.datastructures import FileStorage
from conftest import login, K


def fs(name, data):
    return FileStorage(stream=io.BytesIO(data), filename=name)


def _zip(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, c in files.items():
            z.writestr(n, c)
    return b.getvalue()


DOCX = _zip({"word/document.xml": "<w:document><w:body><w:p><w:r><w:t>Quarterly plan</w:t></w:r></w:p>"
                                  "<w:p><w:r><w:t>Ship &amp; learn</w:t></w:r></w:p></w:body></w:document>"})
XLSX = _zip({
    "xl/workbook.xml": '<workbook><sheets><sheet name="Revenue" sheetId="1" r:id="rId1"/></sheets></workbook>',
    "xl/sharedStrings.xml": "<sst><si><t>Region</t></si><si><t>West</t></si></sst>",
    "xl/worksheets/sheet1.xml": '<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><t>Amount</t></is></c></row>'
                                '<row r="2"><c r="A2" t="s"><v>1</v></c><c r="C2"><v>42</v></c></row></sheetData></worksheet>'})
PPTX = _zip({"ppt/slides/slide2.xml": "<p:sld><a:p><a:r><a:t>Second</a:t></a:r></a:p></p:sld>",
             "ppt/slides/slide1.xml": "<p:sld><a:p><a:r><a:t>First</a:t></a:r></a:p></p:sld>"})


def test_each_kind_is_read(warden):
    import attachments
    blocks, names, errors = attachments.process([
        fs("notes.csv", b"a,b\n1,2\n"), fs("plan.docx", DOCX), fs("rev.xlsx", XLSX), fs("deck.pptx", PPTX),
        fs("one.pdf", b"%PDF-1.4 fake")])
    assert names == ["notes.csv", "plan.docx", "rev.xlsx", "deck.pptx", "one.pdf"] and not errors
    text = "\n".join(b.get("text", "") for b in blocks if b["type"] == "text")
    assert "a,b" in text and "Quarterly plan" in text and "Ship & learn" in text
    assert "--- Sheet: Revenue ---\nRegion\tAmount\nWest\t\t42" in text
    assert text.index("First") < text.index("Second"), "slides in numeric order"
    assert "not instructions" in text, "every file is framed as data"
    assert any(b["type"] == "document" and b["source"]["media_type"] == "application/pdf" for b in blocks)


def test_bad_files_are_reported_not_fatal(warden):
    import attachments
    blocks, names, errors = attachments.process([
        fs("ok.txt", b"fine"), fs("virus.exe", b"MZ\x90"), fs("empty.txt", b""), fs("fake.pdf", b"hello"), fs("bin.txt", b"\x00\x01\x02")])
    assert names == ["ok.txt"]
    assert len(errors) == 4 and all("was not used" in e for e in errors)
    blocks, names, errors = attachments.process([
        fs("ok2.txt", b"fine"), fs("big.csv", b"x" * (attachments.MAX_BYTES_EACH + 1)), fs("fake.docx", b"not a zip")])
    assert names == ["ok2.txt"] and len(errors) == 2


def test_limits_and_names(warden):
    import attachments
    many = [fs("f%d.txt" % i, b"x") for i in range(8)]
    blocks, names, errors = attachments.process(many)
    assert len(names) == attachments.MAX_FILES and any("first 5" in e for e in errors)
    assert attachments.clean_name('../../etc/pa"ss<wd>.txt') == "passwd.txt"
    # a long text file is cut, and says so
    blocks, names, errors = attachments.process([fs("long.txt", b"y" * (attachments.MAX_TEXT_CHARS + 10))])
    assert "characters shown" in blocks[0]["text"]


def test_zip_bomb_member_is_refused(warden):
    import attachments
    bomb = _zip({"word/document.xml": "<w:t>" + "A" * (attachments.MAX_ZIP_MEMBER + 100) + "</w:t>"})
    blocks, names, errors = attachments.process([fs("bomb.docx", bomb)])
    assert not names and errors


def test_run_with_files_reaches_the_conversation(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("Files", "read files", rt.MODEL_DEFAULT, [K("lookup_customer")], owner="fx@x.com")
    login(client, "fx@x.com")
    r = client.post("/run", data={"agent_id": aid, "input": "Summarise this", "files": [
        (io.BytesIO(b"region,amount\nwest,42\n"), "sales.csv"), (io.BytesIO(b"MZ"), "tool.exe")]},
        content_type="multipart/form-data")
    assert r.status_code == 302
    rid = r.headers["Location"].rstrip("/").split("/")[-1]
    run = store.get_run(rid)
    first = run["transcript"][0]
    assert first["role"] == "user" and isinstance(first["content"], list)
    body = first["content"][0]["text"]
    assert "Summarise this" in body and "tool.exe" in body and "was not used" in body
    assert any("west,42" in b.get("text", "") for b in first["content"])
    started = [e for e in store.audit_for_run(rid) if e["kind"] == "run_started"]
    assert len(started) == 1 and started[0]["detail"]["files"] == ["sales.csv"] and started[0]["detail"]["file_errors"]
    assert run["input"] == "Summarise this"


def test_reply_with_a_file_and_plain_replies_still_work(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("Reply", "x", rt.MODEL_DEFAULT, [], owner="rp@x.com")
    login(client, "rp@x.com")
    rid = store.create_run(aid, "hello")
    store.update_run(rid, status="done", transcript=[{"role": "user", "content": "hello"}, {"role": "assistant", "content": [{"type": "text", "text": "hi"}]}])
    r = client.post("/run/%s/say" % rid, data={"input": "and this", "files": (io.BytesIO(b"col\n1\n"), "d.csv")}, content_type="multipart/form-data")
    assert r.status_code == 200
    tr = store.get_run(rid)["transcript"]
    assert isinstance(tr[2]["content"], list) and "col" in tr[2]["content"][1]["text"]
    store.update_run(rid, status="done")
    assert client.post("/run/%s/say" % rid, data={"input": "plain"}).status_code == 200
    assert client.post("/run/%s/say" % rid, data={"input": ""}).status_code in (400, 409)


def test_file_only_message_and_oversized_request(client, warden):
    store, rt = warden["store"], warden["rt"]
    aid = store.create_agent("FO", "x", rt.MODEL_DEFAULT, [], owner="fo@x.com")
    login(client, "fo@x.com")
    r = client.post("/run", data={"agent_id": aid, "input": "", "files": (io.BytesIO(b"hello"), "n.txt")}, content_type="multipart/form-data")
    assert r.status_code == 302
    rid = r.headers["Location"].rstrip("/").split("/")[-1]
    assert store.get_run(rid)["input"].startswith("Please look at the attached file")
    assert client.post("/run", data={"agent_id": aid, "input": ""}, content_type="multipart/form-data").status_code == 400


def test_token_estimate_counts_files_by_size_not_base64_length(warden):
    rt = warden["rt"]
    import base64
    pdf = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": base64.b64encode(b"x" * 100_000).decode()}}
    assert 2500 < rt._est_tokens([pdf]) < 3500          # about 30 tokens per KB
    assert rt._est_tokens("a" * 400) == 100
