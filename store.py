"""
Persistence for Warden: agents, runs, the audit log, and the approvals queue.
SQLite on disk. On a platform with an ephemeral filesystem (Render) this resets on
redeploy, which is fine for a demo; the point is that within a session every agent
action and every approval is durably recorded and queryable.
"""
import os
import json
import hashlib
import sqlite3
import datetime
import uuid

import paths
DATA_ROOT = paths.DATA_ROOT
DB = os.path.join(DATA_ROOT, "warden.db")

def _conn():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=8000")
    except Exception:
        pass
    return c

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def _id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

def init():
    c = _conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS agents(
      id TEXT PRIMARY KEY, name TEXT, instructions TEXT, model TEXT,
      skills TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS runs(
      id TEXT PRIMARY KEY, agent_id TEXT, input TEXT, status TEXT,
      transcript TEXT, created_at TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS audit(
      id TEXT PRIMARY KEY, run_id TEXT, agent_id TEXT, ts TEXT,
      kind TEXT, skill TEXT, risk TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
    CREATE TABLE IF NOT EXISTS approvals(
      id TEXT PRIMARY KEY, run_id TEXT, agent_id TEXT, skill TEXT, risk TEXT,
      arguments TEXT, status TEXT, created_at TEXT, decided_at TEXT, decided_by TEXT);
    CREATE TABLE IF NOT EXISTS connections(
      id TEXT PRIMARY KEY, transport TEXT, command TEXT, url TEXT, token TEXT,
      enabled INTEGER, created_at TEXT);
    CREATE TABLE IF NOT EXISTS tool_overrides(
      model_key TEXT PRIMARY KEY, risk TEXT);
    CREATE TABLE IF NOT EXISTS policies(
      id TEXT PRIMARY KEY, name TEXT, priority INTEGER, agent_id TEXT, tool TEXT,
      field TEXT, op TEXT, value TEXT, effect TEXT, enabled INTEGER, created_at TEXT);
    CREATE TABLE IF NOT EXISTS custom_servers(
      id TEXT PRIMARY KEY, name TEXT, category TEXT, transport TEXT,
      url TEXT, command TEXT, description TEXT, repo TEXT, created_at TEXT);
    """)
    # migrate older databases: add the audit hash-chain columns if they are missing
    cols = [r["name"] for r in c.execute("PRAGMA table_info(audit)").fetchall()]
    if "prev_hash" not in cols:
        c.execute("ALTER TABLE audit ADD COLUMN prev_hash TEXT")
    if "hash" not in cols:
        c.execute("ALTER TABLE audit ADD COLUMN hash TEXT")
    c.commit(); c.close()

# ---- agents ----
def create_agent(name, instructions, model, skills):
    c = _conn(); aid = _id("ag")
    c.execute("INSERT INTO agents VALUES(?,?,?,?,?,?)",
              (aid, name, instructions, model, json.dumps(skills), now()))
    c.commit(); c.close(); return aid

def update_agent(aid, name, instructions, model, skills):
    c = _conn()
    c.execute("UPDATE agents SET name=?, instructions=?, model=?, skills=? WHERE id=?",
              (name, instructions, model, json.dumps(skills), aid))
    c.commit(); c.close()

def get_agent(aid):
    c = _conn(); r = c.execute("SELECT * FROM agents WHERE id=?", (aid,)).fetchone(); c.close()
    if not r: return None
    d = dict(r); d["skills"] = json.loads(d["skills"] or "[]"); return d

def list_agents():
    c = _conn(); rows = c.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["skills"] = json.loads(d["skills"] or "[]"); out.append(d)
    return out

# ---- runs ----
def create_run(agent_id, user_input):
    c = _conn(); rid = _id("run")
    c.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?)",
              (rid, agent_id, user_input, "running", json.dumps([]), now(), now()))
    c.commit(); c.close(); return rid

def update_run(rid, status=None, transcript=None):
    c = _conn()
    if status is not None:
        c.execute("UPDATE runs SET status=?, updated_at=? WHERE id=?", (status, now(), rid))
    if transcript is not None:
        c.execute("UPDATE runs SET transcript=?, updated_at=? WHERE id=?",
                  (json.dumps(transcript), now(), rid))
    c.commit(); c.close()

def get_run(rid):
    c = _conn(); r = c.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone(); c.close()
    if not r: return None
    d = dict(r); d["transcript"] = json.loads(d["transcript"] or "[]"); return d

def list_runs(limit=50):
    c = _conn(); rows = c.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall(); c.close()
    return [dict(r) for r in rows]

# ---- audit (hash-chained, tamper-evident) ----
def _audit_payload(eid, run_id, agent_id, ts, kind, skill, risk, detail_s):
    return "|".join([eid, run_id or "", agent_id or "", ts, kind or "",
                     skill or "", risk or "", detail_s or ""])

def audit(run_id, agent_id, kind, skill=None, risk=None, detail=None):
    c = _conn()
    eid = _id("ev"); ts = now()
    detail_s = json.dumps(detail) if detail is not None else None
    prev = c.execute("SELECT hash FROM audit ORDER BY rowid DESC LIMIT 1").fetchone()
    prev_hash = prev["hash"] if (prev and prev["hash"]) else ""
    h = hashlib.sha256((prev_hash + "\n" + _audit_payload(
        eid, run_id, agent_id, ts, kind, skill, risk, detail_s)).encode()).hexdigest()
    c.execute("INSERT INTO audit(id,run_id,agent_id,ts,kind,skill,risk,detail,prev_hash,hash) "
              "VALUES(?,?,?,?,?,?,?,?,?,?)",
              (eid, run_id, agent_id, ts, kind, skill, risk, detail_s, prev_hash, h))
    c.commit(); c.close()

def verify_audit():
    """Walk the audit log in insertion order and recompute the hash chain. Any edit,
    deletion, or reorder breaks a link and is reported. Rows written before chaining was
    added (no hash) are counted as 'legacy' and reset the chain rather than fail it."""
    c = _conn(); rows = c.execute("SELECT * FROM audit ORDER BY rowid").fetchall(); c.close()
    prev_hash = ""; checked = 0; legacy = 0
    for r in rows:
        d = dict(r)
        if not d.get("hash"):
            legacy += 1; prev_hash = ""; continue
        expect = hashlib.sha256(((d.get("prev_hash") or "") + "\n" + _audit_payload(
            d["id"], d["run_id"], d["agent_id"], d["ts"], d["kind"], d["skill"], d["risk"], d["detail"])).encode()).hexdigest()
        if expect != d["hash"] or (d.get("prev_hash") or "") != prev_hash:
            return {"ok": False, "checked": checked, "legacy": legacy,
                    "broken_at": d["id"], "broken_ts": d["ts"], "total": len(rows)}
        prev_hash = d["hash"]; checked += 1
    return {"ok": True, "checked": checked, "legacy": legacy, "broken_at": None, "total": len(rows)}

def audit_for_run(run_id):
    c = _conn(); rows = c.execute("SELECT * FROM audit WHERE run_id=? ORDER BY ts", (run_id,)).fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["detail"] = json.loads(d["detail"]) if d["detail"] else None; out.append(d)
    return out

def audit_all(limit=200):
    c = _conn(); rows = c.execute("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["detail"] = json.loads(d["detail"]) if d["detail"] else None; out.append(d)
    return out

# ---- approvals ----
def create_approval(run_id, agent_id, skill, risk, arguments):
    c = _conn(); apid = _id("ap")
    c.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,?,?)",
              (apid, run_id, agent_id, skill, risk, json.dumps(arguments),
               "pending", now(), None, None))
    c.commit(); c.close(); return apid

def get_approval(apid):
    c = _conn(); r = c.execute("SELECT * FROM approvals WHERE id=?", (apid,)).fetchone(); c.close()
    if not r: return None
    d = dict(r); d["arguments"] = json.loads(d["arguments"] or "{}"); return d

def decide_approval(apid, status, by="operator"):
    c = _conn()
    c.execute("UPDATE approvals SET status=?, decided_at=?, decided_by=? WHERE id=?",
              (status, now(), by, apid))
    c.commit(); c.close()

def pending_approvals():
    c = _conn(); rows = c.execute("SELECT * FROM approvals WHERE status='pending' ORDER BY created_at").fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["arguments"] = json.loads(d["arguments"] or "{}"); out.append(d)
    return out

def approvals_for_run(run_id):
    c = _conn(); rows = c.execute("SELECT * FROM approvals WHERE run_id=? ORDER BY created_at", (run_id,)).fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["arguments"] = json.loads(d["arguments"] or "{}"); out.append(d)
    return out

# ---- connections (enabled external MCP servers) ----
def enable_connection(cid, transport, command=None, url=None, token=None):
    import vault
    c = _conn()
    c.execute("INSERT OR REPLACE INTO connections VALUES(?,?,?,?,?,?,?)",
              (cid, transport, command, url, vault.encrypt(token), 1, now()))
    c.commit(); c.close()

def disable_connection(cid):
    c = _conn(); c.execute("DELETE FROM connections WHERE id=?", (cid,)); c.commit(); c.close()

def enabled_connections():
    import vault
    c = _conn(); rows = c.execute("SELECT * FROM connections WHERE enabled=1").fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r)
        out.append({"id": d["id"], "transport": d["transport"], "command": d["command"],
                    "url": d["url"], "token": vault.decrypt(d["token"])})
    return out

def is_enabled(cid):
    c = _conn(); r = c.execute("SELECT 1 FROM connections WHERE id=? AND enabled=1", (cid,)).fetchone(); c.close()
    return bool(r)

# ---- tool risk overrides ----
def set_override(model_key, risk):
    c = _conn(); c.execute("INSERT OR REPLACE INTO tool_overrides VALUES(?,?)", (model_key, risk)); c.commit(); c.close()

def get_override(model_key):
    c = _conn(); r = c.execute("SELECT risk FROM tool_overrides WHERE model_key=?", (model_key,)).fetchone(); c.close()
    return r["risk"] if r else None

def all_overrides():
    c = _conn(); rows = c.execute("SELECT * FROM tool_overrides").fetchall(); c.close()
    return {r["model_key"]: r["risk"] for r in rows}

def approval_counts():
    c = _conn(); rows = c.execute("SELECT status, COUNT(*) n FROM approvals GROUP BY status").fetchall(); c.close()
    return {r["status"]: r["n"] for r in rows}

# ---- policies ----
def create_policy(name, effect, agent_id="*", tool="*", field="", op="", value="", priority=100):
    c = _conn(); pid = _id("pol")
    c.execute("INSERT INTO policies VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (pid, name, int(priority), agent_id or "*", tool or "*",
               field or "", op or "", value or "", effect, 1, now()))
    c.commit(); c.close(); return pid

def list_policies(enabled_only=False):
    c = _conn()
    q = "SELECT * FROM policies"
    if enabled_only:
        q += " WHERE enabled=1"
    q += " ORDER BY priority ASC, created_at ASC"
    rows = c.execute(q).fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r)
        a = get_agent(d["agent_id"]) if d["agent_id"] not in ("*", "", None) else None
        d["agent_name"] = a["name"] if a else None
        out.append(d)
    return out

def get_policy(pid):
    c = _conn(); r = c.execute("SELECT * FROM policies WHERE id=?", (pid,)).fetchone(); c.close()
    return dict(r) if r else None

def toggle_policy(pid, enabled):
    c = _conn(); c.execute("UPDATE policies SET enabled=? WHERE id=?", (1 if enabled else 0, pid))
    c.commit(); c.close()

def delete_policy(pid):
    c = _conn(); c.execute("DELETE FROM policies WHERE id=?", (pid,)); c.commit(); c.close()

# ---- discovered (custom) MCP servers ----
def add_custom_server(sid, name, category, transport, url="", command="", description="", repo=""):
    c = _conn()
    c.execute("INSERT OR REPLACE INTO custom_servers VALUES(?,?,?,?,?,?,?,?,?)",
              (sid, name, category or "Discovered", transport, url or "", command or "",
               description or "", repo or "", now()))
    c.commit(); c.close(); return sid

def list_custom_servers():
    c = _conn(); rows = c.execute("SELECT * FROM custom_servers ORDER BY created_at DESC").fetchall(); c.close()
    return [dict(r) for r in rows]

def get_custom_server(sid):
    c = _conn(); r = c.execute("SELECT * FROM custom_servers WHERE id=?", (sid,)).fetchone(); c.close()
    return dict(r) if r else None

def delete_custom_server(sid):
    c = _conn(); c.execute("DELETE FROM custom_servers WHERE id=?", (sid,)); c.commit(); c.close()
