"""
Persistence for Warden: agents, runs, the audit log, and the approvals queue.
SQLite on disk. On a platform with an ephemeral filesystem (Render) this resets on
redeploy, which is fine for a demo; the point is that within a session every agent
action and every approval is durably recorded and queryable.
"""
import os
import json
import sqlite3
import datetime
import uuid

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "warden.db")

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
      kind TEXT, skill TEXT, risk TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS approvals(
      id TEXT PRIMARY KEY, run_id TEXT, agent_id TEXT, skill TEXT, risk TEXT,
      arguments TEXT, status TEXT, created_at TEXT, decided_at TEXT, decided_by TEXT);
    CREATE TABLE IF NOT EXISTS connections(
      id TEXT PRIMARY KEY, transport TEXT, command TEXT, url TEXT, token TEXT,
      enabled INTEGER, created_at TEXT);
    CREATE TABLE IF NOT EXISTS tool_overrides(
      model_key TEXT PRIMARY KEY, risk TEXT);
    """)
    c.commit(); c.close()

# ---- agents ----
def create_agent(name, instructions, model, skills):
    c = _conn(); aid = _id("ag")
    c.execute("INSERT INTO agents VALUES(?,?,?,?,?,?)",
              (aid, name, instructions, model, json.dumps(skills), now()))
    c.commit(); c.close(); return aid

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

# ---- audit ----
def audit(run_id, agent_id, kind, skill=None, risk=None, detail=None):
    c = _conn()
    c.execute("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?)",
              (_id("ev"), run_id, agent_id, now(), kind, skill, risk,
               json.dumps(detail) if detail is not None else None))
    c.commit(); c.close()

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
    c = _conn()
    c.execute("INSERT OR REPLACE INTO connections VALUES(?,?,?,?,?,?,?)",
              (cid, transport, command, url, token, 1, now()))
    c.commit(); c.close()

def disable_connection(cid):
    c = _conn(); c.execute("DELETE FROM connections WHERE id=?", (cid,)); c.commit(); c.close()

def enabled_connections():
    c = _conn(); rows = c.execute("SELECT * FROM connections WHERE enabled=1").fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["id"] = d["id"]; out.append(
            {"id": d["id"], "transport": d["transport"], "command": d["command"],
             "url": d["url"], "token": d["token"]})
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
