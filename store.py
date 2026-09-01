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
    acols = [r["name"] for r in c.execute("PRAGMA table_info(agents)").fetchall()]
    if "icon" not in acols:
        c.execute("ALTER TABLE agents ADD COLUMN icon TEXT")
    if "budget_usd" not in acols:
        c.execute("ALTER TABLE agents ADD COLUMN budget_usd REAL")
    if "owner" not in acols:
        c.execute("ALTER TABLE agents ADD COLUMN owner TEXT")
    if "members" not in acols:
        c.execute("ALTER TABLE agents ADD COLUMN members TEXT")
    rcols = [r["name"] for r in c.execute("PRAGMA table_info(runs)").fetchall()]
    if "owner" not in rcols:
        c.execute("ALTER TABLE runs ADD COLUMN owner TEXT")
    # team runs: a lead's run delegates to member runs, linked back to the parent
    if "parent_run_id" not in rcols:
        c.execute("ALTER TABLE runs ADD COLUMN parent_run_id TEXT")
    if "parent_tool_use_id" not in rcols:
        c.execute("ALTER TABLE runs ADD COLUMN parent_tool_use_id TEXT")
    if "depth" not in rcols:
        c.execute("ALTER TABLE runs ADD COLUMN depth INTEGER DEFAULT 0")
    c.commit(); c.close()

def _agent_row(r):
    d = dict(r)
    d["skills"] = json.loads(d["skills"] or "[]")
    d["members"] = json.loads(d.get("members") or "[]")
    return d

# ---- agents ----
def create_agent(name, instructions, model, skills, icon="", budget_usd=0, owner="", members=None):
    c = _conn(); aid = _id("ag")
    c.execute("INSERT INTO agents(id,name,instructions,model,skills,created_at,icon,budget_usd,owner,members) "
              "VALUES(?,?,?,?,?,?,?,?,?,?)",
              (aid, name, instructions, model, json.dumps(skills), now(), icon or "",
               float(budget_usd or 0), owner or "", json.dumps(list(members or []))))
    c.commit(); c.close(); return aid

def update_agent(aid, name, instructions, model, skills, icon=None, budget_usd=None, members=None):
    c = _conn()
    sets = ["name=?", "instructions=?", "model=?", "skills=?"]
    vals = [name, instructions, model, json.dumps(skills)]
    if icon is not None:
        sets.append("icon=?"); vals.append(icon or "")
    if budget_usd is not None:
        sets.append("budget_usd=?"); vals.append(float(budget_usd or 0))
    if members is not None:
        sets.append("members=?"); vals.append(json.dumps(list(members)))
    vals.append(aid)
    c.execute("UPDATE agents SET " + ", ".join(sets) + " WHERE id=?", vals)
    c.commit(); c.close()

def delete_agent(aid):
    """Remove the agent, its runs, and any pending approvals. The append-only, hash-chained
    audit log is deliberately left intact: erasing what an agent did would break the chain
    and defeat the tamper-evidence. History outlives the agent."""
    c = _conn()
    c.execute("DELETE FROM approvals WHERE agent_id=? AND status='pending'", (aid,))
    c.execute("DELETE FROM runs WHERE agent_id=?", (aid,))
    c.execute("DELETE FROM agents WHERE id=?", (aid,))
    c.commit(); c.close()

def get_agent(aid):
    c = _conn(); r = c.execute("SELECT * FROM agents WHERE id=?", (aid,)).fetchone(); c.close()
    if not r: return None
    return _agent_row(r)

def list_agents(owner=None):
    c = _conn()
    if owner is None:
        rows = c.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
    else:
        rows = c.execute("SELECT * FROM agents WHERE owner=? ORDER BY created_at DESC", (owner,)).fetchall()
    c.close()
    return [_agent_row(r) for r in rows]

def leads_of(agent_id):
    """Agents that list this agent as a team member."""
    c = _conn(); rows = c.execute("SELECT * FROM agents WHERE members LIKE ?", ('%"' + agent_id + '"%',)).fetchall(); c.close()
    return [_agent_row(r) for r in rows if agent_id in (json.loads(r["members"] or "[]"))]

# ---- runs ----
def create_run(agent_id, user_input, parent_run_id=None, parent_tool_use_id=None, depth=0):
    c = _conn(); rid = _id("run")
    ag = c.execute("SELECT owner FROM agents WHERE id=?", (agent_id,)).fetchone()
    owner = ag["owner"] if ag else ""
    c.execute("INSERT INTO runs(id,agent_id,input,status,transcript,created_at,updated_at,owner,"
              "parent_run_id,parent_tool_use_id,depth) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (rid, agent_id, user_input, "running", json.dumps([]), now(), now(), owner or "",
               parent_run_id, parent_tool_use_id, int(depth or 0)))
    c.commit(); c.close(); return rid

def child_runs(rid):
    """Member runs delegated from this run, oldest first."""
    c = _conn(); rows = c.execute("SELECT * FROM runs WHERE parent_run_id=? ORDER BY created_at", (rid,)).fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["transcript"] = json.loads(d["transcript"] or "[]"); out.append(d)
    return out

def run_tree_ids(rid, _acc=None):
    """This run plus every descendant run id."""
    acc = _acc if _acc is not None else [rid]
    for ch in child_runs(rid):
        acc.append(ch["id"]); run_tree_ids(ch["id"], acc)
    return acc

def root_run(run):
    """Walk up to the top-level run of a team tree."""
    seen = set()
    while run and run.get("parent_run_id") and run["id"] not in seen:
        seen.add(run["id"])
        p = get_run(run["parent_run_id"])
        if not p: break
        run = p
    return run

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

def list_runs(limit=50, owner=None, top_level=True):
    """Runs newest first. Member runs (delegated by a lead) are hidden by default; they
    are reached through the lead's conversation."""
    c = _conn()
    where = ["(parent_run_id IS NULL OR parent_run_id='')"] if top_level else []
    args = []
    if owner is not None:
        where.append("owner=?"); args.append(owner)
    q = "SELECT * FROM runs" + ((" WHERE " + " AND ".join(where)) if where else "") + \
        " ORDER BY created_at DESC LIMIT ?"
    rows = c.execute(q, (*args, limit)).fetchall()
    c.close()
    return [dict(r) for r in rows]

def owned_agent_ids(owner):
    c = _conn(); rows = c.execute("SELECT id FROM agents WHERE owner=?", (owner,)).fetchall(); c.close()
    return {r["id"] for r in rows}

def audit_for_owner(owner, limit=300):
    ids = owned_agent_ids(owner)
    if not ids:
        return []
    c = _conn()
    q = "SELECT * FROM audit WHERE agent_id IN (%s) ORDER BY ts DESC LIMIT ?" % ",".join("?" * len(ids))
    rows = c.execute(q, (*ids, limit)).fetchall(); c.close()
    out = []
    for r in rows:
        d = dict(r); d["detail"] = json.loads(d["detail"]) if d["detail"] else None; out.append(d)
    return out

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

def cost_since(iso_prefix):
    """Total model-call cost across ALL runs whose audit ts starts with iso_prefix
    (e.g. '2026-08-31' for today, UTC). Powers the global daily spend cap."""
    c = _conn()
    rows = c.execute("SELECT detail FROM audit WHERE kind='model_call' AND ts LIKE ?",
                     (iso_prefix + "%",)).fetchall()
    c.close()
    total = 0.0
    for r in rows:
        try:
            total += (json.loads(r["detail"]) or {}).get("cost", 0) or 0
        except Exception:
            pass
    return round(total, 6)

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

def pending_approvals(owner=None):
    c = _conn()
    if owner is None:
        rows = c.execute("SELECT * FROM approvals WHERE status='pending' ORDER BY created_at").fetchall()
    else:
        ids = owned_agent_ids(owner)
        if not ids:
            c.close(); return []
        q = ("SELECT * FROM approvals WHERE status='pending' AND agent_id IN (%s) ORDER BY created_at"
             % ",".join("?" * len(ids)))
        rows = c.execute(q, tuple(ids)).fetchall()
    c.close()
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

def delete_orphan_agents():
    """Delete agents with no owner (created before per-user isolation existed). Their runs
    and pending approvals go too; the hash-chained audit trail is preserved."""
    c = _conn()
    ids = [r["id"] for r in c.execute("SELECT id FROM agents WHERE owner IS NULL OR owner=''").fetchall()]
    for aid in ids:
        c.execute("DELETE FROM approvals WHERE agent_id=? AND status='pending'", (aid,))
        c.execute("DELETE FROM runs WHERE agent_id=?", (aid,))
        c.execute("DELETE FROM agents WHERE id=?", (aid,))
    c.commit(); c.close()
    return len(ids)
