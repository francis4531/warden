"""
Multi-server MCP connection manager.

Owns one dedicated asyncio loop thread for the process and keeps a persistent session
to each connected MCP server (built-in local servers plus any the user enables from the
catalog: stdio commands or remote HTTP endpoints). Discovers tools across all connected
servers and exposes them under model-safe names, routing each call back to its server.
"""
import os, sys, asyncio, threading, warnings, shlex
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
try:
    from mcp.client.streamable_http import streamablehttp_client
    _HTTP_OK = True
except Exception:
    _HTTP_OK = False

import catalog as catalog_mod

HERE = os.path.dirname(os.path.abspath(__file__))

# built-in servers always available (local Python MCP servers this app ships)
BUILTINS = {
    "builtin_enterprise": [sys.executable, os.path.join(HERE, "mcp_server.py")],
    "builtin_files":      [sys.executable, os.path.join(HERE, "mcp_fs_server.py")],
}

class _LoopThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                w = asyncio.ThreadedChildWatcher(); w.attach_loop(self.loop)
                asyncio.set_child_watcher(w)
            except Exception:
                pass
        threading.Thread(target=self._run, daemon=True).start()
    def _run(self):
        asyncio.set_event_loop(self.loop); self.loop.run_forever()
    def run(self, coro, timeout=None):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

class _Manager:
    def __init__(self):
        self._lt = _LoopThread()
        self._lock = threading.Lock()
        self._sessions = {}     # server_id -> session
        self._keep = {}         # server_id -> [context managers]
        self._status = {}       # server_id -> {"status","error","name","transport","tool_count"}
        self._toolmap = {}      # model_name -> (server_id, tool_name)
        self._started = False

    # ---- lifecycle ----
    def ensure_started(self, enabled_specs=None):
        with self._lock:
            if not self._started:
                for sid in BUILTINS:
                    self._connect(sid, {"id": sid, "transport": "builtin"})
                self._started = True
            for spec in (enabled_specs or []):
                if spec["id"] not in self._sessions:
                    self._connect(spec["id"], spec)
            self._rebuild_toolmap()

    def connect_spec(self, spec):
        with self._lock:
            self._connect(spec["id"], spec)
            self._rebuild_toolmap()
        return self._status.get(spec["id"])

    def disconnect(self, sid):
        with self._lock:
            self._sessions.pop(sid, None); self._keep.pop(sid, None)
            self._status.pop(sid, None); self._rebuild_toolmap()

    # ---- internals (run on loop thread) ----
    def _connect(self, sid, spec):
        cat = catalog_mod.BY_ID.get(sid, {})
        name = cat.get("name", sid)
        transport = spec.get("transport") or cat.get("transport", "stdio_node")
        try:
            self._lt.run(self._aopen(sid, spec, transport), timeout=75)
            tools = self._lt.run(self._alist(sid), timeout=30)
            self._status[sid] = {"status": "connected", "error": None, "name": name,
                                 "transport": transport, "tool_count": len(tools)}
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            self._status[sid] = {"status": "error", "error": msg[:200], "name": name,
                                 "transport": transport, "tool_count": 0}

    async def _aopen(self, sid, spec, transport):
        if transport == "http":
            if not _HTTP_OK:
                raise RuntimeError("HTTP transport unavailable in this build")
            url = spec.get("url") or catalog_mod.BY_ID.get(sid, {}).get("run")
            headers = {}
            tok = spec.get("token")
            if tok:
                headers["Authorization"] = tok if tok.lower().startswith("bearer") else f"Bearer {tok}"
            cm = streamablehttp_client(url, headers=headers or None)
            read, write, _ = await cm.__aenter__()
        else:
            if transport == "builtin":
                cmd = BUILTINS[sid]
            else:
                run = spec.get("command") or catalog_mod.BY_ID.get(sid, {}).get("run", "")
                cmd = shlex.split(run)
                if not cmd:
                    raise RuntimeError("no command configured")
            params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=os.environ.copy())
            cm = stdio_client(params)
            read, write = await cm.__aenter__()
        sess_cm = ClientSession(read, write)
        session = await sess_cm.__aenter__()
        await session.initialize()
        self._keep[sid] = [cm, sess_cm]
        self._sessions[sid] = session

    async def _alist(self, sid):
        s = self._sessions[sid]
        resp = await s.list_tools()
        return [{"name": t.name, "description": t.description or "", "input_schema": t.inputSchema}
                for t in resp.tools]

    async def _acall(self, sid, tool, args):
        s = self._sessions[sid]
        result = await s.call_tool(tool, args or {})
        return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")

    def _rebuild_toolmap(self):
        self._toolmap = {}
        for sid in self._sessions:
            for t in self._lt.run(self._alist(sid)):
                model_name = f"{sid}__{t['name']}"[:64]
                self._toolmap[model_name] = (sid, t["name"])

    # ---- public queries ----
    def connected_servers(self):
        return [dict(id=sid, **self._status[sid]) for sid in self._status]

    def all_tools(self):
        out = []
        with self._lock:
            for sid, session in self._sessions.items():
                sname = self._status.get(sid, {}).get("name", sid)
                for t in self._lt.run(self._alist(sid)):
                    key = f"{sid}__{t['name']}"[:64]
                    self._toolmap[key] = (sid, t["name"])
                    out.append({"key": key, "server_id": sid, "server_name": sname,
                                "tool": t["name"], "description": t["description"],
                                "input_schema": t["input_schema"]})
        return out

    def call_by_key(self, key, args):
        sid, tool = self._toolmap.get(key, (None, None))
        if sid is None:
            return '{"error":"unknown tool ' + str(key) + '"}'
        with self._lock:
            return self._lt.run(self._acall(sid, tool, args), timeout=90)

_CM = None
_CM_LOCK = threading.Lock()
def manager():
    global _CM
    with _CM_LOCK:
        if _CM is None:
            _CM = _Manager()
    return _CM
