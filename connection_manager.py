"""
Multi-server MCP connection manager.

Owns one dedicated asyncio loop thread. Tool discovery is done once at connect time and
cached, so listing tools never re-hits a server. For execution: stdio/builtin servers
keep a persistent session (subprocess spawn is expensive); HTTP servers open a fresh
short-lived session per call, entirely within one coroutine, because the streamable-HTTP
transport binds its cancel scope to the creating task and cannot be reused across tasks.
"""
import os, sys, asyncio, threading, warnings, shlex
from contextlib import asynccontextmanager
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
try:
    from mcp.client.streamable_http import streamablehttp_client
    _HTTP_OK = True
except Exception:
    _HTTP_OK = False

import catalog as catalog_mod

HERE = os.path.dirname(os.path.abspath(__file__))
BUILTINS = {
    "builtin_enterprise": [sys.executable, os.path.join(HERE, "mcp_server.py")],
    "builtin_files":      [sys.executable, os.path.join(HERE, "mcp_fs_server.py")],
    "builtin_code":       [sys.executable, os.path.join(HERE, "mcp_code_server.py")],
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

def _http_params(sid, spec):
    url = spec.get("url") or catalog_mod.BY_ID.get(sid, {}).get("run")
    headers = {}
    tok = spec.get("token")
    if tok:
        headers["Authorization"] = tok if tok.lower().startswith("bearer") else f"Bearer {tok}"
    return url, (headers or None)

def _stdio_params(sid, spec, transport):
    if transport == "builtin":
        cmd = BUILTINS[sid]
    else:
        run = spec.get("command") or catalog_mod.BY_ID.get(sid, {}).get("run", "")
        cmd = shlex.split(run)
        if not cmd:
            raise RuntimeError("no command configured")
    return StdioServerParameters(command=cmd[0], args=cmd[1:], env=os.environ.copy())

@asynccontextmanager
async def _http_session(sid, spec):
    url, headers = _http_params(sid, spec)
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session

class _Manager:
    def __init__(self):
        self._lt = _LoopThread()
        self._lock = threading.Lock()
        self._sessions = {}   # sid -> persistent session (stdio/builtin only)
        self._keep = {}       # sid -> [context managers] to keep alive
        self._http = {}       # sid -> spec (http servers, fresh session per call)
        self._toolcache = {}  # sid -> [ {name,description,input_schema} ]  (from connect)
        self._status = {}     # sid -> status dict
        self._toolmap = {}    # model_name -> (sid, tool)
        self._started = False

    def ensure_started(self, enabled_specs=None):
        with self._lock:
            if not self._started:
                for sid in BUILTINS:
                    self._connect(sid, {"id": sid, "transport": "builtin"})
                self._started = True
            for spec in (enabled_specs or []):
                if spec["id"] not in self._status:
                    self._connect(spec["id"], spec)
            self._rebuild_toolmap()

    def connect_spec(self, spec):
        with self._lock:
            self._connect(spec["id"], spec); self._rebuild_toolmap()
        return self._status.get(spec["id"])

    def disconnect(self, sid):
        with self._lock:
            self._sessions.pop(sid, None); self._keep.pop(sid, None)
            self._http.pop(sid, None); self._toolcache.pop(sid, None)
            self._status.pop(sid, None); self._rebuild_toolmap()

    # ---- connect (on loop thread) ----
    def _connect(self, sid, spec):
        cat = catalog_mod.BY_ID.get(sid, {})
        name = cat.get("name", sid)
        transport = spec.get("transport") or cat.get("transport", "stdio_node")
        try:
            tools = self._lt.run(self._aopen(sid, spec, transport), timeout=75)
            self._toolcache[sid] = tools
            self._status[sid] = {"status": "connected", "error": None, "name": name,
                                 "transport": transport, "tool_count": len(tools)}
        except Exception as e:
            self._status[sid] = {"status": "error", "error": (str(e) or e.__class__.__name__)[:200],
                                 "name": name, "transport": transport, "tool_count": 0}

    async def _aopen(self, sid, spec, transport):
        if transport == "http":
            if not _HTTP_OK:
                raise RuntimeError("HTTP transport unavailable in this build")
            self._http[sid] = spec
            async with _http_session(sid, spec) as session:      # validate + discover, same task
                resp = await session.list_tools()
                return _tools(resp)
        # stdio / builtin: persistent session
        params = _stdio_params(sid, spec, transport)
        cm = stdio_client(params)
        read, write = await cm.__aenter__()
        sess_cm = ClientSession(read, write)
        session = await sess_cm.__aenter__()
        await session.initialize()
        self._keep[sid] = [cm, sess_cm]; self._sessions[sid] = session
        resp = await session.list_tools()
        return _tools(resp)

    async def _acall(self, sid, tool, args):
        if sid in self._http:
            async with _http_session(sid, self._http[sid]) as session:   # fresh, same task
                result = await session.call_tool(tool, args or {})
                return _text(result)
        result = await self._sessions[sid].call_tool(tool, args or {})
        return _text(result)

    def _rebuild_toolmap(self):
        self._toolmap = {}
        for sid, tools in self._toolcache.items():
            for t in tools:
                self._toolmap[f"{sid}__{t['name']}"[:64]] = (sid, t["name"])

    # ---- queries (use cache; no live calls) ----
    def connected_servers(self):
        return [dict(id=sid, **self._status[sid]) for sid in self._status]

    def all_tools(self):
        out = []
        with self._lock:
            for sid, tools in self._toolcache.items():
                sname = self._status.get(sid, {}).get("name", sid)
                for t in tools:
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

def _tools(resp):
    return [{"name": t.name, "description": t.description or "", "input_schema": t.inputSchema}
            for t in resp.tools]
def _text(result):
    return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")

_CM = None
_CM_LOCK = threading.Lock()
def manager():
    global _CM
    with _CM_LOCK:
        if _CM is None:
            _CM = _Manager()
    return _CM
