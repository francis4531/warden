"""
MCP client wrapper, thread-safe for a web server.

Web servers dispatch requests on worker threads, and asyncio subprocess transports
(which MCP's stdio client uses) do not run reliably off the main thread. So we own a
single dedicated thread that runs one asyncio event loop for the process, attach a
ThreadedChildWatcher to it, and marshal every MCP call onto that loop with
run_coroutine_threadsafe. We also keep ONE long-lived session to a single server
subprocess and reuse it, instead of spawning a server per call.
"""
import os
import sys
import asyncio
import threading
import warnings
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")

def _server_params():
    return StdioServerParameters(command=sys.executable, args=[_SERVER], env=os.environ.copy())

class _LoopThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                watcher = asyncio.ThreadedChildWatcher()
                watcher.attach_loop(self.loop)
                asyncio.set_child_watcher(watcher)
            except Exception:
                pass
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        self._session = None
        self._keep = []

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result()

    async def _ensure(self):
        if self._session is not None:
            return self._session
        stdio_cm = stdio_client(_server_params())
        read, write = await stdio_cm.__aenter__()
        sess_cm = ClientSession(read, write)
        session = await sess_cm.__aenter__()
        await session.initialize()
        self._keep = [stdio_cm, sess_cm]
        self._session = session
        return session

    async def _list(self):
        s = await self._ensure()
        resp = await s.list_tools()
        return [{"name": t.name, "description": t.description or "",
                 "input_schema": t.inputSchema} for t in resp.tools]

    async def _call(self, name, arguments):
        s = await self._ensure()
        result = await s.call_tool(name, arguments or {})
        parts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
        return "\n".join(parts)

_LT = None
_LT_LOCK = threading.Lock()
_CALL_LOCK = threading.Lock()  # serialize MCP ops (one shared session per process)

def _lt():
    global _LT
    with _LT_LOCK:
        if _LT is None:
            _LT = _LoopThread()
        return _LT

def list_tools():
    lt = _lt()
    with _CALL_LOCK:
        return lt.run(lt._list())

def call_tool(name, arguments):
    lt = _lt()
    with _CALL_LOCK:
        return lt.run(lt._call(name, arguments))

if __name__ == "__main__":
    print("discovery:", [t["name"] for t in list_tools()])
    print("call:", call_tool("lookup_customer", {"account_id": "AC-1001"})[:80])
