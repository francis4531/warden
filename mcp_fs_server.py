"""
Warden's built-in Filesystem MCP server. A real second MCP server (local, Python) so
multi-server connection and routing is demonstrable without needing Node. All access
is confined to a sandbox workspace directory.
"""
import os
import json
from mcp.server.fastmcp import FastMCP

WORKSPACE = os.path.join(os.environ.get("WARDEN_DATA_DIR", os.path.dirname(os.path.abspath(__file__))), "data", "workspace")
os.makedirs(WORKSPACE, exist_ok=True)

# seed one file so reads have something to find
_seed = os.path.join(WORKSPACE, "welcome.txt")
if not os.path.exists(_seed):
    open(_seed, "w").write("Warden workspace. Files here are readable and writable by agents, under governance.\n")

def _safe(path):
    p = os.path.abspath(os.path.join(WORKSPACE, path.lstrip("/")))
    if not p.startswith(os.path.abspath(WORKSPACE)):
        raise ValueError("path escapes workspace")
    return p

mcp = FastMCP("warden-filesystem")

@mcp.tool()
def list_files(subdir: str = "") -> str:
    """List files in the workspace (or a subdirectory). Read only."""
    base = _safe(subdir)
    if not os.path.exists(base):
        return json.dumps({"error": "no such path"})
    return json.dumps(sorted(os.listdir(base)))

@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file from the workspace. Read only."""
    p = _safe(path)
    if not os.path.isfile(p):
        return json.dumps({"error": f"no file {path}"})
    return open(p, encoding="utf-8", errors="replace").read()[:8000]

@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a text file in the workspace. Write action (changes state)."""
    p = _safe(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(content)
    return json.dumps({"written": True, "path": path, "bytes": len(content)})

if __name__ == "__main__":
    mcp.run()
