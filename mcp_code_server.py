"""
Warden self-audit MCP server. Exposes Warden's own source code to an agent so a
"Warden Engineer" agent can inspect the running codebase, run a real static self-check,
and propose fixes. Reads are safe and auto-run; proposing a patch is a gated write that
lands in a review folder (it never overwrites the running source).
"""
import os, json, ast, py_compile, tempfile
from mcp.server.fastmcp import FastMCP

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PATCH_DIR = os.path.join(APP_DIR, "data", "patches")
os.makedirs(PATCH_DIR, exist_ok=True)

def _py_files():
    return sorted(f for f in os.listdir(APP_DIR) if f.endswith(".py"))

mcp = FastMCP("warden-self-audit")

@mcp.tool()
def list_source() -> str:
    """List Warden's own Python source files with line counts. Read only."""
    out = []
    for f in _py_files():
        n = sum(1 for _ in open(os.path.join(APP_DIR, f), encoding="utf-8", errors="replace"))
        out.append({"file": f, "lines": n})
    return json.dumps(out)

@mcp.tool()
def read_source(filename: str) -> str:
    """Read one of Warden's own source files. Read only."""
    if filename not in _py_files():
        return json.dumps({"error": f"no source file {filename}", "available": _py_files()})
    return open(os.path.join(APP_DIR, filename), encoding="utf-8", errors="replace").read()[:12000]

@mcp.tool()
def run_selfcheck() -> str:
    """Statically check every Warden source file: byte-compile for syntax errors and
    AST-scan for bare excepts and TODO/FIXME markers. Runs real checks; no side effects."""
    findings = []
    for f in _py_files():
        path = os.path.join(APP_DIR, f)
        try:
            py_compile.compile(path, doraise=True)
        except py_compile.PyCompileError as e:
            findings.append({"file": f, "kind": "syntax_error", "detail": str(e).splitlines()[-1][:160]})
            continue
        src = open(path, encoding="utf-8", errors="replace").read()
        try:
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    findings.append({"file": f, "kind": "bare_except", "line": node.lineno})
        except Exception:
            pass
        try:
            import tokenize, io
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type == tokenize.COMMENT and ("TODO" in tok.string.upper() or "FIXME" in tok.string.upper()):
                    findings.append({"file": f, "kind": "todo", "line": tok.start[0], "detail": tok.string.strip()[:120]})
        except Exception:
            pass
    return json.dumps({"files_checked": len(_py_files()),
                       "findings": findings, "clean": len(findings) == 0})

@mcp.tool()
def propose_patch(filename: str, new_content: str, rationale: str = "") -> str:
    """Propose a fix for a source file. Gated write: saves the proposed version to a
    review folder for a human to inspect and apply. Never edits the running source."""
    safe = os.path.basename(filename)
    out = os.path.join(PATCH_DIR, safe)
    open(out, "w", encoding="utf-8").write(new_content)
    meta = os.path.join(PATCH_DIR, safe + ".rationale.txt")
    open(meta, "w", encoding="utf-8").write(rationale or "(none)")
    return json.dumps({"proposed": True, "review_path": f"data/patches/{safe}",
                       "bytes": len(new_content), "note": "saved for human review; running source unchanged"})

if __name__ == "__main__":
    mcp.run()
