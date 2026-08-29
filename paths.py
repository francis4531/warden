"""
Resolves where Warden stores its data. Prefers WARDEN_DATA_DIR (a mounted persistent
disk in production). If that path can't be created or written, it falls back to a
writable local directory instead of crashing the app, and records that it fell back so
the condition is visible on /healthz. A misconfigured disk should degrade to ephemeral,
never take the service down.
"""
import os

_APPDIR = os.path.dirname(os.path.abspath(__file__))
REQUESTED = os.environ.get("WARDEN_DATA_DIR") or _APPDIR

def _writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        t = os.path.join(path, ".wtest")
        with open(t, "w") as f:
            f.write("ok")
        os.remove(t)
        return True
    except Exception:
        return False

def _resolve():
    if _writable(REQUESTED):
        return REQUESTED, False
    fallback = os.path.join(_APPDIR, "_localdata")
    if _writable(fallback):
        return fallback, True
    return _APPDIR, True

DATA_ROOT, FALLBACK = _resolve()
