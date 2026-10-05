"""Shared fixtures. Every test gets a fresh data directory and runs in sandbox mode (no
ANTHROPIC_API_KEY), so the built-in planner stands in for the model and the only MCP server
is builtin_enterprise. Run with:  python -m pytest -q
"""
import os, sys, tempfile, importlib
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ADMIN = "admin@x.com"
ALICE = "alice@x.com"
BOB = "bob@x.com"


@pytest.fixture(scope="session")
def warden():
    """Import the app once against a scratch data dir. Module state (connection manager,
    sqlite path) is process-wide, so tests share one database and use distinct owners."""
    tmp = tempfile.mkdtemp(prefix="warden-test-")
    os.environ.update(WARDEN_DATA_DIR=tmp, WARDEN_PASSWORD="pw", WARDEN_ADMIN_EMAILS=ADMIN,
                      WARDEN_SECRET_KEY="test-secret-not-for-production",
                      GOOGLE_CLIENT_ID="x", GOOGLE_CLIENT_SECRET="y")
    os.environ.pop("ANTHROPIC_API_KEY", None)
    for m in ("paths", "store", "vault", "governance", "policy", "connection_manager", "agent_runtime", "app"):
        sys.modules.pop(m, None)
    import app as A
    import store, agent_runtime as rt
    A.app.config["TESTING"] = True
    return {"app": A, "store": store, "rt": rt}


@pytest.fixture
def client(warden):
    return warden["app"].app.test_client()


def login(client, email, hat="agents"):
    with client.session_transaction() as s:
        s["auth"] = True; s["email"] = email; s["hat"] = hat
    return client


def K(tool):
    return "builtin_enterprise__" + tool
