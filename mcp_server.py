"""
Warden MCP server: a real Model Context Protocol server exposing a small set of
enterprise-flavored tools. The Warden runtime connects to this as an MCP client,
discovers these tools over the protocol, and invokes them.

Tools deliberately span read and write so the governance layer has something to
govern: reads are low risk and auto-execute; writes change state and are the ones
the studio gates behind human approval.

Run standalone for a protocol smoke test:  python mcp_server.py
(but normally it is spawned over stdio by the runtime's MCP client)
"""
import json
import os
import datetime
from mcp.server.fastmcp import FastMCP

import paths
DATA_DIR = os.path.join(paths.DATA_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

CUSTOMERS = {
    "AC-1001": {"account_id": "AC-1001", "name": "Rivera Logistics", "plan": "Enterprise",
                "mrr": 4200, "status": "active", "last_charge": 4200,
                "notes": "Charged twice on 2026-08-03 due to a billing retry bug."},
    "AC-1002": {"account_id": "AC-1002", "name": "Halcyon Health", "plan": "Premium",
                "mrr": 1800, "status": "active", "last_charge": 1800, "notes": ""},
    "AC-1003": {"account_id": "AC-1003", "name": "Meridian Foods", "plan": "Standard",
                "mrr": 600, "status": "past_due", "last_charge": 0,
                "notes": "Payment failed twice this month."},
}

KB = [
    {"id": "kb-01", "title": "Refund policy",
     "body": "Duplicate charges are refunded in full once verified against the billing ledger. "
             "Refunds above 1000 require a human approver."},
    {"id": "kb-02", "title": "Past-due accounts",
     "body": "Do not issue credits on past-due accounts until the balance is cleared. "
             "Open a billing ticket instead."},
    {"id": "kb-03", "title": "Escalation",
     "body": "Anything touching money movement is a governed action and must be logged."},
]

def _ledger_path(name):
    return os.path.join(DATA_DIR, name)

def _append(name, row):
    path = _ledger_path(name)
    rows = []
    if os.path.exists(path):
        rows = json.load(open(path))
    row["at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    rows.append(row)
    json.dump(rows, open(path, "w"), indent=2)
    return row

mcp = FastMCP("warden-enterprise-tools")

@mcp.tool()
def lookup_customer(account_id: str) -> str:
    """Look up an enterprise customer account by id (e.g. AC-1001). Read only."""
    rec = CUSTOMERS.get(account_id.strip().upper())
    if not rec:
        return json.dumps({"error": f"no account {account_id}"})
    return json.dumps(rec)

@mcp.tool()
def search_knowledge(query: str) -> str:
    """Search the internal knowledge base for policy and guidance. Read only."""
    q = query.lower()
    hits = [a for a in KB if q in a["title"].lower() or q in a["body"].lower()]
    if not hits:
        hits = KB  # fall back to returning all short KB so the agent has context
    return json.dumps(hits)

@mcp.tool()
def create_ticket(subject: str, body: str) -> str:
    """Open an internal billing/support ticket. Write action (changes state)."""
    row = _append("tickets.json", {"id": f"TK-{abs(hash(subject)) % 9000 + 1000}",
                                   "subject": subject, "body": body})
    return json.dumps({"created": True, "ticket": row})

@mcp.tool()
def issue_refund(account_id: str, amount: float, reason: str = "") -> str:
    """Issue a monetary refund to a customer account. High-impact write action:
    moves money, so the studio gates this behind human approval before it runs."""
    acct = account_id.strip().upper()
    if acct not in CUSTOMERS:
        return json.dumps({"error": f"no account {account_id}"})
    row = _append("refunds.json", {"id": f"RF-{abs(hash(acct + str(amount))) % 9000 + 1000}",
                                   "account_id": acct, "amount": float(amount), "reason": reason})
    return json.dumps({"refunded": True, "refund": row})

if __name__ == "__main__":
    mcp.run()
