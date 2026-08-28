"""
The governance layer. This is Warden's point of view: the MCP server exposes tools
that *can* do things; governance decides which ones an agent may run on its own and
which must pause for a human. Risk is a property of the action, not the prompt.
"""

# risk registry: maps each skill (tool) to a risk tier and a gate decision.
# LOW  = read only, auto-run.
# MED  = writes something reversible, auto-run but always audited prominently.
# HIGH = moves money or is otherwise irreversible, REQUIRES human approval.
SKILLS = {
    "lookup_customer": {"risk": "LOW",  "kind": "read",  "gate": "auto",
                        "label": "Look up customer"},
    "search_knowledge": {"risk": "LOW",  "kind": "read",  "gate": "auto",
                        "label": "Search knowledge base"},
    "create_ticket":   {"risk": "MED",  "kind": "write", "gate": "auto",
                        "label": "Open a ticket"},
    "issue_refund":    {"risk": "HIGH", "kind": "write", "gate": "approval",
                        "label": "Issue a refund"},
}

RISK_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2}

def skill_meta(name):
    return SKILLS.get(name, {"risk": "HIGH", "kind": "write", "gate": "approval",
                             "label": name})

def requires_approval(name):
    """Any skill not explicitly known is treated as high-risk and gated (fail closed)."""
    return skill_meta(name)["gate"] == "approval"

def risk_of(name):
    return skill_meta(name)["risk"]
