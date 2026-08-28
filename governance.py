"""
The governance layer. Warden's point of view: tools can do things; governance decides
which run on their own and which pause for a human. Built-in enterprise tools have a
hand-set risk registry. Tools discovered from external MCP servers are classified
automatically, fail-closed: reads run, writes and anything unrecognized are gated.
An operator can override any tool's risk.
"""
SKILLS = {
    "lookup_customer": {"risk":"LOW","gate":"auto","kind":"read"},
    "search_knowledge":{"risk":"LOW","gate":"auto","kind":"read"},
    "create_ticket":   {"risk":"MED","gate":"auto","kind":"write"},
    "issue_refund":    {"risk":"HIGH","gate":"approval","kind":"write"},
    "list_files":      {"risk":"LOW","gate":"auto","kind":"read"},
    "read_file":       {"risk":"LOW","gate":"auto","kind":"read"},
    "write_file":      {"risk":"HIGH","gate":"approval","kind":"write"},
}

READ_HINTS  = ("get","list","read","search","lookup","fetch","find","query","view",
               "describe","show","count","status","summary","recent")
WRITE_HINTS = ("create","write","update","delete","remove","issue","send","post","add",
               "set","merge","close","open","deploy","execute","run","refund","cancel",
               "approve","edit","upload","move","rename","revoke","grant","pay","charge")

def classify(name, desc=""):
    """Heuristic risk for an external tool, judged by its leading verb.
    Fail-closed: unrecognized => HIGH."""
    import re
    n = (name or "").lower().replace("-", "_")
    lead = re.match(r"[a-z]+", n)
    lead = lead.group(0) if lead else n           # leading alpha run (handles camelCase)
    first = n.split("_")[0]                         # first snake_case token
    for h in READ_HINTS:
        if first == h or lead.startswith(h):
            return "LOW"
    for h in WRITE_HINTS:
        if first == h or lead.startswith(h):
            return "HIGH"
    return "HIGH"

def meta(model_key, tool_name, desc="", override=None):
    """Resolve effective governance for a tool. Precedence: override > known registry > classify."""
    if override in ("LOW","MED","HIGH"):
        risk = override
    elif tool_name in SKILLS:
        risk = SKILLS[tool_name]["risk"]
    else:
        risk = classify(tool_name, desc)
    return {"risk": risk, "gate": "approval" if risk == "HIGH" else "auto"}

# convenience wrappers used where only a bare name is available (built-ins)
def skill_meta(name):
    m = SKILLS.get(name)
    if m: return m
    r = classify(name)
    return {"risk": r, "gate": "approval" if r=="HIGH" else "auto", "kind":"?"}
def requires_approval(name):
    return skill_meta(name)["gate"] == "approval"
def risk_of(name):
    return skill_meta(name)["risk"]
