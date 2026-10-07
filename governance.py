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
    "list_source":     {"risk":"LOW","gate":"auto","kind":"read"},
    "read_source":     {"risk":"LOW","gate":"auto","kind":"read"},
    # team hand-off: a lead delegating to a member. Auto by default (the member's own
    # tools stay governed); override to HIGH to make every hand-off ask a human first.
    "delegate":        {"risk":"MED","gate":"auto","kind":"delegate"},
    # asking the operator to connect a capability; no side effects until a human connects it
    "request_connection": {"risk":"LOW","gate":"auto","kind":"request"},
}

READ_HINTS  = ("get","list","read","search","lookup","fetch","find","query","view",
               "describe","show","count","status","summary","recent","ask","explore",
               "inspect","check","scrape","crawl","browse","retrieve","download","ls",
               "cat","head","tail","grep","stat","info","preview","watch","poll")
WRITE_HINTS = ("create","write","update","delete","remove","issue","send","post","add",
               "set","merge","close","open","deploy","execute","run","refund","cancel",
               "approve","edit","upload","move","rename","revoke","grant","pay","charge",
               "put","patch","insert","drop","truncate","purge","destroy","kill","restart",
               "reset","push","commit","publish","archive","restore","transfer","assign",
               "invite","ban","mute","reply","forward","submit","trigger","start","stop",
               "schedule","modify","replace","append","clear","mark","label","release",
               "checkout","rollback","migrate","exec","eval","apply","install","uninstall")

# the hand-set registry applies to Warden's sample server and its two virtual tools only
_REGISTRY_PREFIXES = ("builtin_enterprise__",)
_VIRTUAL = ("delegate", "request_connection")

def _tokens(name):
    """snake_case, kebab-case and camelCase split into lower-case words."""
    import re
    n = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return [t for t in re.split(r"[^a-zA-Z0-9]+", n.lower()) if t]

def classify(name, desc="", annotations=None):
    """Heuristic risk for an external tool. Precedence:
    1. the server's own MCP annotations: readOnlyHint true => LOW, destructiveHint true => HIGH;
    2. the strongest verb anywhere in the name: one write verb makes it HIGH, so
       find_and_replace, showAndDelete and get_or_create are writes, not reads;
    3. a name made only of read verbs => LOW;
    4. anything else => HIGH (fail closed)."""
    a = annotations or {}
    if a.get("readOnlyHint") is True and a.get("destructiveHint") is not True:
        return "LOW"
    if a.get("destructiveHint") is True:
        return "HIGH"
    toks = _tokens(name)
    if any(t in WRITE_HINTS for t in toks):
        return "HIGH"
    if toks and any(t in READ_HINTS for t in toks):
        return "LOW"
    return "HIGH"

def meta(model_key, tool_name, desc="", override=None, annotations=None):
    """Resolve effective governance for a tool. Precedence: admin override > the hand-set
    registry (only for Warden's own sample server and virtual tools; an external server's
    tool that happens to be called read_file is classified like any other) > classify."""
    if override in ("LOW","MED","HIGH"):
        risk = override
    elif tool_name in SKILLS and (not model_key or model_key.startswith(_REGISTRY_PREFIXES) or tool_name in _VIRTUAL):
        risk = SKILLS[tool_name]["risk"]
    else:
        risk = classify(tool_name, desc, annotations)
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
