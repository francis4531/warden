"""
Policy engine. Governance beyond per-tool risk tiers.

A policy is an ordered rule that matches on (agent, tool, condition) and yields an
effect: allow (run without a gate), require_approval (hold for a human), or deny (block).
Policies are evaluated top to bottom by priority; the first match wins. If nothing matches,
the runtime falls back to the risk-tier default (HIGH gates, everything else auto-runs).

This lets a human express real controls:
  - spend caps        issue_refund where amount > 500        -> require_approval
  - auto-approve small issue_refund where amount <= 100       -> allow
  - rate limits       issue_refund where __count__ >= 3       -> deny
  - off-hours         deploy where __hour__ >= 18             -> require_approval
  - hard scope        * where __risk__ == HIGH  (per agent)   -> deny

Conditions are structured (field, op, value), never eval'd, so a policy can never run code.
Special fields: __count__ (times this tool ran in the run so far), __hour__ (0-23 UTC),
__weekday__ (0=Mon), __risk__ (LOW/MED/HIGH). Any other field reads the tool's arguments
(case-insensitive, dotted paths allowed). String comparisons ignore case and surrounding
whitespace. On a named tool, a condition that cannot be evaluated (the argument is missing
or not a number) fails closed: deny and require_approval rules still match, allow rules do
not; on an any-tool rule the condition simply does not apply to that call. The tool
may be named bare (send), per catalog server (gmail__send), or by full key.
"""
import store

EFFECTS = ("allow", "require_approval", "deny")
OPS = (">", ">=", "<", "<=", "==", "!=", "contains", "exists")

def _num(x):
    if isinstance(x, bool):
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

def _norm(x):
    """Strings compare stripped and case-folded, so ' AC-1003' and 'ac-1003' are the same
    account to a policy as they are to the system behind it."""
    return " ".join(str(x).split()).casefold() if x is not None else None

def _cmp(left, op, right):
    """True / False, or None when the condition cannot be evaluated (field missing, or not
    a number where a number is compared). The caller decides what None means."""
    if op == "exists":
        return left is not None
    if left is None:
        return None
    if op == "==":
        return _norm(left) == _norm(right)
    if op == "!=":
        return _norm(left) != _norm(right)
    if op == "contains":
        return _norm(right) in _norm(left)
    ln, rn = _num(left), _num(right)
    if ln is None or rn is None:
        return None
    return {">": ln > rn, ">=": ln >= rn, "<": ln < rn, "<=": ln <= rn}[op]

def _resolve(field, args, ctx):
    if field in ("__count__", "__hour__", "__weekday__", "__risk__"):
        return ctx.get(field.strip("_"))
    if not isinstance(args, dict):
        return None
    cur = args
    for part in field.split("."):          # dotted path into nested arguments
        if not isinstance(cur, dict):
            return None
        hit = None
        for k, v in cur.items():            # case-insensitive key match
            if isinstance(k, str) and k.casefold() == part.casefold():
                hit = v; break
        if hit is None:
            return None
        cur = hit
    return cur

def _tool_name(t):
    return (t or "").split("__")[-1]

def _catalog_key(t):
    """gmail~1a2b3c4d__send -> gmail__send, so a policy written per catalog server applies to
    every user's own copy of it."""
    sid, _, tool = (t or "").partition("__")
    return sid.split("~")[0] + "__" + tool if tool else t

def _tool_matches(spec, tool):
    spec = (spec or "").strip()
    if spec in ("*", ""):
        return True
    spec = spec.casefold(); tool = (tool or "").casefold()
    return spec in (tool, _tool_name(tool), _catalog_key(tool))

def _matches(p, agent_id, tool, args, ctx):
    if p["agent_id"] not in ("*", "", None, agent_id):
        return False
    if not _tool_matches(p["tool"], tool):
        return False
    if not p["field"]:
        return True                      # scope-only rule, no condition
    r = _cmp(_resolve(p["field"], args, ctx), p["op"], p["value"])
    if r is None:
        # the condition could not be evaluated (argument missing, wrong type). For a rule
        # on a named tool, fail closed: a restricting rule still applies, a relaxing rule
        # does not. For an any-tool rule the field simply does not apply to this tool.
        if (p["tool"] or "").strip() in ("*", ""):
            return False
        return p["effect"] != "allow"
    return r

def evaluate(agent_id, tool, args, ctx):
    """Return the first matching policy's effect, or {'effect': None} to fall back to
    the risk-tier default. tool is the namespaced key; a policy may name the bare tool,
    the catalog server and tool (gmail__send), or the full key."""
    for p in store.list_policies(enabled_only=True):
        if _matches(p, agent_id, tool, args, ctx):
            return {"effect": p["effect"], "id": p["id"], "name": p["name"]}
    return {"effect": None, "id": None, "name": None}

def describe(p):
    """A one-line human summary of a policy, for the UI."""
    scope = []
    if p["agent_id"] and p["agent_id"] != "*":
        scope.append("agent " + (p.get("agent_name") or p["agent_id"]))
    scope.append(("tool " + p["tool"]) if p["tool"] not in ("*", "", None) else "any tool")
    cond = ""
    if p["field"]:
        f = {"__count__": "call count", "__hour__": "hour (UTC)",
             "__weekday__": "weekday", "__risk__": "risk"}.get(p["field"], p["field"])
        cond = " where %s %s %s" % (f, p["op"], p["value"]) if p["op"] != "exists" else " where %s exists" % f
    verb = {"allow": "auto-run", "require_approval": "require approval", "deny": "deny"}[p["effect"]]
    return "%s%s \u2192 %s" % (", ".join(scope), cond, verb)
