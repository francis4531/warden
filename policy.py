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
__weekday__ (0=Mon), __risk__ (LOW/MED/HIGH). Any other field reads the tool's arguments.
"""
import store

EFFECTS = ("allow", "require_approval", "deny")
OPS = (">", ">=", "<", "<=", "==", "!=", "contains", "exists")

def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

def _cmp(left, op, right):
    if op == "exists":
        return left is not None
    if op == "==":
        return str(left) == str(right)
    if op == "!=":
        return str(left) != str(right)
    if op == "contains":
        return left is not None and str(right).lower() in str(left).lower()
    ln, rn = _num(left), _num(right)
    if ln is None or rn is None:
        return False
    return {">": ln > rn, ">=": ln >= rn, "<": ln < rn, "<=": ln <= rn}[op]

def _resolve(field, args, ctx):
    if field in ("__count__", "__hour__", "__weekday__", "__risk__"):
        return ctx.get(field.strip("_"))
    if isinstance(args, dict):
        return args.get(field)
    return None

def _tool_name(t):
    return (t or "").split("__")[-1]

def _matches(p, agent_id, tool, args, ctx):
    if p["agent_id"] not in ("*", "", None, agent_id):
        return False
    if p["tool"] not in ("*", "", None, tool, _tool_name(tool)):
        return False
    if not p["field"]:
        return True                      # scope-only rule, no condition
    return _cmp(_resolve(p["field"], args, ctx), p["op"], p["value"])

def evaluate(agent_id, tool, args, ctx):
    """Return the first matching policy's effect, or {'effect': None} to fall back to
    the risk-tier default. tool may be the namespaced key or the bare tool name."""
    tool = _tool_name(tool)
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
