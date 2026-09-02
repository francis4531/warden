"""
Evals: measure whether an agent performs well, on the agent's own terms.

An eval suite belongs to one agent and holds cases (inputs, optionally with an expected
output) and checks. Running a suite creates a real run per case, in evaluation mode:
low-risk tools execute, anything that would need human approval is recorded as held and
never executed. Each check then scores each run.

Three kinds of check, cheapest first:
  code    deterministic assertions over the run (structured, never eval'd)
  golden  compare the final answer against the case's expected output
  judge   an LLM answers one binary question about the answer; humans can mark each
          verdict agree/disagree so the suite reports how far the judge is from you

Every eval run snapshots the agent (instructions, model, tools, budget) so two runs can be
compared check by check, with the instructions diff between them.
"""
import os, re, json, time, threading
import store
import agent_runtime as rt

JUDGE_MODEL = os.environ.get("WARDEN_JUDGE_MODEL", "") or rt.MODEL_DEFAULT

# ---- check catalog (what the UI offers) ----
CODE_KINDS = [
    ("final_contains",     "Answer contains",            "text",   "The final answer must contain this text (case-insensitive)."),
    ("final_not_contains", "Answer does not contain",    "text",   "The final answer must not contain this text."),
    ("final_regex",        "Answer matches pattern",     "text",   "A regular expression the final answer must match."),
    ("red_flag_words",     "No red-flag words",          "text",   "Comma-separated words that must not appear in the answer, e.g. typically, usually, I have issued."),
    ("tool_called",        "Tool was used",              "tool",   "The agent must have called this tool at least once."),
    ("tool_not_called",    "Tool was not used",          "tool",   "The agent must not have called this tool."),
    ("held_action",        "Held for approval",          "tool",   "Governance: this tool must have reached the approval gate (held, not executed)."),
    ("no_held_actions",    "No held actions",            "",       "The run must complete without reaching the approval gate at all."),
    ("max_tool_calls",     "At most N tool calls",       "number", "Upper bound on tool calls in the run."),
    ("max_cost_usd",       "Cost under $N",              "number", "Upper bound on model spend for the run (live mode)."),
    ("no_tool_errors",     "No tool errors",             "",       "Every tool call returned without an error."),
    ("quotes_grounded",    "Quotes are grounded",        "",       "Every quoted span in the answer (\"...\") must appear verbatim in a tool result or the input. A hallucination guard."),
    ("finished",           "Run finished cleanly",       "",       "The run ended with an answer, not an error or a budget stop."),
]
CODE_BY_KIND = {k[0]: k for k in CODE_KINDS}

# ---- gather the facts about a run that checks look at ----
def facts(run_id):
    """Everything a check can look at, in one place: final answer, tools called, held
    actions, errors, cost, plus the text pool quotes must be grounded in. Includes member
    runs, so a team is judged as a whole."""
    ids = store.run_tree_ids(run_id)
    root = store.get_run(run_id)
    f = {"final": "", "status": root["status"] if root else "missing", "tools": [], "held": [], "errors": 0,
         "calls": 0, "cost": 0.0, "pool": [root["input"] if root else ""], "ended": None}
    for rid in ids:
        for e in store.audit_for_run(rid):
            d = e.get("detail") or {}
            k = e["kind"]; tool = (e.get("skill") or "").split("__")[-1]
            if k in ("tool_result", "tool_result_gated"):
                f["tools"].append(tool); f["calls"] += 1
                if d.get("outcome") == "error": f["errors"] += 1
                res = d.get("result")
                f["pool"].append(res if isinstance(res, str) else json.dumps(res, ensure_ascii=False))
            elif k == "eval_held":
                f["held"].append(tool); f["calls"] += 1
            elif k == "approval_request":
                f["held"].append(tool)
            elif k == "model_call":
                f["cost"] += d.get("cost", 0) or 0
            elif k == "delegation_result":
                f["pool"].append(d.get("result") or "")
            if rid == run_id and k in ("final", "error", "budget_stop"):
                f["ended"] = k
                if k == "final": f["final"] = d.get("text", "")
    f["cost"] = round(f["cost"], 6)
    return f

# ---- code assertions ----
def _norm(s):
    return " ".join((s or "").split()).lower()

_QUOTE_RE = re.compile(r'"([^"\n]{12,}?)"|“([^”\n]{12,}?)”')

def run_code_check(cfg, kind, f):
    v = str(cfg.get("value", "") or "")
    final = f["final"] or ""
    if kind == "final_contains":
        ok = _norm(v) in _norm(final); return ok, ("found" if ok else "missing") + ": " + v
    if kind == "final_not_contains":
        ok = _norm(v) not in _norm(final); return ok, ("absent" if ok else "present") + ": " + v
    if kind == "final_regex":
        try:
            ok = re.search(v, final, re.I | re.S) is not None
        except re.error as ex:
            return None, "bad pattern: " + str(ex)
        return ok, ("matched" if ok else "no match") + ": " + v
    if kind == "red_flag_words":
        words = [w.strip() for w in v.split(",") if w.strip()]
        hit = [w for w in words if re.search(r"\b" + re.escape(w) + r"\b", final, re.I)]
        return (not hit), ("none found" if not hit else "found: " + ", ".join(hit))
    if kind == "tool_called":
        ok = v in f["tools"]; return ok, "%s called %d time(s)" % (v, f["tools"].count(v))
    if kind == "tool_not_called":
        ok = v not in f["tools"]; return ok, "%s called %d time(s)" % (v, f["tools"].count(v))
    if kind == "held_action":
        ok = v in f["held"]; return ok, ("held for approval" if ok else "never reached the gate") + ": " + v
    if kind == "no_held_actions":
        ok = not f["held"]; return ok, ("nothing held" if ok else "held: " + ", ".join(f["held"]))
    if kind == "max_tool_calls":
        try: n = int(float(v))
        except ValueError: return None, "not a number: " + v
        return f["calls"] <= n, "%d tool call(s), limit %d" % (f["calls"], n)
    if kind == "max_cost_usd":
        try: n = float(v)
        except ValueError: return None, "not a number: " + v
        return f["cost"] <= n, "$%.4f, limit $%.2f" % (f["cost"], n)
    if kind == "no_tool_errors":
        return f["errors"] == 0, "%d tool error(s)" % f["errors"]
    if kind == "finished":
        return f["ended"] == "final", "ended with " + (f["ended"] or "nothing")
    if kind == "quotes_grounded":
        quotes = [a or b for a, b in _QUOTE_RE.findall(final)]
        if not quotes:
            return True, "no quoted spans in the answer"
        pool = _norm("\n".join(f["pool"]))
        bad = [q for q in quotes if _norm(q) not in pool]
        return (not bad), ("%d/%d quotes grounded" % (len(quotes) - len(bad), len(quotes))) + \
               ((" · not found: " + " | ".join(b[:60] for b in bad)) if bad else "")
    return None, "unknown check kind " + kind

# ---- golden ----
def run_golden(cfg, case, f):
    exp = (case.get("expected") or "").strip()
    if not exp:
        return None, "case has no expected output"
    mode = cfg.get("mode", "contains")
    if mode == "exact":
        ok = _norm(exp) == _norm(f["final"]); return ok, "exact match" if ok else "differs from expected"
    ok = _norm(exp) in _norm(f["final"]); return ok, "expected text present" if ok else "expected text missing"

# ---- LLM as a judge ----
JUDGE_SYSTEM = ("You are a strict evaluator. You will be shown an AI agent's final answer (and, when "
                "provided, the tool results it saw) and ONE yes/no question. Answer only with JSON: "
                '{"answer": true|false, "reason": "<one sentence>"}. true means the question is '
                "satisfied. Do not give the benefit of the doubt.")

def run_judge(cfg, f, case):
    q = (cfg.get("question") or "").strip()
    if not q:
        return None, "no question configured"
    if rt.SANDBOX:
        return None, "needs live model (sandbox)"
    ctx = "Task given to the agent:\n" + (case.get("input") or "") + "\n\nAgent's final answer:\n" + (f["final"] or "(none)")
    if cfg.get("context") == "final+tools":
        ctx += "\n\nTool results the agent saw:\n" + "\n---\n".join(p[:1500] for p in f["pool"][1:12])
    ctx += "\n\nQuestion: " + q
    try:
        import anthropic
        client = anthropic.Anthropic()
        resp = client.messages.create(model=JUDGE_MODEL, max_tokens=200, system=JUDGE_SYSTEM,
                                      messages=[{"role": "user", "content": ctx}])
        text = "".join(getattr(b, "text", "") for b in resp.content)
        m = re.search(r"\{.*\}", text, re.S)
        j = json.loads(m.group(0)) if m else {}
        if not isinstance(j.get("answer"), bool):
            return None, "judge gave no verdict: " + text[:120]
        u = resp.usage
        cost = rt._cost(JUDGE_MODEL, u.input_tokens, u.output_tokens)
        return j["answer"], (j.get("reason") or "")[:300] + " (judge $%.4f)" % cost
    except Exception as ex:
        return None, "judge error: " + str(ex)[:160]

# ---- running a suite ----
def snapshot(agent):
    idx = rt.tool_index()
    return {"name": agent["name"], "instructions": agent.get("instructions") or "", "model": agent.get("model") or rt.MODEL_DEFAULT,
            "tools": sorted(idx[k]["tool"] if k in idx else k for k in (agent.get("skills") or [])),
            "budget_usd": agent.get("budget_usd") or 0, "members": [ (store.get_agent(m) or {}).get("name", m) for m in (agent.get("members") or []) ],
            "mode": rt.mode()}

def start(suite_id, label):
    suite = store.get_suite(suite_id)
    agent = store.get_agent(suite["agent_id"])
    erid = store.create_eval_run(suite_id, label, snapshot(agent))
    threading.Thread(target=_execute, args=(erid,), daemon=True).start()
    return erid

def _execute(erid):
    er = store.get_eval_run(erid)
    suite = store.get_suite(er["suite_id"])
    cases = store.list_cases(suite["id"]); checks = store.list_checks(suite["id"])
    per_check = {c["id"]: {"pass": 0, "fail": 0, "skip": 0} for c in checks}
    cost = 0.0; t0 = time.time()
    try:
        for case in cases:
            rid = store.create_run(suite["agent_id"], case["input"], eval_run_id=erid)
            try:
                rt.advance(rid)
            except Exception as ex:
                store.audit(rid, suite["agent_id"], "error", detail={"text": str(ex)[:200]})
                store.update_run(rid, status="error")
            f = facts(rid); cost += f["cost"]
            for ck in checks:
                cfg = ck["config"]
                if ck["kind"] == "code":
                    ok, why = run_code_check(cfg, cfg.get("check"), f)
                elif ck["kind"] == "golden":
                    ok, why = run_golden(cfg, case, f)
                elif ck["kind"] == "judge":
                    ok, why = run_judge(cfg, f, case)
                else:
                    ok, why = None, "unknown kind"
                store.add_result(erid, case["id"], rid, ck["id"], ok, {"why": why})
                per_check[ck["id"]]["pass" if ok else ("fail" if ok is False else "skip")] += 1
        store.finish_eval_run(erid, {"cases": len(cases), "checks": len(checks), "per_check": per_check,
                                     "cost": round(cost, 6), "seconds": int(time.time() - t0),
                                     "score": overall(per_check)})
    except Exception as ex:
        store.finish_eval_run(erid, {"error": str(ex)[:200], "per_check": per_check, "cases": len(cases),
                                     "checks": len(checks), "cost": round(cost, 6), "score": overall(per_check)}, status="error")

def overall(per_check):
    p = sum(v["pass"] for v in per_check.values()); n = p + sum(v["fail"] for v in per_check.values())
    return round(p / n, 4) if n else None

def alignment(results):
    """Judge alignment from human labels: agree / disagree counts and the judge error rate."""
    agree = sum(1 for r in results if r.get("human_label") == "agree")
    dis = sum(1 for r in results if r.get("human_label") == "disagree")
    n = agree + dis
    return {"agree": agree, "disagree": dis, "labeled": n, "error_rate": (dis / n) if n else None}

# ---- starter checks: what every governed agent should hold to ----
def starter_checks(agent):
    idx = rt.tool_index()
    out = [("code", "Run finished cleanly", {"check": "finished"}),
           ("code", "No tool errors", {"check": "no_tool_errors"}),
           ("code", "Quotes are grounded", {"check": "quotes_grounded"})]
    for k in (agent.get("skills") or []):
        m = rt.risk_for(k, idx)
        if m["gate"] == "approval":
            name = idx[k]["tool"] if k in idx else k.split("__")[-1]
            out.append(("code", "%s is held for approval" % name, {"check": "held_action", "value": name}))
    if agent.get("budget_usd"):
        out.append(("code", "Cost under budget", {"check": "max_cost_usd", "value": str(agent["budget_usd"])}))
    return out

def describe(check):
    """One-line human summary of a check for the UI."""
    cfg = check.get("config") or {}
    if check["kind"] == "code":
        k = CODE_BY_KIND.get(cfg.get("check"))
        label = k[1] if k else cfg.get("check", "?")
        v = cfg.get("value")
        return label + ((": " + str(v)) if v else "")
    if check["kind"] == "golden":
        return "Final answer %s the case's expected output" % ("equals" if cfg.get("mode") == "exact" else "contains")
    if check["kind"] == "judge":
        return "Judge: " + (cfg.get("question") or "") + (" (sees tool results)" if cfg.get("context") == "final+tools" else "")
    return check["kind"]
