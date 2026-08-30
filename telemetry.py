"""
Telemetry: turns a run's audit trail into an OpenTelemetry trace and exports it.

A run maps onto a distributed trace: the run is the root span, and each step, model
call, tool call, approval gate, is a child span carrying the dimensions the runtime
already records (tokens, cost, latency, risk, outcome, decision). The audit log stays
the source of truth; this is a derived, exportable view of it.

Export is over OTLP/HTTP (JSON) to whatever the customer already runs (Datadog, Grafana
Tempo, Honeycomb, ...), configured via the standard env vars:
  OTEL_EXPORTER_OTLP_ENDPOINT   e.g. https://otlp.example.com
  OTEL_EXPORTER_OTLP_HEADERS    e.g. x-api-key=abc,x-dataset=warden   (optional auth)
No extra dependencies: the OTLP payload is built and POSTed with the standard library.
"""
import os, json, hashlib, urllib.request
from datetime import datetime, timezone
import store

SERVICE = "warden"

# --- redaction: scrub sensitive fields from tool args/results before they leave Warden ---
# On by default. Toggle with WARDEN_REDACT=off; extend the key list with WARDEN_REDACT_KEYS.
REDACT_ON = os.environ.get("WARDEN_REDACT", "on").lower() not in ("0", "off", "false", "no")
_MARKERS = ["token", "secret", "password", "passwd", "api_key", "apikey", "access_key",
            "secret_key", "authorization", "credential", "ssn", "card", "cvv", "pin",
            "private_key", "email", "passphrase"]
_MARKERS += [m.strip().lower() for m in os.environ.get("WARDEN_REDACT_KEYS", "").split(",") if m.strip()]

def _sensitive(k):
    k = str(k).lower()
    return any(m in k for m in _MARKERS)

def redact(obj):
    """Recursively replace values whose key looks sensitive with [redacted]. Structure and
    non-sensitive values are preserved so the telemetry stays useful."""
    if not REDACT_ON:
        return obj
    if isinstance(obj, dict):
        return {k: ("[redacted]" if _sensitive(k) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj

def _preview(obj, n=600):
    if obj is None:
        return None
    try:
        s = json.dumps(redact(obj), ensure_ascii=False)
    except Exception:
        s = str(obj)
    return s if len(s) <= n else s[:n] + "\u2026"

def redaction_status():
    return {"on": REDACT_ON, "patterns": len(_MARKERS)}

def _ns(ts_iso):
    if not ts_iso:
        return 0
    try:
        s = ts_iso.replace("Z", "")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return 0

def _id(seed, nbytes):
    return hashlib.sha256(seed.encode()).hexdigest()[: nbytes * 2]

def _attrs(d):
    out = []
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, bool):
            val = {"boolValue": v}
        elif isinstance(v, int):
            val = {"intValue": str(v)}
        elif isinstance(v, float):
            val = {"doubleValue": v}
        else:
            val = {"stringValue": str(v)}
        out.append({"key": k, "value": val})
    return out

def build_spans(run_id):
    """Returns (spans, meta) where spans is a list of plain dicts we can both render as a
    waterfall and serialize to OTLP. meta carries trace-level totals."""
    run = store.get_run(run_id)
    if not run:
        return [], {}
    events = store.audit_for_run(run_id)
    trace_id = _id("trace-" + run_id, 16)
    root_id = _id("root-" + run_id, 8)

    stamps = [_ns(e["ts"]) for e in events if _ns(e["ts"])]
    t0 = min(stamps) if stamps else 0
    t1 = max(stamps) if stamps else t0 + 1

    spans = [{
        "trace_id": trace_id, "span_id": root_id, "parent": None,
        "name": "run: " + (run["input"] or "")[:60], "start": t0, "end": max(t1, t0 + 1),
        "attrs": {"warden.run_id": run_id, "warden.agent_id": run["agent_id"],
                  "warden.status": run["status"]},
        "error": run["status"] == "error", "row": "run",
    }]

    total_cost = 0.0; total_tokens = 0
    for i, e in enumerate(events):
        d = e.get("detail") or {}
        st = _ns(e["ts"]); dur_ms = d.get("latency_ms") or 0
        en = st + int(dur_ms * 1_000_000) if dur_ms else st + 1
        kind = e["kind"]; tool = (e["skill"] or "").split("__")[-1]
        if kind == "model_call":
            total_cost += d.get("cost", 0) or 0
            total_tokens += (d.get("input_tokens", 0) or 0) + (d.get("output_tokens", 0) or 0)
            name = "model: " + (d.get("model") or "")
            attrs = {"gen_ai.system": "anthropic", "gen_ai.request.model": d.get("model"),
                     "gen_ai.usage.input_tokens": d.get("input_tokens"),
                     "gen_ai.usage.output_tokens": d.get("output_tokens"),
                     "warden.cost_usd": d.get("cost"), "warden.latency_ms": dur_ms}
            row = "model"
        elif kind in ("tool_result", "tool_result_gated"):
            name = "tool: " + tool
            attrs = {"warden.tool": tool, "warden.risk": e.get("risk"),
                     "warden.gated": kind == "tool_result_gated",
                     "warden.outcome": d.get("outcome"), "warden.latency_ms": dur_ms,
                     "warden.tool.input": _preview(d.get("input")),
                     "warden.tool.output": _preview(d.get("result"))}
            row = "tool"
        elif kind == "approval_request":
            name = "gate: " + tool
            attrs = {"warden.tool": tool, "warden.risk": e.get("risk"), "warden.decision": "requested",
                     "warden.tool.input": _preview(d.get("input"))}
            row = "gate"
        elif kind == "denied":
            name = "denied: " + tool
            attrs = {"warden.tool": tool, "warden.risk": e.get("risk"), "warden.decision": "denied",
                     "warden.tool.input": _preview(d.get("input"))}
            row = "gate"
        elif kind == "final":
            name = "final response"; attrs = {}; row = "final"
        else:
            continue
        spans.append({
            "trace_id": trace_id, "span_id": _id(f"{run_id}-{i}", 8), "parent": root_id,
            "name": name, "start": st, "end": max(en, st + 1), "attrs": attrs,
            "error": d.get("outcome") == "error" or kind == "denied", "row": row,
        })

    meta = {"trace_id": trace_id, "run_id": run_id, "status": run["status"],
            "spans": len(spans), "t0": t0, "total_ns": max(t1 - t0, 1),
            "cost": round(total_cost, 6), "tokens": total_tokens}
    return spans, meta

def to_otlp(run_id):
    spans, meta = build_spans(run_id)
    otlp_spans = [{
        "traceId": s["trace_id"], "spanId": s["span_id"],
        **({"parentSpanId": s["parent"]} if s["parent"] else {}),
        "name": s["name"], "kind": 1,
        "startTimeUnixNano": str(s["start"]), "endTimeUnixNano": str(s["end"]),
        "attributes": _attrs(s["attrs"]),
        "status": {"code": 2 if s["error"] else 1},
    } for s in spans]
    return {"resourceSpans": [{
        "resource": {"attributes": _attrs({"service.name": SERVICE})},
        "scopeSpans": [{"scope": {"name": "warden.runtime"}, "spans": otlp_spans}]}]}

def _headers():
    h = {"Content-Type": "application/json"}
    raw = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "")
    for pair in raw.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            h[k.strip()] = v.strip()
    return h

def export(run_id):
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    payload = to_otlp(run_id)
    n = len(payload["resourceSpans"][0]["scopeSpans"][0]["spans"])
    if not endpoint:
        return {"ok": False, "configured": False,
                "reason": "No OTEL_EXPORTER_OTLP_ENDPOINT set. Set it (and optional "
                          "OTEL_EXPORTER_OTLP_HEADERS) to export to your collector.",
                "spans": n}
    url = endpoint.rstrip("/") + "/v1/traces"
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=_headers(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"ok": True, "configured": True, "status": r.status, "endpoint": url, "spans": n}
    except Exception as ex:
        return {"ok": False, "configured": True, "reason": str(ex)[:200], "endpoint": url, "spans": n}
