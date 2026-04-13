#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

APP_VERSION = "0.1.0"
HOST = os.getenv("AUTOMATION_BIND", "0.0.0.0")
PORT = int(os.getenv("AUTOMATION_PORT", "8080"))
DB_PATH = Path(os.getenv("AUTOMATION_DB_PATH", "/app/data/automation.db"))
RULES_FILE = Path(os.getenv("AUTOMATION_RULES_FILE", "/app/config/rules.json"))
ACTION_MODE = os.getenv("AUTOMATION_ACTION_MODE", "dry-run").lower()
WEBHOOK_BEARER_TOKEN = os.getenv("AUTOMATION_WEBHOOK_BEARER_TOKEN", "")
GLPI_HELPER_PATH = os.getenv("AUTOMATION_GLPI_PAM_HELPER", "/app/glpi-scripts/pam_privileged_access_request.py")
EVENT_RETENTION_DAYS = int(os.getenv("AUTOMATION_EVENT_RETENTION_DAYS", "30"))
DEBUG = os.getenv("AUTOMATION_DEBUG", "false").lower() in {"1", "true", "yes"}

_db_lock = threading.Lock()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(msg: str) -> None:
    sys.stdout.write(f"[{now_utc_iso()}] {msg}\n")
    sys.stdout.flush()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def db_connect() -> sqlite3.Connection:
    ensure_parent(DB_PATH)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def db_init() -> None:
    with _db_lock:
        conn = db_connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                  event_id TEXT PRIMARY KEY,
                  idempotency_key TEXT NOT NULL,
                  source TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  received_at TEXT NOT NULL,
                  event_time TEXT,
                  severity INTEGER,
                  payload_json TEXT NOT NULL,
                  status TEXT NOT NULL,
                  rule_count INTEGER NOT NULL DEFAULT 0,
                  action_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_events_idempotency ON events(idempotency_key);
                CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
                CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source, event_type);

                CREATE TABLE IF NOT EXISTS actions (
                  action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_id TEXT NOT NULL,
                  rule_name TEXT NOT NULL,
                  action_type TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  status TEXT NOT NULL,
                  result_json TEXT,
                  FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_actions_event_id ON actions(event_id);
                """
            )
            conn.commit()
        finally:
            conn.close()


def db_prune() -> None:
    cutoff = time.time() - (EVENT_RETENTION_DAYS * 86400)
    cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute("DELETE FROM events WHERE received_at < ?", (cutoff_iso,))
            conn.commit()
        finally:
            conn.close()


def load_rules() -> Dict[str, Any]:
    if not RULES_FILE.exists():
        return {"version": 1, "rules": []}
    raw = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("rules.json must be an object")
    raw.setdefault("version", 1)
    raw.setdefault("rules", [])
    if not isinstance(raw.get("rules"), list):
        raise ValueError("rules.json 'rules' must be a list")
    return raw


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_event_id(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:32]


def derive_idempotency_key(event: Dict[str, Any]) -> str:
    key = str(event.get("idempotency_key") or "").strip()
    if key:
        return key
    candidate = {
        "source": event.get("source"),
        "event_type": event.get("event_type"),
        "external_ref": event.get("external_ref"),
        "actor": event.get("actor"),
        "target": event.get("target"),
        "labels": event.get("labels"),
    }
    return hashlib.sha256(canonical_json(candidate).encode("utf-8")).hexdigest()


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("event payload must be an object")
    source = str(event.get("source") or "").strip()
    event_type = str(event.get("event_type") or "").strip()
    if not source or not event_type:
        raise ValueError("event requires 'source' and 'event_type'")
    normalized = {
        "source": source,
        "event_type": event_type,
        "event_time": str(event.get("event_time") or now_utc_iso()),
        "severity": int(event.get("severity") or 0),
        "external_ref": str(event.get("external_ref") or ""),
        "idempotency_key": str(event.get("idempotency_key") or ""),
        "actor": event.get("actor") if isinstance(event.get("actor"), dict) else {},
        "target": event.get("target") if isinstance(event.get("target"), dict) else {},
        "labels": event.get("labels") if isinstance(event.get("labels"), list) else [],
        "metadata": event.get("metadata") if isinstance(event.get("metadata"), dict) else {},
        "payload": event.get("payload") if isinstance(event.get("payload"), dict) else {},
        "raw": event.get("raw"),
    }
    normalized["idempotency_key"] = derive_idempotency_key(normalized)
    return normalized


def get_nested(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def match_rule(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    m = rule.get("match") or {}
    if not isinstance(m, dict):
        return False

    equals = m.get("equals") or {}
    for key, expected in (equals.items() if isinstance(equals, dict) else []):
        if get_nested(event, key) != expected:
            return False

    any_equals = m.get("any_equals") or {}
    for key, options in (any_equals.items() if isinstance(any_equals, dict) else []):
        if get_nested(event, key) not in (options if isinstance(options, list) else []):
            return False

    contains = m.get("contains") or {}
    for key, expected in (contains.items() if isinstance(contains, dict) else []):
        val = get_nested(event, key)
        if isinstance(val, list):
            if expected not in val:
                return False
        elif isinstance(val, str):
            if str(expected) not in val:
                return False
        else:
            return False

    all_contains = m.get("all_contains") or {}
    for key, expected_values in (all_contains.items() if isinstance(all_contains, dict) else []):
        val = get_nested(event, key)
        if not isinstance(val, list):
            return False
        for expected in (expected_values if isinstance(expected_values, list) else []):
            if expected not in val:
                return False

    min_sev = m.get("min_severity")
    if min_sev is not None and int(event.get("severity") or 0) < int(min_sev):
        return False

    return True


def substitute(value: Any, event: Dict[str, Any], ctx: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        out = value
        # Supports {{event.foo.bar}} and {{ctx.foo}}
        for prefix, root in (("event.", event), ("ctx.", ctx)):
            start = 0
            while True:
                marker = f"{{{{{prefix}"
                i = out.find(marker, start)
                if i == -1:
                    break
                j = out.find("}}", i)
                if j == -1:
                    break
                expr = out[i + 2 : j].strip()
                repl = ""
                if expr.startswith(prefix):
                    val = get_nested(root, expr[len(prefix):])
                    repl = "" if val is None else str(val)
                out = out[:i] + repl + out[j + 2 :]
                start = i + len(repl)
        return out
    if isinstance(value, list):
        return [substitute(v, event, ctx) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, event, ctx) for k, v in value.items()}
    return value


def http_json(method: str, url: str, headers: Dict[str, str], payload: Optional[Dict[str, Any]] = None, timeout: int = 15) -> Dict[str, Any]:
    data = None
    req_headers = dict(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    req = Request(url, data=data, method=method.upper(), headers=req_headers)
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return {
            "status_code": resp.status,
            "headers": dict(resp.headers),
            "body": body.decode("utf-8", errors="replace"),
        }


@dataclass
class ActionResult:
    status: str
    details: Dict[str, Any]


def run_action(action: Dict[str, Any], event: Dict[str, Any], ctx: Dict[str, Any]) -> ActionResult:
    a_type = str(action.get("type") or "").strip()
    params = action.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    params = substitute(params, event, ctx)

    if a_type == "log":
        msg = str(params.get("message") or f"event={event.get('event_type')} source={event.get('source')}")
        log(f"automation-action log: {msg}")
        return ActionResult("ok", {"message": msg})

    if a_type == "http_request":
        if ACTION_MODE != "live":
            return ActionResult("dry-run", {"type": a_type, "params": params})
        try:
            resp = http_json(
                method=str(params.get("method") or "POST"),
                url=str(params["url"]),
                headers=params.get("headers") or {},
                payload=params.get("json") if isinstance(params.get("json"), dict) else None,
                timeout=int(params.get("timeout") or 15),
            )
            return ActionResult("ok", {"response": resp})
        except (HTTPError, URLError, KeyError, ValueError) as exc:
            return ActionResult("error", {"error": str(exc), "type": a_type, "params": params})

    if a_type == "glpi_pam_request":
        cmd_mode = str(params.get("mode") or "open")
        if ACTION_MODE != "live":
            return ActionResult("dry-run", {"type": a_type, "mode": cmd_mode, "params": params})
        helper = Path(GLPI_HELPER_PATH)
        if not helper.exists():
            return ActionResult("error", {"error": f"GLPI helper not found: {helper}"})
        try:
            if cmd_mode == "open":
                argv = [
                    sys.executable,
                    str(helper),
                    "open",
                    "--request-id", str(params["request_id"]),
                    "--user", str(params.get("user") or "unknown"),
                    "--target", str(params.get("target") or "unknown"),
                    "--protocol", str(params.get("protocol") or "ssh"),
                    "--duration", str(params.get("duration") or "30m"),
                    "--reason", str(params.get("reason") or "Privileged access request"),
                    "--source", str(params.get("source") or "automation-service"),
                    "--priority", str(params.get("priority") or 3),
                ]
            elif cmd_mode == "close":
                argv = [sys.executable, str(helper), "close"]
                if str(params.get("request_id") or ""):
                    argv += ["--request-id", str(params["request_id"])]
                if str(params.get("ticket_id") or ""):
                    argv += ["--ticket-id", str(params["ticket_id"])]
                if str(params.get("comment") or ""):
                    argv += ["--comment", str(params["comment"])]
            else:
                return ActionResult("error", {"error": f"unsupported glpi_pam_request mode: {cmd_mode}"})
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=int(params.get("timeout") or 30), check=False)
            return ActionResult(
                "ok" if proc.returncode == 0 else "error",
                {"returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()},
            )
        except (KeyError, subprocess.SubprocessError, ValueError) as exc:
            return ActionResult("error", {"error": str(exc)})

    if a_type == "noop":
        return ActionResult("ok", {"type": "noop"})

    return ActionResult("error", {"error": f"unsupported action type: {a_type}"})


def store_event_if_new(event: Dict[str, Any]) -> Tuple[bool, str]:
    event_id = compute_event_id(event)
    with _db_lock:
        conn = db_connect()
        try:
            cur = conn.execute("SELECT event_id FROM events WHERE idempotency_key = ?", (event["idempotency_key"],))
            row = cur.fetchone()
            if row:
                return False, str(row["event_id"])
            conn.execute(
                "INSERT INTO events (event_id, idempotency_key, source, event_type, received_at, event_time, severity, payload_json, status, rule_count, action_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)",
                (
                    event_id,
                    event["idempotency_key"],
                    event["source"],
                    event["event_type"],
                    now_utc_iso(),
                    str(event.get("event_time") or ""),
                    int(event.get("severity") or 0),
                    canonical_json(event),
                    "received",
                ),
            )
            conn.commit()
            return True, event_id
        finally:
            conn.close()


def update_event_result(event_id: str, status: str, rule_count: int, action_count: int) -> None:
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute(
                "UPDATE events SET status=?, rule_count=?, action_count=? WHERE event_id=?",
                (status, int(rule_count), int(action_count), event_id),
            )
            conn.commit()
        finally:
            conn.close()


def store_action_result(event_id: str, rule_name: str, action_type: str, result: ActionResult) -> None:
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute(
                "INSERT INTO actions (event_id, rule_name, action_type, created_at, status, result_json) VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, rule_name, action_type, now_utc_iso(), result.status, canonical_json(result.details)),
            )
            conn.commit()
        finally:
            conn.close()


def process_event(event: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_event(event)
    created, event_id = store_event_if_new(normalized)
    if not created:
        return {"status": "duplicate", "event_id": event_id, "idempotency_key": normalized["idempotency_key"]}

    rules_doc = load_rules()
    matched: List[Dict[str, Any]] = []
    action_results: List[Dict[str, Any]] = []
    ctx = {"event_id": event_id, "received_at": now_utc_iso()}
    final_status = "processed"

    for rule in rules_doc.get("rules", []):
        if not isinstance(rule, dict) or rule.get("enabled", True) is False:
            continue
        rule_name = str(rule.get("name") or f"rule-{len(matched)+1}")
        try:
            if not match_rule(rule, normalized):
                continue
        except Exception as exc:
            matched.append({"rule": rule_name, "status": "error", "error": f"match failed: {exc}"})
            final_status = "error"
            continue

        matched.append({"rule": rule_name, "status": "matched"})
        for action in (rule.get("actions") or []):
            a_type = str((action or {}).get("type") or "")
            result = run_action(action or {}, normalized, ctx)
            store_action_result(event_id, rule_name, a_type, result)
            action_results.append({"rule": rule_name, "action": a_type, "status": result.status, "details": result.details})
            if result.status == "error":
                final_status = "error"
            if result.status in {"ok", "dry-run"} and isinstance(result.details, dict):
                if a_type == "glpi_pam_request":
                    out = result.details.get("stdout") or ""
                    try:
                        parsed = json.loads(out) if out else {}
                    except json.JSONDecodeError:
                        parsed = {}
                    if parsed.get("ticket_id"):
                        ctx["glpi_ticket_id"] = parsed.get("ticket_id")

    update_event_result(event_id, final_status, len(matched), len(action_results))
    return {
        "status": final_status,
        "event_id": event_id,
        "idempotency_key": normalized["idempotency_key"],
        "matched_rules": matched,
        "actions": action_results,
    }


def adapt_wazuh_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    labels = []
    if isinstance(rule.get("groups"), list):
        labels = [str(x) for x in rule.get("groups")]
    srcip = data.get("srcip") or data.get("src_ip") or alert.get("srcip")
    event = {
        "source": "wazuh",
        "event_type": "wazuh.alert",
        "event_time": alert.get("timestamp") or now_utc_iso(),
        "severity": int(rule.get("level") or 0),
        "external_ref": str(alert.get("id") or alert.get("decoder") or ""),
        "actor": {"ip": srcip} if srcip else {},
        "target": {
            "host": str((alert.get("agent") or {}).get("name") or "") if isinstance(alert.get("agent"), dict) else "",
            "component": "wazuh",
        },
        "labels": labels,
        "metadata": {
            "wazuh_rule_id": rule.get("id"),
            "wazuh_description": rule.get("description"),
        },
        "payload": alert,
        "raw": alert,
    }
    return event


class Handler(BaseHTTPRequestHandler):
    server_version = "automation-service/0.1"

    def _json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object")
        return parsed

    def _check_auth(self) -> bool:
        if not WEBHOOK_BEARER_TOKEN:
            return True
        auth = self.headers.get("Authorization") or ""
        if auth == f"Bearer {WEBHOOK_BEARER_TOKEN}":
            return True
        self._json(401, {"error": "unauthorized"})
        return False

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            try:
                rules_doc = load_rules()
                db_init()
                self._json(200, {
                    "status": "ok",
                    "service": "automation-service",
                    "version": APP_VERSION,
                    "mode": ACTION_MODE,
                    "rules_file": str(RULES_FILE),
                    "rule_count": len(rules_doc.get("rules", [])),
                    "db_path": str(DB_PATH),
                })
            except Exception as exc:
                self._json(500, {"status": "error", "error": str(exc)})
            return

        if self.path == "/v1/rules":
            if not self._check_auth():
                return
            try:
                self._json(200, load_rules())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return

        if self.path.startswith("/v1/events/"):
            if not self._check_auth():
                return
            event_id = self.path.rsplit("/", 1)[-1]
            with _db_lock:
                conn = db_connect()
                try:
                    er = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
                    if not er:
                        self._json(404, {"error": "not_found"})
                        return
                    ars = conn.execute("SELECT * FROM actions WHERE event_id = ? ORDER BY action_id", (event_id,)).fetchall()
                finally:
                    conn.close()
            self._json(200, {
                "event": dict(er),
                "actions": [dict(r) for r in ars],
            })
            return

        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/v1/events", "/v1/events/wazuh"}:
            self._json(404, {"error": "not_found"})
            return
        if not self._check_auth():
            return

        try:
            body = self._read_json()
            event = adapt_wazuh_alert(body) if self.path == "/v1/events/wazuh" else body
            result = process_event(event)
            status = 200 if result.get("status") == "duplicate" else 202
            self._json(status, result)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            log(f"automation error: {exc}")
            self._json(500, {"error": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        if DEBUG:
            super().log_message(fmt, *args)


def main() -> int:
    db_init()
    db_prune()
    log(f"automation-service starting on {HOST}:{PORT} mode={ACTION_MODE} rules={RULES_FILE}")
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
