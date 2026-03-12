#!/usr/bin/env python3
import ast
import contextlib
import io
import json
import sqlite3
import tempfile
import types
import unittest
from email.message import Message
from pathlib import Path


_MISSING = object()


@contextlib.contextmanager
def _override(ns: dict, **repls):
    old = {}
    for k, v in repls.items():
        old[k] = ns.get(k, _MISSING)
        ns[k] = v
    try:
        yield
    finally:
        for k, prev in old.items():
            if prev is _MISSING:
                ns.pop(k, None)
            else:
                ns[k] = prev


def _extract_dashboard_api_python_source(script_text: str) -> str:
    marker = "if write_atomic \"${DASH_API_BIN}\" <<'PYEOF'"
    start = script_text.find(marker)
    if start < 0:
        raise RuntimeError("Could not locate embedded dashboard API python block start marker")
    start += len(marker)
    end = script_text.find("\nPYEOF", start)
    if end < 0:
        raise RuntimeError("Could not locate embedded dashboard API python block end marker")
    return script_text[start:end].lstrip("\n")


class EmbeddedDashboardApiSyntaxRegressionTest(unittest.TestCase):
    def test_embedded_dashboard_api_python_parses(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        script_path = repo_root / "zypper-auto.sh"
        py_src = _extract_dashboard_api_python_source(script_path.read_text(encoding="utf-8"))
        ast.parse(py_src)


class AiSmartReportRuntimeRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        script_path = repo_root / "zypper-auto.sh"
        py_src = _extract_dashboard_api_python_source(script_path.read_text(encoding="utf-8"))

        cls.ns: dict = {"__name__": "znh_dashboard_api_test_ai_runtime"}
        exec(py_src, cls.ns, cls.ns)
        cls.handler_cls = cls.ns["Handler"]

    def _invoke_post(self, path: str, body: dict, *, conf_path: str, server_extras: dict | None = None) -> tuple[int, dict]:
        h = object.__new__(self.handler_cls)
        h.path = path
        h.client_address = ("127.0.0.1", 0)
        raw = json.dumps(body).encode("utf-8")
        h.rfile = io.BytesIO(raw)
        h.wfile = io.BytesIO()
        h.request_version = "HTTP/1.1"
        h.command = "POST"

        headers = Message()
        headers["X-ZNH-Token"] = "tok"
        headers["Origin"] = "http://127.0.0.1:8765"
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(raw))
        h.headers = headers

        state = {"code": 0}

        def _send_response(code: int, _msg: str | None = None):
            state["code"] = int(code)

        h.send_response = _send_response
        h.send_header = lambda *_args, **_kwargs: None
        h.end_headers = lambda: None

        server_kwargs = {
            "token": "tok",
            "conf_path": str(conf_path),
            "_znh_log": (lambda *_args, **_kwargs: None),
        }
        if server_extras:
            server_kwargs.update(server_extras)
        h.server = types.SimpleNamespace(**server_kwargs)

        self.handler_cls.do_POST(h)
        raw_out = h.wfile.getvalue().decode("utf-8", errors="replace").strip()
        payload = json.loads(raw_out or "{}")
        return int(state.get("code", 0) or 0), payload

    def _temp_helper_script(self, content: str) -> str:
        tf = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        tf.write(content)
        tf.flush()
        tf.close()
        return tf.name

    def _mk_history_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE jobs (
                job_id TEXT,
                job_type TEXT,
                action TEXT,
                title TEXT,
                started_ts REAL,
                rc INTEGER,
                stage TEXT,
                summary TEXT,
                log_tail TEXT,
                done INTEGER,
                finished_ts REAL
            )
            """
        )
        now = 1_780_000_000.0
        rows = [
            (
                "job-conflict",
                "system-dup",
                "rm-conflict",
                "System update",
                now - 120.0,
                1,
                "failed",
                "zypper dup failed with solver conflict",
                "ERROR conflicting requests\nproblem: nothing provides libfoo >= 9\nconflicts with bar-package",
                1,
                now - 90.0,
            ),
            ("job-h1", "quick-action", "rm-conflict", "Conflict cleanup", now - 3600.0, 0, "done", "ok", "", 1, now - 3500.0),
            ("job-h2", "quick-action", "rm-conflict", "Conflict cleanup", now - 5600.0, 0, "done", "ok", "", 1, now - 5500.0),
            ("job-h3", "quick-action", "verify", "Verify", now - 7600.0, 1, "done", "failed", "", 1, now - 7500.0),
        ]
        conn.executemany(
            """
            INSERT INTO jobs (
                job_id, job_type, action, title, started_ts, rc, stage, summary, log_tail, done, finished_ts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        return conn

    def test_smart_report_runtime_incident_severity_and_action_ordering(self) -> None:
        conf_path = self._temp_helper_script("SELF_UPDATE_CHANNEL=\"stable\"\n")
        conn = self._mk_history_conn()
        try:
            with _override(self.ns, _history_conn=lambda _server: conn, time=types.SimpleNamespace(time=lambda: 1_780_000_100.0, gmtime=self.ns["time"].gmtime, strftime=self.ns["time"].strftime)):
                code, payload = self._invoke_post(
                    "/api/ai/smart-report",
                    {"days": 7, "include_debug": False},
                    conf_path=conf_path,
                )
        finally:
            conn.close()

        self.assertEqual(code, 200)
        self.assertTrue(bool(payload.get("ok")))
        self.assertTrue(bool(payload.get("schema_valid")), msg=f"schema_errors={payload.get('schema_errors')}")

        incidents = payload.get("incidents") or []
        self.assertTrue(incidents, "expected at least one incident from failed conflict job")
        conflict = None
        for inc in incidents:
            if str(inc.get("kind") or "") == "update-conflict":
                conflict = inc
                break
        self.assertIsNotNone(conflict, "expected update-conflict incident in runtime payload")
        self.assertIn(str(conflict.get("severity") or ""), {"high", "critical"})

        repair_plan = payload.get("repair_plan") or {}
        self.assertEqual(str(repair_plan.get("selected_action") or ""), "rm-conflict")

        top_actions = repair_plan.get("top_actions") or []
        self.assertTrue(top_actions, "expected non-empty top_actions")
        self.assertEqual(str(top_actions[0].get("action") or ""), str(repair_plan.get("selected_action") or ""))

        scores = [int((it or {}).get("score", 0) or 0) for it in top_actions]
        self.assertEqual(scores, sorted(scores, reverse=True), "top_actions must be score-sorted descending")


if __name__ == "__main__":
    unittest.main()
