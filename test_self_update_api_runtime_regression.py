#!/usr/bin/env python3
import contextlib
import io
import json
import tempfile
import types
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock


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


class SelfUpdateApiRuntimeRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parent
        script_path = repo_root / "zypper-auto.sh"
        script_text = script_path.read_text(encoding="utf-8")

        marker = "if write_atomic \"${DASH_API_BIN}\" <<'PYEOF'"
        start = script_text.find(marker)
        if start < 0:
            raise RuntimeError("Could not locate embedded dashboard API python block start marker")
        start += len(marker)
        end = script_text.find("\nPYEOF", start)
        if end < 0:
            raise RuntimeError("Could not locate embedded dashboard API python block end marker")
        py_src = script_text[start:end].lstrip("\n")

        cls.ns: dict = {"__name__": "znh_dashboard_api_test_runtime"}
        exec(py_src, cls.ns, cls.ns)
        cls.handler_cls = cls.ns["Handler"]

    def _invoke_get(self, path: str, *, conf_path: str, server_extras: dict | None = None) -> tuple[int, dict]:
        h = object.__new__(self.handler_cls)
        h.path = path
        h.client_address = ("127.0.0.1", 0)
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h.request_version = "HTTP/1.1"
        h.command = "GET"

        headers = Message()
        headers["X-ZNH-Token"] = "tok"
        headers["Origin"] = "http://127.0.0.1:8765"
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

        self.handler_cls.do_GET(h)
        raw = h.wfile.getvalue().decode("utf-8", errors="replace").strip()
        payload = json.loads(raw or "{}")
        return int(state.get("code", 0) or 0), payload

    def _temp_helper_script(self, content: str) -> str:
        tf = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        tf.write(content)
        tf.flush()
        tf.close()
        return tf.name

    def test_self_update_status_handles_github_rate_limit_safely(self) -> None:
        helper_path = self._temp_helper_script("#!/bin/bash\n# VERSION 1\n")
        conf_path = self._temp_helper_script("SELF_UPDATE_CHANNEL=\"stable\"\n")

        http_err = self.ns["urllib"].error.HTTPError(
            url="https://api.github.com/",
            code=429,
            msg="rate limited",
            hdrs=None,
            fp=None,
        )
        stub_any_running = lambda: {"running": False, "channel": "", "unit": "", "status_path": ""}
        stub_conf = lambda _p: ({"SELF_UPDATE_CHANNEL": "stable", "SELF_UPDATE_STABLE_POLICY": "release"}, [], [])

        with _override(
            self.ns,
            HELPER_BIN=helper_path,
            SELF_UPDATE_STATE_FILE=f"{helper_path}.state",
            _read_conf=stub_conf,
            _self_update_any_running=stub_any_running,
            _github_latest_release_candidate=lambda **_k: (_ for _ in ()).throw(http_err),
        ):
            code, payload = self._invoke_get("/api/self-update/status?channel=stable", conf_path=conf_path)

        self.assertEqual(code, 200)
        self.assertIn("429", str(payload.get("error", "")))
        rec = payload.get("post_action_recommendation") or {}
        self.assertEqual(rec.get("recommended"), "verify")
        self.assertEqual(rec.get("risk_level"), "elevated")

    def test_self_update_status_missing_remote_script_uses_safer_verify_recommendation(self) -> None:
        helper_path = self._temp_helper_script("#!/bin/bash\n# VERSION 1\n")
        conf_path = self._temp_helper_script("SELF_UPDATE_CHANNEL=\"stable\"\n")

        stub_any_running = lambda: {"running": False, "channel": "", "unit": "", "status_path": ""}
        stub_conf = lambda _p: ({"SELF_UPDATE_CHANNEL": "stable", "SELF_UPDATE_STABLE_POLICY": "release"}, [], [])
        stub_release = (
            {
                "tag_name": "v999",
                "name": "v999",
                "published_at": "2026-03-10T00:00:00Z",
                "prerelease": False,
            },
            {
                "policy": "release",
                "selection": "release",
                "fallback_reason": "",
                "source_url": "",
                "source_urls": [],
                "is_prerelease": False,
            },
        )

        with _override(
            self.ns,
            HELPER_BIN=helper_path,
            SELF_UPDATE_STATE_FILE=f"{helper_path}.state",
            _read_conf=stub_conf,
            _self_update_any_running=stub_any_running,
            _github_latest_release_candidate=lambda **_k: stub_release,
            _read_remote_script_bytes=lambda *_a, **_k: (b"", ""),
        ):
            code, payload = self._invoke_get("/api/self-update/status?channel=stable", conf_path=conf_path)

        self.assertEqual(code, 200)
        rec = payload.get("post_action_recommendation") or {}
        self.assertEqual(rec.get("recommended"), "verify")
        self.assertIn("unavailable", str(rec.get("reason", "")).lower())

    def test_self_update_status_marker_ambiguity_defaults_to_install(self) -> None:
        helper_path = self._temp_helper_script("#!/bin/bash\n# VERSION 1\n")
        conf_path = self._temp_helper_script("SELF_UPDATE_CHANNEL=\"stable\"\n")

        stub_any_running = lambda: {"running": False, "channel": "", "unit": "", "status_path": ""}
        stub_conf = lambda _p: ({"SELF_UPDATE_CHANNEL": "stable", "SELF_UPDATE_STABLE_POLICY": "release"}, [], [])
        stub_release = (
            {
                "tag_name": "v1000",
                "name": "v1000",
                "published_at": "2026-03-10T00:00:00Z",
                "prerelease": False,
            },
            {
                "policy": "release",
                "selection": "release",
                "fallback_reason": "",
                "source_url": "",
                "source_urls": [],
                "is_prerelease": False,
            },
        )

        # Remote text intentionally lacks known marker sections -> ambiguous markers path.
        remote_bytes = b"#!/bin/bash\n# VERSION 1000\necho hi\n"

        with _override(
            self.ns,
            HELPER_BIN=helper_path,
            SELF_UPDATE_STATE_FILE=f"{helper_path}.state",
            _read_conf=stub_conf,
            _self_update_any_running=stub_any_running,
            _github_latest_release_candidate=lambda **_k: stub_release,
            _read_remote_script_bytes=lambda *_a, **_k: (remote_bytes, "zypper-auto.sh"),
        ):
            code, payload = self._invoke_get("/api/self-update/status?channel=stable", conf_path=conf_path)

        self.assertEqual(code, 200)
        rec = payload.get("post_action_recommendation") or {}
        self.assertEqual(rec.get("recommended"), "install")
        self.assertIn("ambiguous", str(rec.get("reason", "")).lower())
        self.assertEqual(rec.get("risk_level"), "high")

    def test_snapper_timers_missing_units_include_partial_reason(self) -> None:
        conf_path = self._temp_helper_script("SELF_UPDATE_CHANNEL=\"stable\"\n")

        class _CP:
            def __init__(self, stdout: str, rc: int = 0):
                self.stdout = stdout
                self.returncode = rc

        def _fake_run(cmd, **_kwargs):  # noqa: ANN001
            c = list(cmd or [])
            if c[:3] == ["systemctl", "show", "snapper-timeline.timer"] or c[:3] == ["systemctl", "show", "snapper-cleanup.timer"] or c[:3] == ["systemctl", "show", "snapper-boot.timer"]:
                return _CP("LoadState=not-found\nUnitFileState=\nActiveState=\nNextElapseUSecRealtime=0\nLastTriggerUSec=0\nResult=failed\n")
            if c[:2] == ["systemctl", "is-enabled"]:
                return _CP("disabled\n", 1)
            if c[:2] == ["systemctl", "is-active"]:
                return _CP("inactive\n", 3)
            if c[:3] == ["systemctl", "list-unit-files", "--no-legend"]:
                return _CP("", 0)
            return _CP("", 0)

        stub_conf = lambda _p: ({"SELF_UPDATE_CHANNEL": "stable", "SELF_UPDATE_STABLE_POLICY": "release"}, [], [])

        with _override(self.ns, _read_conf=stub_conf):
            with mock.patch.object(self.ns["subprocess"], "run", side_effect=_fake_run):
                code, payload = self._invoke_get("/api/snapper/timers", conf_path=conf_path)

        self.assertEqual(code, 200)
        self.assertEqual(payload.get("snapper_timeline_timer"), "missing")
        self.assertEqual(payload.get("snapper_cleanup_timer"), "missing")
        self.assertEqual(payload.get("snapper_boot_timer"), "missing")

        live = payload.get("snapper_timeline_timer_live") or {}
        self.assertIn("load state reports", str(live.get("partial_reason", "")).lower())
        self.assertEqual(str(live.get("last_result") or ""), "failed")

    def test_recover_self_update_job_uses_terminal_state_fallback(self) -> None:
        job_id = "selfupdatet1"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            su_log_dir = root / "logs"
            su_state_dir = root / "state"
            su_log_dir.mkdir(parents=True, exist_ok=True)
            su_state_dir.mkdir(parents=True, exist_ok=True)

            with _override(self.ns, SU_LOG_DIR=str(su_log_dir), SU_STATUS_DIR=str(su_state_dir)):
                unit, log_path, status_path, _script_path = self.ns["_su_paths"](job_id)
                Path(log_path).write_text(
                    "header\nupdate complete\nfooter\n",
                    encoding="utf-8",
                )
                # Simulate status-file lag (no done=1 marker yet).
                Path(status_path).write_text(
                    "channel=stable\nstage=Running\ndry_run=0\n",
                    encoding="utf-8",
                )

                def _fake_run_cmd(cmd, timeout_s=0, log=None):  # noqa: ANN001
                    _ = timeout_s, log
                    if list(cmd or []) == [
                        "systemctl",
                        "show",
                        unit,
                        "-p",
                        "ActiveState",
                        "-p",
                        "SubState",
                        "-p",
                        "ExecMainStatus",
                    ]:
                        return 0, "ActiveState=inactive\nSubState=dead\nExecMainStatus=0\n"
                    return 1, ""

                with _override(self.ns, _run_cmd=_fake_run_cmd):
                    recovered = self.ns["_recover_self_update_job"](job_id)

        self.assertIsNotNone(recovered, "Expected recovered self-update payload")
        self.assertTrue(bool(recovered.get("done")), "terminal state fallback should set done=true")
        self.assertFalse(bool(recovered.get("running")), "terminal state fallback should set running=false")
        self.assertEqual(int(recovered.get("rc", 1)), 0, "ExecMainStatus=0 should map to rc=0")
        self.assertEqual(int(recovered.get("progress", 0)), 100, "terminal-complete update should be at 100%")
        self.assertNotEqual(int(recovered.get("progress", 0)), 99, "terminal-complete update must not stall at 99%")
        self.assertIn("done", str(recovered.get("stage", "")).lower())

    def test_self_update_job_api_returns_effective_full_output(self) -> None:
        conf_path = self._temp_helper_script("SELF_UPDATE_CHANNEL=\"stable\"\n")
        job_id = "selfupdatej2"

        prefix = "BEGIN-FULL-OUTPUT-MARKER\n"
        middle = "x" * 50050
        suffix = "\nEND-FULL-OUTPUT-MARKER\n"
        full_log = prefix + middle + suffix

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log_path = root / "self-update.log"
            log_path.write_text(full_log, encoding="utf-8")

            jobs = {
                job_id: {
                    "job_id": job_id,
                    "type": "self-update",
                    "channel": "stable",
                    "dry_run": False,
                    "simulate": False,
                    "running": False,
                    "done": True,
                    "rc": 0,
                    "stage": "Done",
                    "progress": 100,
                    "output": "tail-placeholder",
                    "output_truncated": False,
                    "restart_check_output": "",
                    "log_path": str(log_path),
                    "status_path": str(root / "self-update.status"),
                }
            }

            code, payload = self._invoke_get(
                f"/api/self-update/job?job_id={job_id}",
                conf_path=conf_path,
                server_extras={"jobs": jobs},
            )

        self.assertEqual(code, 200)
        out = str(payload.get("output") or "")
        self.assertIn("BEGIN-FULL-OUTPUT-MARKER", out)
        self.assertIn("END-FULL-OUTPUT-MARKER", out)
        self.assertEqual(
            out,
            full_log,
            "self-update job API should return effective-full output, not JOB_OUTPUT_TAIL_CHARS slicing",
        )
        self.assertFalse(bool(payload.get("output_truncated")))


if __name__ == "__main__":
    unittest.main()
