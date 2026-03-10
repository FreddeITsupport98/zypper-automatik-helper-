#!/usr/bin/env python3
# RUNNER_OPTIONAL=1
# RUNNER_RUNTIME=playwright
import re
import unittest
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover - optional dependency
    sync_playwright = None


class SnapperTimerPlaywrightRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        cls.script_path = repo_root / "zypper-auto.sh"
        cls.script_text = cls.script_path.read_text(encoding="utf-8")

    @classmethod
    def _extract_function(cls, name: str) -> str:
        pattern = re.compile(rf"function\s+{re.escape(name)}\s*\(")
        m = pattern.search(cls.script_text)
        if not m:
            raise AssertionError(f"Could not find function {name} in {cls.script_path}")

        start = m.start()
        brace_start = cls.script_text.find("{", m.end())
        if brace_start < 0:
            raise AssertionError(f"Could not find opening brace for function {name}")

        text = cls.script_text
        depth = 0
        i = brace_start
        in_single = False
        in_double = False
        in_backtick = False
        escaped = False

        while i < len(text):
            ch = text[i]

            if escaped:
                escaped = False
                i += 1
                continue

            if in_single:
                if ch == "\\":
                    escaped = True
                elif ch == "'":
                    in_single = False
                i += 1
                continue

            if in_double:
                if ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_double = False
                i += 1
                continue

            if in_backtick:
                if ch == "\\":
                    escaped = True
                elif ch == "`":
                    in_backtick = False
                i += 1
                continue

            if ch == "'":
                in_single = True
                i += 1
                continue
            if ch == '"':
                in_double = True
                i += 1
                continue
            if ch == "`":
                in_backtick = True
                i += 1
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
            i += 1

        raise AssertionError(f"Could not parse full function body for {name}")

    @classmethod
    def _extract_var_line(cls, var_name: str) -> str:
        m = re.search(rf"var\s+{re.escape(var_name)}\s*=\s*[^;]+;", cls.script_text)
        if not m:
            raise AssertionError(f"Could not find var declaration for {var_name}")
        return m.group(0)

    def _build_harness_html(self) -> str:
        needed_vars = [
            "_znhSnapperTimerOverride",
            "_znhSnapperTimerApiSyncLastMs",
            "_znhSnapperTimerApiSyncInFlight",
        ]
        needed_functions = [
            "setTimerState",
            "_znhSnapperTimerStateNorm",
            "_znhSnapperTimerUiSetBtn",
            "znhSnapperSyncTimerButtons",
            "_znhSnapperTimerMaybeApiSync",
            "_znhSnapperTimerOverrideSetFromApi",
            "_znhSnapperTimerOverrideGet",
            "_znhSnapperTimerOverrideMaybeClear",
            "znhSnapperRefreshTimerBadges",
            "applyLiveData",
        ]

        vars_js = "\n".join(self._extract_var_line(v) for v in needed_vars)
        funcs_js = "\n\n".join(self._extract_function(f) for f in needed_functions)

        return f"""<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<body>
  <span id="snapper-timeline-timer">disabled</span>
  <span id="snapper-cleanup-timer">disabled</span>
  <span id="snapper-boot-timer">disabled</span>
  <button class="pill" id="snapper-auto-enable-btn">Enable all</button>
  <button class="pill" id="snapper-auto-disable-btn">Disable all</button>
  <button class="pill" id="snapper-enable-timeline-btn">Enable timeline</button>
  <button class="pill" id="snapper-enable-cleanup-btn">Enable cleanup</button>
  <button class="pill" id="snapper-enable-boot-btn">Enable boot</button>
  <button class="pill" id="snapper-disable-timeline-btn">Disable timeline</button>
  <button class="pill" id="snapper-disable-cleanup-btn">Disable cleanup</button>
  <button class="pill" id="snapper-disable-boot-btn">Disable boot</button>
  <pre id="log-content"></pre>
  <pre id="flight-content"></pre>
  <script>
    window.__apiQueue = [];
    window.__apiCalls = 0;
    window.__now = 1700000000000;
    Date.now = function() {{ return window.__now; }};

    function _api(path, _opts) {{
      window.__apiCalls += 1;
      if (path === '/api/snapper/timers') {{
        var next = window.__apiQueue.length ? window.__apiQueue.shift() : null;
        if (!next) {{
          next = {{
            snapper_timeline_timer: 'missing',
            snapper_cleanup_timer: 'missing',
            snapper_boot_timer: 'missing'
          }};
        }}
        return Promise.resolve(next);
      }}
      return Promise.resolve({{}});
    }}

    function _znhMarkUpdated(_el) {{}}
    function setText(id, value) {{
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = String(value === undefined || value === null ? '' : value);
    }}
    function znhDispatch(_name, _payload) {{ return true; }}
    function _znhSetHeaderStatusBadge(_s) {{}}
    function updateRebootRequiredBadge(_d) {{}}
    function updateZyppLockBadge(_d) {{}}
    function _rocketSetAvailable(_on) {{}}
    function updateDiskBar(_pct) {{}}
    function setClass(_id, _on) {{}}
    function _nearBottom(_el, _px) {{ return true; }}
    function highlightBlock(_id) {{}}
    function updateJumpButton(_id, _wrap) {{}}
    var genTime = null;
    var logView = 'install';
    var _logAutoScrollOnce = false;

    {vars_js}
    {funcs_js}

    document.getElementById('snapper-auto-enable-btn').addEventListener('click', function() {{
      znhSnapperRefreshTimerBadges();
    }});
    document.getElementById('snapper-auto-disable-btn').addEventListener('click', function() {{
      znhSnapperRefreshTimerBadges();
    }});

    window.__snapperState = function() {{
      function byId(id) {{ return document.getElementById(id); }}
      return {{
        timeline_badge: byId('snapper-timeline-timer').textContent,
        cleanup_badge: byId('snapper-cleanup-timer').textContent,
        boot_badge: byId('snapper-boot-timer').textContent,
        auto_enable_disabled: byId('snapper-auto-enable-btn').disabled,
        auto_disable_disabled: byId('snapper-auto-disable-btn').disabled,
        auto_enable_on: byId('snapper-auto-enable-btn').classList.contains('state-on'),
        auto_disable_off: byId('snapper-auto-disable-btn').classList.contains('state-off'),
        timeline_enable_disabled: byId('snapper-enable-timeline-btn').disabled,
        timeline_disable_disabled: byId('snapper-disable-timeline-btn').disabled,
        timeline_enable_on: byId('snapper-enable-timeline-btn').classList.contains('state-on'),
        timeline_disable_off: byId('snapper-disable-timeline-btn').classList.contains('state-off')
      }};
    }};
  </script>
</body>
</html>
"""

    def test_timer_buttons_and_badges_survive_live_poll_reconciliation(self) -> None:
        if sync_playwright is None:
            self.skipTest("playwright is not installed (python package missing)")

        enabled_all = {
            "snapper_timeline_timer": "enabled",
            "snapper_cleanup_timer": "enabled",
            "snapper_boot_timer": "enabled",
        }
        disabled_all = {
            "snapper_timeline_timer": "disabled",
            "snapper_cleanup_timer": "disabled",
            "snapper_boot_timer": "disabled",
        }

        html = self._build_harness_html()

        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception as exc:  # pragma: no cover - environment dependent
                self.skipTest(f"playwright chromium is not available: {exc}")
                return

            page = browser.new_page()
            try:
                page.set_content(html, wait_until="domcontentloaded")

                # Simulate clicking "Enable all" (backed by authoritative timers API).
                page.evaluate("payloads => { window.__apiQueue = payloads.slice(); }", [enabled_all, enabled_all])
                page.click("#snapper-auto-enable-btn")
                page.wait_for_timeout(80)

                state = page.evaluate("() => window.__snapperState()")
                self.assertEqual(state["timeline_badge"], "✓ enabled")
                self.assertTrue(state["timeline_enable_disabled"])
                self.assertFalse(state["timeline_disable_disabled"])
                self.assertTrue(state["timeline_enable_on"])
                self.assertTrue(state["auto_enable_disabled"])
                self.assertFalse(state["auto_disable_disabled"])
                self.assertTrue(state["auto_enable_on"])

                # Simulate stale status-data polls saying "disabled"; override should keep enabled.
                stale_disabled_poll = dict(disabled_all)
                page.evaluate("payload => applyLiveData(payload)", stale_disabled_poll)
                page.evaluate("() => { window.__now += 1000; }")
                page.evaluate("payload => applyLiveData(payload)", stale_disabled_poll)
                page.wait_for_timeout(80)

                state = page.evaluate("() => window.__snapperState()")
                self.assertEqual(state["timeline_badge"], "✓ enabled")
                self.assertTrue(state["timeline_enable_disabled"])
                self.assertTrue(state["auto_enable_disabled"])

                # Simulate CLI-side change to disabled; throttled API resync should pull it in.
                page.evaluate("payloads => { window.__apiQueue = payloads.slice(); }", [disabled_all, disabled_all])
                page.evaluate("() => { window.__now += 16000; }")
                page.evaluate("payload => applyLiveData(payload)", enabled_all)  # stale payload still says enabled
                page.wait_for_timeout(80)

                state = page.evaluate("() => window.__snapperState()")
                self.assertEqual(state["timeline_badge"], "✓ disabled")
                self.assertFalse(state["timeline_enable_disabled"])
                self.assertTrue(state["timeline_disable_disabled"])
                self.assertTrue(state["timeline_disable_off"])
                self.assertFalse(state["auto_enable_disabled"])
                self.assertTrue(state["auto_disable_disabled"])
                self.assertTrue(state["auto_disable_off"])

                # Additional stale polls should not regress button/badge state.
                page.evaluate("() => { window.__now += 1000; }")
                page.evaluate("payload => applyLiveData(payload)", enabled_all)
                page.evaluate("() => { window.__now += 1000; }")
                page.evaluate("payload => applyLiveData(payload)", enabled_all)
                page.wait_for_timeout(80)

                state = page.evaluate("() => window.__snapperState()")
                self.assertEqual(state["timeline_badge"], "✓ disabled")
                self.assertTrue(state["timeline_disable_disabled"])
                self.assertTrue(state["auto_disable_disabled"])

                api_calls = page.evaluate("() => window.__apiCalls")
                self.assertGreaterEqual(api_calls, 2, "Expected at least one click refresh plus one throttled resync")
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
