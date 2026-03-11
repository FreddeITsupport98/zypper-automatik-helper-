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


class WebUiBlankGuardPlaywrightRegressionTest(unittest.TestCase):
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

    def _build_harness_html(self) -> str:
        needed_functions = [
            "_znhMiHardBlockShow",
            "_znhMiPreventBlankScreen",
            "_znhMiTick",
        ]
        funcs_js = "\n\n".join(self._extract_function(f) for f in needed_functions)

        return f"""<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<body>
  <div id="main-content" style="display:block">Main</div>
  <div id="znh-multi-instance-page" style="display:none">
    <span id="znh-multi-instance-text"></span>
  </div>
  <script>
    window.__warns = [];
    window.__toasts = [];
    window.__blankGuardCalls = 0;
    window.__scheduledTickMs = null;

    function toast(a, b, c) {{ window.__toasts.push([String(a||''), String(b||''), String(c||'')]); }}
    window.znhUiWarn = function(msg) {{ window.__warns.push(String(msg || '')); }};

    var _znhMi = {{ hbMs: 2500, timer: null }};
    function _znhMiEval() {{}}
    window.clearTimeout = function(_id) {{ return true; }};
    window.setTimeout = function(_fn, ms) {{ window.__scheduledTickMs = Number(ms || 0); return 42; }};

    {funcs_js}

    var __origPrevent = _znhMiPreventBlankScreen;
    _znhMiPreventBlankScreen = function() {{
      window.__blankGuardCalls += 1;
      return __origPrevent();
    }};

    window.__state = function() {{
      var main = document.getElementById('main-content');
      var page = document.getElementById('znh-multi-instance-page');
      return {{
        mainDisplay: main ? String(main.style.display || '') : '',
        pageDisplay: page ? String(page.style.display || '') : '',
        warns: window.__warns.slice(),
        toasts: window.__toasts.slice(),
        blankGuardCalls: window.__blankGuardCalls,
        scheduledTickMs: window.__scheduledTickMs
      }};
    }};
  </script>
</body>
</html>
"""

    def test_blank_screen_is_recovered_and_tick_invokes_guard(self) -> None:
        if sync_playwright is None:
            self.skipTest("playwright is not installed (python package missing)")

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

                # Reproduce blank-screen edge: both blocker page and main hidden.
                page.evaluate(
                    """() => {
                        document.getElementById('main-content').style.display = 'none';
                        document.getElementById('znh-multi-instance-page').style.display = 'none';
                    }"""
                )
                page.evaluate("() => _znhMiPreventBlankScreen()")
                state = page.evaluate("() => window.__state()")
                self.assertEqual(state["mainDisplay"], "block")
                self.assertGreaterEqual(len(state["warns"]), 1)
                self.assertTrue(
                    any("Recovered blank WebUI" in item[0] for item in state["toasts"]),
                    "Expected recovery toast after both-hidden guard state",
                )

                # When blocker node is absent, hard block should not hide main content.
                page.evaluate(
                    """() => {
                        var blocker = document.getElementById('znh-multi-instance-page');
                        if (blocker && blocker.parentNode) blocker.parentNode.removeChild(blocker);
                        document.getElementById('main-content').style.display = 'block';
                        _znhMiHardBlockShow('multi-tab');
                    }"""
                )
                state = page.evaluate("() => window.__state()")
                self.assertEqual(state["mainDisplay"], "block")
                self.assertTrue(
                    any("multi-tab blocker missing; main-content left visible" in w for w in state["warns"])
                )

                # Tick path should invoke blank-screen guard and schedule next heartbeat.
                page.evaluate("() => _znhMiTick()")
                state = page.evaluate("() => window.__state()")
                self.assertGreaterEqual(state["blankGuardCalls"], 2)
                self.assertEqual(state["scheduledTickMs"], 2500)
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
