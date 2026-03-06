#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


class AiSmartReportContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parent
        cls.script_path = repo_root / "zypper-auto.sh"
        cls.script_text = cls.script_path.read_text(encoding="utf-8")

    def _smart_report_block(self) -> str:
        block_match = re.search(
            r'if path == "/api/ai/smart-report":(?P<body>.*?)\n\s*# --- Confirmation token cache \(shared\) ---',
            self.script_text,
            re.S,
        )
        self.assertIsNotNone(block_match, f'Could not find /api/ai/smart-report block in {self.script_path}')
        return str(block_match.group("body"))

    def test_smart_report_payload_includes_repair_plan_and_initiation_fields(self) -> None:
        block = self._smart_report_block()
        payload_match = re.search(
            r'payload\s*=\s*\{(?P<payload>.*?)\}\n\s*return _json_response\(self,\s*200,\s*payload,\s*origin\)',
            block,
            re.S,
        )
        self.assertIsNotNone(payload_match, "Could not find /api/ai/smart-report payload object")
        payload_text = "{" + str(payload_match.group("payload")) + "}"

        keys = set(re.findall(r'"([a-z_]+)"\s*:', payload_text))
        required = {"repair_plan", "initiated_repair", "counts", "failed_jobs", "files", "text"}
        missing = sorted(required - keys)
        self.assertFalse(missing, f"/api/ai/smart-report payload missing keys: {missing}; found: {sorted(keys)}")

    def test_smart_report_builds_selected_repair_action_fields(self) -> None:
        block = self._smart_report_block()
        plan_match = re.search(
            r'def _build_repair_plan\(issue_lines: list\[str\]\) -> dict:(?P<body>.*?)\n\s*def _ai_start_quick_action',
            block,
            re.S,
        )
        self.assertIsNotNone(plan_match, "Could not find _build_repair_plan implementation in smart-report block")
        plan_text = str(plan_match.group("body"))

        required_literals = [
            '"selected_action"',
            '"selected_label"',
            '"selected_reason"',
            '"confidence"',
            '"needs_confirm"',
            '"can_auto_start"',
            '"matches"',
        ]
        for lit in required_literals:
            self.assertIn(lit, plan_text, f"Missing repair-plan field literal: {lit}")

    def test_smart_report_supports_optional_repair_initiation_flag(self) -> None:
        block = self._smart_report_block()
        self.assertRegex(
            block,
            r'initiate_repair\s*=\s*bool\(body\.get\("initiate_repair",\s*False\)\)',
            "smart-report must parse initiate_repair request flag",
        )
        self.assertIn(
            "if initiate_repair:",
            block,
            "smart-report must have a guarded initiation path when initiate_repair is true",
        )
    def test_smart_report_ai_start_routes_to_shared_launcher(self) -> None:
        block = self._smart_report_block()
        ai_start_match = re.search(
            r'def _ai_start_quick_action\(ai_action: str, meta: dict\) -> dict:(?P<body>.*?)\n\s*issue_lines = _collect_issue_lines\(\)',
            block,
            re.S,
        )
        self.assertIsNotNone(ai_start_match, "Could not find _ai_start_quick_action implementation")
        ai_start_text = str(ai_start_match.group("body"))

        self.assertIn(
            "_launch_quick_action(",
            ai_start_text,
            "AI smart-report quick-action starter must call shared _launch_quick_action helper",
        )
        self.assertIn(
            'ai_source="webui-ai-smart-report"',
            ai_start_text,
            "AI smart-report starter must preserve webui-ai-smart-report source tagging",
        )


if __name__ == "__main__":
    unittest.main()
