#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


class SnapperStartResponseContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parent
        cls.script_path = repo_root / "zypper-auto.sh"
        cls.script_text = cls.script_path.read_text(encoding="utf-8")

    def test_snapper_start_success_response_has_required_keys(self) -> None:
        block_match = re.search(
            r'if path == "/api/snapper/start":(?P<body>.*?)\n\s*if path == "/api/snapper/run":',
            self.script_text,
            re.S,
        )
        self.assertIsNotNone(block_match, f"Could not find /api/snapper/start block in {self.script_path}")
        block = str(block_match.group("body"))

        success_match = re.search(
            r'return _json_response\(self,\s*200,\s*\{\s*"job_id":\s*job_id,\s*"coalesced":\s*False,(?P<payload>.*?)\},\s*origin\)',
            block,
            re.S,
        )
        self.assertIsNotNone(success_match, "Could not find canonical /api/snapper/start success response payload")

        payload_text = '"job_id": job_id, "coalesced": False,' + str(success_match.group("payload"))
        keys = set(re.findall(r'"([a-z_]+)"\s*:', payload_text))
        required = {"job_id", "coalesced", "artifact_gc", "preflight"}
        missing = sorted(required - keys)
        self.assertFalse(missing, f"/api/snapper/start success payload missing keys: {missing}; found: {sorted(keys)}")
    def test_quick_action_history_seed_excludes_low_space_keys(self) -> None:
        block_match = re.search(
            r'if path == "/api/quick/start":(?P<body>.*?)\n\s*if path == "/api/self-update/confirm":',
            self.script_text,
            re.S,
        )
        self.assertIsNotNone(block_match, f"Could not find /api/quick/start block in {self.script_path}")
        block = str(block_match.group("body"))

        upsert_match = re.search(
            r'_history_job_upsert\(self\.server,\s*\{(?P<payload>.*?)\},\s*summary=',
            block,
            re.S,
        )
        self.assertIsNotNone(upsert_match, "Could not find quick-action history upsert payload")

        payload_text = "{" + str(upsert_match.group("payload")) + "}"
        self.assertIn('"type": "quick-action"', payload_text, "Expected quick-action history payload type")

        keys = set(re.findall(r'"([a-z_]+)"\s*:', payload_text))
        low_space_keys = {
            "force_low_space",
            "low_space_guard_required",
            "low_space_guard_reason",
            "low_space_hysteresis_enabled",
            "low_space_hysteresis_latched",
            "low_space_free_mb",
            "low_space_critical_mb",
            "low_space_high_mb",
        }
        leaked = sorted(keys & low_space_keys)
        self.assertFalse(
            leaked,
            f"quick-action history payload must not include low-space telemetry keys, found: {leaked}",
        )
    def test_snapper_history_seed_includes_low_space_keys(self) -> None:
        block_match = re.search(
            r'if path == "/api/snapper/start":(?P<body>.*?)\n\s*if path == "/api/snapper/run":',
            self.script_text,
            re.S,
        )
        self.assertIsNotNone(block_match, f"Could not find /api/snapper/start block in {self.script_path}")
        block = str(block_match.group("body"))

        upsert_match = re.search(
            r'_history_job_upsert\(self\.server,\s*\{(?P<payload>.*?)\},\s*summary=',
            block,
            re.S,
        )
        self.assertIsNotNone(upsert_match, "Could not find snapper history upsert payload")

        payload_text = "{" + str(upsert_match.group("payload")) + "}"
        self.assertIn('"type": "snapper"', payload_text, "Expected snapper history payload type")

        keys = set(re.findall(r'"([a-z_]+)"\s*:', payload_text))
        low_space_keys = {
            "force_low_space",
            "low_space_guard_required",
            "low_space_guard_reason",
            "low_space_hysteresis_enabled",
            "low_space_hysteresis_latched",
            "low_space_free_mb",
            "low_space_critical_mb",
            "low_space_high_mb",
        }
        missing = sorted(low_space_keys - keys)
        self.assertFalse(
            missing,
            f"snapper history payload missing low-space telemetry keys: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
