from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "notifier.py"
spec = importlib.util.spec_from_file_location("scheduled_notifier", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class NotifierTests(unittest.TestCase):
    def test_parses_structured_threat_event(self) -> None:
        raw = json.dumps(
            {
                "event": "threat_detected",
                "scan": "FULL",
                "threat": "Eicar-Signature",
                "source": "/scan/eicar.com",
                "quarantine": "/quarantine/eicar.com",
                "quarantine_success": True,
            }
        ).encode()
        event = module.parse_event(raw, "abc", "clamav_scheduled.log")
        self.assertIsNotNone(event)
        self.assertEqual(event["threat"], "Eicar-Signature")
        self.assertTrue(event["quarantine_success"])

    def test_ignores_non_json_log_lines(self) -> None:
        self.assertIsNone(module.parse_event(b"[FULL] normal line", "abc", "scan.log"))

    def test_first_start_skips_existing_logs_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = Path(temporary)
            log_path = log_dir / "clamav_scheduled.log"
            log_path.write_text(
                '{"event":"threat_detected","source":"old","threat":"old"}\n',
                encoding="utf-8",
            )
            old_log_dir = module.LOG_DIR
            old_replay = module.REPLAY_EXISTING
            module.LOG_DIR = log_dir
            module.REPLAY_EXISTING = False
            try:
                state = module.new_state()
                module.collect_events(state)
                self.assertEqual(state["pending"], [])
                self.assertTrue(state["initialized"])
            finally:
                module.LOG_DIR = old_log_dir
                module.REPLAY_EXISTING = old_replay


if __name__ == "__main__":
    unittest.main()
