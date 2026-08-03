from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).parents[1] / "notifier.py"
spec = importlib.util.spec_from_file_location("central_notifier", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def example_event(event_id: str = "event-1", **changes: object) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": "scan_failed",
        "service": "web-scan-move",
        "severity": "warning",
        "timestamp": "2026-08-02T00:00:00Z",
        "message": "Scan failed",
        "source_path": "/watch/example.bin",
    }
    event.update(changes)
    return event


class NotifierTests(unittest.TestCase):
    def test_sqlite_files_are_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state" / "notifier.sqlite3"
            connection = module.connect_database(database)
            try:
                connection.execute("INSERT INTO metadata(key, value) VALUES ('mode-test', '1')")
                connection.commit()
                self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)
                for suffix in ("-wal", "-shm"):
                    candidate = Path(f"{database}{suffix}")
                    if candidate.exists():
                        self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            finally:
                connection.close()

    def test_validates_structured_event_and_directory_service(self) -> None:
        event = module.parse_event(
            json.dumps(example_event(failure_kind="scan_policy_limit")).encode(),
            expected_service="web-scan-move",
        )
        self.assertEqual(event["event_id"], "event-1")
        self.assertEqual(event["failure_kind"], "scan_policy_limit")
        with self.assertRaises(ValueError):
            module.parse_event(
                json.dumps(example_event()).encode(), expected_service="clamav-scheduled"
            )
        with self.assertRaisesRegex(ValueError, "UTC"):
            module.validate_event(example_event(timestamp="2026-08-02T01:00:00+01:00"))

    def test_symlink_event_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            service = events / "web-scan-move"
            service.mkdir(parents=True)
            outside = root / "outside.json"
            outside.write_text(json.dumps(example_event()), encoding="utf-8")
            link = service / "linked.json"
            link.symlink_to(outside)
            connection = module.connect_database(root / "state" / "notifier.sqlite3")
            old_events = module.EVENTS_DIR
            module.EVENTS_DIR = events
            try:
                self.assertEqual(module.collect_events(connection), 0)
                self.assertTrue(outside.exists())
                self.assertFalse(link.exists())
                self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 0)
            finally:
                module.EVENTS_DIR = old_events
                connection.close()

    def test_import_is_durable_and_duplicate_event_id_is_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            service = events / "web-scan-move"
            service.mkdir(parents=True)
            database = root / "state" / "notifier.sqlite3"
            connection = module.connect_database(database)
            old_events = module.EVENTS_DIR
            old_delay = module.AGGREGATION_SECONDS
            module.EVENTS_DIR = events
            module.AGGREGATION_SECONDS = 0
            try:
                first = service / "first.json"
                first.write_text(json.dumps(example_event()), encoding="utf-8")
                self.assertEqual(module.collect_events(connection), 1)
                self.assertFalse(first.exists())
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM events").fetchone()[0], 1
                )

                duplicate = service / "duplicate.json"
                duplicate.write_text(json.dumps(example_event()), encoding="utf-8")
                self.assertEqual(module.collect_events(connection), 1)
                self.assertFalse(duplicate.exists())
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM events").fetchone()[0], 1
                )
            finally:
                module.EVENTS_DIR = old_events
                module.AGGREGATION_SECONDS = old_delay
                connection.close()

    def test_rejected_event_does_not_unlink_a_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            service = events / "web-scan-move"
            service.mkdir(parents=True)
            event_path = service / "event.json"
            event_path.write_text("invalid", encoding="utf-8")
            replacement = json.dumps(example_event(event_id="replacement"))
            connection = module.connect_database(root / "state" / "notifier.sqlite3")
            old_events = module.EVENTS_DIR
            module.EVENTS_DIR = events

            def replace_then_reject(_raw: bytes, expected_service: str | None = None):
                event_path.unlink()
                event_path.write_text(replacement, encoding="utf-8")
                raise ValueError("rejected old event")

            try:
                with mock.patch.object(module, "parse_event", side_effect=replace_then_reject):
                    self.assertEqual(module.collect_events(connection), 0)
                self.assertEqual(event_path.read_text(encoding="utf-8"), replacement)
                self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 0)
            finally:
                module.EVENTS_DIR = old_events
                connection.close()

    def test_marks_sent_only_after_telegram_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            service = events / "web-scan-move"
            service.mkdir(parents=True)
            connection = module.connect_database(root / "state" / "notifier.sqlite3")
            old_events = module.EVENTS_DIR
            old_delay = module.AGGREGATION_SECONDS
            module.EVENTS_DIR = events
            module.AGGREGATION_SECONDS = 0
            try:
                (service / "event.json").write_text(
                    json.dumps(example_event()), encoding="utf-8"
                )
                module.collect_events(connection)
                with mock.patch.object(module, "send_telegram", side_effect=RuntimeError("offline")):
                    self.assertFalse(module.deliver_pending(connection))
                row = connection.execute(
                    "SELECT status, attempts FROM events WHERE event_id='event-1'"
                ).fetchone()
                self.assertEqual((row["status"], row["attempts"]), ("pending", 1))

                connection.execute(
                    "UPDATE events SET next_attempt_at=0 WHERE event_id='event-1'"
                )
                connection.commit()
                with mock.patch.object(
                    module, "send_telegram", return_value=module.DeliveryResult("42")
                ):
                    self.assertTrue(module.deliver_pending(connection))
                row = connection.execute(
                    "SELECT status, telegram_message_id FROM events WHERE event_id='event-1'"
                ).fetchone()
                self.assertEqual((row["status"], row["telegram_message_id"]), ("sent", "42"))
            finally:
                module.EVENTS_DIR = old_events
                module.AGGREGATION_SECONDS = old_delay
                connection.close()

    def test_info_updates_are_stored_without_telegram_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            service = events / "clamav-defs-updater"
            service.mkdir(parents=True)
            connection = module.connect_database(root / "state" / "notifier.sqlite3")
            old_events = module.EVENTS_DIR
            module.EVENTS_DIR = events
            try:
                event = example_event(
                    service="clamav-defs-updater",
                    event_type="definitions_updated",
                    severity="info",
                )
                (service / "event.json").write_text(json.dumps(event), encoding="utf-8")
                module.collect_events(connection)
                row = connection.execute("SELECT status FROM events").fetchone()
                self.assertEqual(row["status"], "suppressed")
            finally:
                module.EVENTS_DIR = old_events
                connection.close()

    def test_rate_limit_retry_after_is_honored(self) -> None:
        self.assertEqual(
            module._telegram_retry_after({"parameters": {"retry_after": 17}}), 17
        )

    def test_repeat_operational_event_waits_for_group_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            service = events / "web-scan-move"
            service.mkdir(parents=True)
            connection = module.connect_database(root / "state" / "notifier.sqlite3")
            old_values = (module.EVENTS_DIR, module.AGGREGATION_SECONDS, module.REPEAT_WINDOW_SECONDS)
            module.EVENTS_DIR = events
            module.AGGREGATION_SECONDS = 0
            module.REPEAT_WINDOW_SECONDS = 900
            try:
                (service / "first.json").write_text(json.dumps(example_event()), encoding="utf-8")
                module.collect_events(connection)
                with mock.patch.object(
                    module, "send_telegram", return_value=module.DeliveryResult("1")
                ):
                    self.assertTrue(module.deliver_pending(connection))
                sent_at = connection.execute(
                    "SELECT sent_at FROM events WHERE event_id='event-1'"
                ).fetchone()["sent_at"]

                second = example_event(event_id="event-2")
                (service / "second.json").write_text(json.dumps(second), encoding="utf-8")
                module.collect_events(connection)
                next_attempt = connection.execute(
                    "SELECT next_attempt_at FROM events WHERE event_id='event-2'"
                ).fetchone()["next_attempt_at"]
                self.assertGreaterEqual(next_attempt, sent_at + 900)
                self.assertFalse(module.deliver_pending(connection))
            finally:
                (
                    module.EVENTS_DIR,
                    module.AGGREGATION_SECONDS,
                    module.REPEAT_WINDOW_SECONDS,
                ) = old_values
                connection.close()

    def test_message_is_plain_text_and_includes_combined_count(self) -> None:
        message = module.render_message(
            module.validate_event(example_event(failure_kind="scan_policy_limit")),
            3,
        )
        self.assertIn("Occurrences combined: 3", message)
        self.assertIn("Failure kind: scan_policy_limit", message)
        self.assertNotIn("parse_mode", message)

    def test_message_is_bounded_for_telegram(self) -> None:
        event = module.validate_event(example_event())
        event["message"] = "m" * 2000
        event["source_path"] = "/watch/" + "s" * 4090
        event["destination_path"] = "/quarantine/" + "d" * 4080
        message = module.render_message(event)
        self.assertLessEqual(len(message), module.MAX_TELEGRAM_TEXT_CHARACTERS)
        self.assertTrue(message.endswith("..."))


if __name__ == "__main__":
    unittest.main()
