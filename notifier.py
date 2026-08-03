#!/usr/bin/env python3
"""Durable central Telegram delivery for ClamAV suite JSON events."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib import error, request

EVENTS_DIR = Path(os.environ.get("EVENTS_DIR", "/events"))
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
DATABASE_PATH = STATE_DIR / "notifier.sqlite3"
POLL_SECONDS = max(float(os.environ.get("NOTIFIER_POLL_SECONDS", "5")), 1.0)
HTTP_TIMEOUT_SECONDS = max(float(os.environ.get("TELEGRAM_TIMEOUT_SECONDS", "15")), 1.0)
AGGREGATION_SECONDS = max(int(os.environ.get("NOTIFIER_AGGREGATION_SECONDS", "30")), 0)
REPEAT_WINDOW_SECONDS = max(int(os.environ.get("NOTIFIER_REPEAT_WINDOW_SECONDS", "900")), 0)
RETENTION_DAYS = max(int(os.environ.get("NOTIFIER_RETENTION_DAYS", "90")), 1)
REJECTED_RETENTION_DAYS = max(int(os.environ.get("NOTIFIER_REJECTED_RETENTION_DAYS", "30")), 1)
MAX_EVENT_BYTES = max(int(os.environ.get("NOTIFIER_MAX_EVENT_BYTES", "131072")), 4096)
MAX_FILES_PER_CYCLE = max(int(os.environ.get("NOTIFIER_MAX_FILES_PER_CYCLE", "1000")), 1)
MAX_TELEGRAM_TEXT_CHARACTERS = 4000
MAX_HEARTBEAT_AGE_SECONDS = max(
    int(os.environ.get("NOTIFIER_HEALTH_MAX_AGE_SECONDS", "180")), 30
)
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

ALLOWED_SEVERITIES = {"info", "warning", "critical"}
ALLOWED_FIELDS = {
    "schema_version",
    "event_id",
    "event_type",
    "service",
    "severity",
    "timestamp",
    "message",
    "source_path",
    "destination_path",
    "threat_name",
    "action_success",
    "definition_age_seconds",
    "scan_type",
    "job_id",
    "torrent_hash",
}
IMMEDIATE_TYPES = {
    "threat_detected",
    "infected_content_held",
    "infected_content_quarantined",
    "infected_content_deleted",
}
INFO_NOTIFICATION_TYPES = {"service_recovered"}

_stop = False


class TelegramRateLimited(RuntimeError):
    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = max(retry_after, 1)


class DeliveryResult:
    def __init__(self, message_id: str) -> None:
        self.message_id = message_id


def _stop_handler(_signum: int, _frame: object) -> None:
    global _stop
    _stop = True


def connect_database(path: Path = DATABASE_PATH) -> sqlite3.Connection:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    previous_umask = os.umask(0o077)
    try:
        connection = sqlite3.connect(path, timeout=30)
    finally:
        os.umask(previous_umask)
    path.chmod(0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            service TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            payload TEXT NOT NULL,
            group_key TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'suppressed')),
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL DEFAULT 0,
            first_seen_at INTEGER NOT NULL,
            sent_at INTEGER,
            telegram_message_id TEXT,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS events_delivery_idx
            ON events(status, next_attempt_at, first_seen_at);
        CREATE INDEX IF NOT EXISTS events_group_idx
            ON events(status, group_key, first_seen_at);
        CREATE TABLE IF NOT EXISTS rejected_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_path TEXT NOT NULL,
            rejected_at INTEGER NOT NULL,
            error TEXT NOT NULL,
            sample TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    connection.commit()
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            candidate.chmod(0o600)
        except FileNotFoundError:
            continue
    return connection


def _bounded_string(payload: dict[str, Any], key: str, maximum: int, required: bool = False) -> str:
    value = payload.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{key} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{key} is longer than {maximum} characters")
    if "\x00" in value:
        raise ValueError(f"{key} contains a NUL character")
    return value


def validate_event(value: Any, expected_service: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("event root must be an object")
    if value.get("schema_version") != 1:
        raise ValueError("unsupported schema_version")

    event_id = _bounded_string(value, "event_id", 128, required=True)
    event_type = _bounded_string(value, "event_type", 80, required=True)
    service = _bounded_string(value, "service", 80, required=True)
    severity = _bounded_string(value, "severity", 16, required=True).lower()
    timestamp = _bounded_string(value, "timestamp", 64, required=True)
    message = _bounded_string(value, "message", 2000, required=True)
    if expected_service is not None and service != expected_service:
        raise ValueError(f"service {service!r} does not match event directory {expected_service!r}")
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"unsupported severity {severity!r}")
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in service):
        raise ValueError("service contains unsupported characters")
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in event_type):
        raise ValueError("event_type contains unsupported characters")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in event_id):
        raise ValueError("event_id contains unsupported characters")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is not valid ISO-8601") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp must be in UTC")

    clean: dict[str, Any] = {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": event_type,
        "service": service,
        "severity": severity,
        "timestamp": timestamp,
        "message": message,
    }
    for key in ALLOWED_FIELDS - clean.keys():
        if key not in value or value[key] is None:
            continue
        item = value[key]
        if key in {"source_path", "destination_path"}:
            clean[key] = _bounded_string(value, key, 4096)
        elif key in {"threat_name", "scan_type", "job_id", "torrent_hash"}:
            clean[key] = _bounded_string(value, key, 512)
        elif key == "action_success" and isinstance(item, bool):
            clean[key] = item
        elif key == "definition_age_seconds" and isinstance(item, int) and item >= 0:
            clean[key] = item
    return clean


def parse_event(raw: bytes, expected_service: str | None = None) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    return validate_event(payload, expected_service=expected_service)


def _should_notify(event: dict[str, Any]) -> bool:
    return event["severity"] != "info" or event["event_type"] in INFO_NOTIFICATION_TYPES


def _group_key(event: dict[str, Any]) -> str:
    return "\x1f".join(
        (event["service"], event["event_type"], event["message"][:512])
    )


def _event_files() -> Iterable[tuple[Path, str]]:
    try:
        service_directories = sorted(EVENTS_DIR.iterdir(), key=lambda path: path.name)
    except OSError:
        return
    yielded = 0
    for directory in service_directories:
        try:
            info = directory.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode) or directory.name.startswith("."):
            continue
        try:
            paths = sorted(directory.glob("*.json"), key=lambda path: path.name)
        except OSError:
            continue
        for path in paths:
            yield path, directory.name
            yielded += 1
            if yielded >= MAX_FILES_PER_CYCLE:
                return


def _read_regular_event(path: Path) -> tuple[bytes, tuple[int, int, int, int, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("event is not a regular file")
        if info.st_size > MAX_EVENT_BYTES:
            raise ValueError(f"event exceeds {MAX_EVENT_BYTES} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_EVENT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_EVENT_BYTES:
                raise ValueError(f"event exceeds {MAX_EVENT_BYTES} bytes")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        before_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        path_identity = (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_size,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
        )
        if before_identity != after_identity or before_identity != path_identity:
            raise OSError("event changed while it was being read")
        return b"".join(chunks), before_identity
    finally:
        os.close(descriptor)


def _unlink_if_same(path: Path, identity: tuple[int, int, int, int, int]) -> None:
    info = path.lstat()
    current_identity = (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    if current_identity != identity:
        raise OSError("event changed while waiting to be removed")
    path.unlink()


def collect_events(connection: sqlite3.Connection) -> int:
    imported = 0
    now = int(time.time())
    for path, expected_service in _event_files():
        file_identity: tuple[int, int, int, int, int] | None = None
        try:
            raw, file_identity = _read_regular_event(path)
            event = parse_event(raw, expected_service=expected_service)
            notify = _should_notify(event)
            initial_delay = 0 if event["event_type"] in IMMEDIATE_TYPES else AGGREGATION_SECONDS
            group_key = _group_key(event)
            previous = connection.execute(
                "SELECT MAX(sent_at) AS sent_at FROM events WHERE group_key = ? AND status = 'sent'",
                (group_key,),
            ).fetchone()
            next_attempt = now + initial_delay
            if (
                event["event_type"] not in IMMEDIATE_TYPES
                and previous is not None
                and previous["sent_at"] is not None
            ):
                next_attempt = max(next_attempt, int(previous["sent_at"]) + REPEAT_WINDOW_SECONDS)
            connection.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_id, service, event_type, severity, message, payload,
                    group_key, status, next_attempt_at, first_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    event["service"],
                    event["event_type"],
                    event["severity"],
                    event["message"],
                    json.dumps(event, separators=(",", ":"), sort_keys=True),
                    group_key,
                    "pending" if notify else "suppressed",
                    next_attempt,
                    now,
                ),
            )
            connection.commit()
            _unlink_if_same(path, file_identity)
            imported += 1
        except (OSError, ValueError) as exc:
            if isinstance(exc, OSError) and "changed while" in str(exc):
                continue
            connection.execute(
                "INSERT INTO rejected_events(source_path, rejected_at, error, sample) VALUES (?, ?, ?, ?)",
                (str(path), now, str(exc)[:2000], ""),
            )
            connection.commit()
            try:
                rejected_identity = file_identity
                if rejected_identity is None:
                    info = path.lstat()
                    rejected_identity = (
                        info.st_dev,
                        info.st_ino,
                        info.st_size,
                        info.st_mtime_ns,
                        info.st_ctime_ns,
                    )
                _unlink_if_same(path, rejected_identity)
            except OSError:
                pass
            print(f"[notifier] rejected {path}: {exc}", file=sys.stderr, flush=True)
    return imported


def render_message(event: dict[str, Any], repeat_count: int = 1) -> str:
    severity_icon = {"critical": "🚨", "warning": "⚠️", "info": "✅"}
    lines = [
        f"{severity_icon.get(event['severity'], 'ℹ️')} ClamAV: {event['event_type']}",
        f"Service: {event['service']}",
        event["message"],
    ]
    if event.get("threat_name"):
        lines.append(f"Threat: {event['threat_name']}")
    if event.get("source_path"):
        lines.append(f"Source: {event['source_path']}")
    if event.get("destination_path"):
        lines.append(f"Destination: {event['destination_path']}")
    if repeat_count > 1:
        lines.append(f"Occurrences combined: {repeat_count}")
    lines.append(f"Time: {event['timestamp']}")
    rendered = "\n".join(lines)
    if len(rendered) > MAX_TELEGRAM_TEXT_CHARACTERS:
        rendered = rendered[: MAX_TELEGRAM_TEXT_CHARACTERS - 3] + "..."
    return rendered


def _telegram_retry_after(payload: Any, default: int = 60) -> int:
    if isinstance(payload, dict):
        parameters = payload.get("parameters")
        if isinstance(parameters, dict):
            value = parameters.get("retry_after")
            if isinstance(value, int) and value > 0:
                return value
    return default


def send_telegram(text: str) -> DeliveryResult:
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")
    body = json.dumps({"chat_id": CHAT_ID, "text": text}).encode("utf-8")
    http_request = request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            response_body = response.read(1024 * 1024)
    except error.HTTPError as exc:
        details = exc.read(65536)
        try:
            payload = json.loads(details.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        if exc.code == 429:
            raise TelegramRateLimited("Telegram rate limit", _telegram_retry_after(payload)) from exc
        description = payload.get("description") if isinstance(payload, dict) else None
        raise RuntimeError(f"Telegram HTTP {exc.code}: {description or 'request failed'}") from exc
    try:
        payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Telegram returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        if isinstance(payload, dict) and payload.get("error_code") == 429:
            raise TelegramRateLimited(
                "Telegram rate limit", _telegram_retry_after(payload)
            )
        raise RuntimeError("Telegram API returned ok=false")
    result = payload.get("result")
    message_id = result.get("message_id") if isinstance(result, dict) else None
    if not isinstance(message_id, (int, str)):
        raise RuntimeError("Telegram response did not include a message id")
    return DeliveryResult(message_id=str(message_id))


def _delivery_group(connection: sqlite3.Connection, first: sqlite3.Row) -> list[sqlite3.Row]:
    if first["event_type"] in IMMEDIATE_TYPES:
        return [first]
    return list(
        connection.execute(
            """
            SELECT * FROM events
            WHERE status = 'pending' AND group_key = ? AND first_seen_at <= ?
            ORDER BY first_seen_at, event_id LIMIT 1000
            """,
            (first["group_key"], int(time.time())),
        )
    )


def deliver_pending(connection: sqlite3.Connection) -> bool:
    now = int(time.time())
    first = connection.execute(
        """
        SELECT * FROM events
        WHERE status = 'pending' AND next_attempt_at <= ?
        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                 first_seen_at, event_id
        LIMIT 1
        """,
        (now,),
    ).fetchone()
    if first is None:
        return False
    rows = _delivery_group(connection, first)
    event = json.loads(first["payload"])
    identifiers = [row["event_id"] for row in rows]
    placeholders = ",".join("?" for _ in identifiers)
    try:
        result = send_telegram(render_message(event, repeat_count=len(rows)))
    except Exception as exc:
        attempts = max(int(row["attempts"]) for row in rows) + 1
        if isinstance(exc, TelegramRateLimited):
            retry_at = now + exc.retry_after
        else:
            retry_at = now + min(3600, 30 * (2 ** min(attempts - 1, 7)))
        connection.execute(
            f"""
            UPDATE events SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
            WHERE event_id IN ({placeholders})
            """,
            (retry_at, str(exc)[:2000], *identifiers),
        )
        connection.commit()
        print(f"[notifier] delivery failed; retry scheduled: {exc}", file=sys.stderr, flush=True)
        return False

    connection.execute(
        f"""
        UPDATE events
        SET status = 'sent', sent_at = ?, telegram_message_id = ?, last_error = NULL
        WHERE event_id IN ({placeholders})
        """,
        (now, result.message_id, *identifiers),
    )
    connection.commit()
    print(
        f"[notifier] delivered {len(identifiers)} event(s), message_id={result.message_id}",
        flush=True,
    )
    return True


def record_heartbeat(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES ('heartbeat', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(int(time.time())),),
    )
    connection.commit()


def prune_history(connection: sqlite3.Connection) -> None:
    now = int(time.time())
    last = connection.execute(
        "SELECT value FROM metadata WHERE key='last_prune'"
    ).fetchone()
    if last is not None and now - int(last["value"]) < 86400:
        return
    event_cutoff = now - RETENTION_DAYS * 86400
    rejected_cutoff = now - REJECTED_RETENTION_DAYS * 86400
    connection.execute(
        "DELETE FROM events WHERE status IN ('sent', 'suppressed') AND first_seen_at < ?",
        (event_cutoff,),
    )
    connection.execute("DELETE FROM rejected_events WHERE rejected_at < ?", (rejected_cutoff,))
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES ('last_prune', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(now),),
    )
    connection.commit()


def healthcheck() -> int:
    try:
        if not BOT_TOKEN or not CHAT_ID:
            raise RuntimeError("Telegram credentials are missing")
        if not EVENTS_DIR.is_dir() or not os.access(EVENTS_DIR, os.R_OK | os.X_OK):
            raise RuntimeError(f"event directory is not readable: {EVENTS_DIR}")
        connection = connect_database()
        try:
            connection.execute("SELECT 1").fetchone()
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='heartbeat'"
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RuntimeError("notifier heartbeat is missing")
        if int(time.time()) - int(row["value"]) > MAX_HEARTBEAT_AGE_SECONDS:
            raise RuntimeError("notifier heartbeat is stale")
        print("healthy")
        return 0
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


def interruptible_sleep(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while not _stop and time.monotonic() < deadline:
        time.sleep(min(0.5, deadline - time.monotonic()))


def main() -> int:
    if "--healthcheck" in sys.argv:
        return healthcheck()
    if not BOT_TOKEN or not CHAT_ID:
        print("[notifier] Telegram credentials are required", file=sys.stderr, flush=True)
        return 2
    signal.signal(signal.SIGTERM, _stop_handler)
    signal.signal(signal.SIGINT, _stop_handler)
    connection = connect_database()
    print(f"[notifier] started events={EVENTS_DIR} database={DATABASE_PATH}", flush=True)
    try:
        while not _stop:
            try:
                imported = collect_events(connection)
                record_heartbeat(connection)
                prune_history(connection)
                delivered = deliver_pending(connection)
                if imported:
                    print(f"[notifier] imported {imported} event file(s)", flush=True)
                if delivered:
                    continue
            except Exception as exc:
                print(f"[notifier] cycle failed: {exc}", file=sys.stderr, flush=True)
            interruptible_sleep(POLL_SECONDS)
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
