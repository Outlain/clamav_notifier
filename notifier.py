#!/usr/bin/env python3
"""Durable Telegram notifier for clamav-scheduled structured threat events."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib import error, request

LOG_DIR = Path(os.environ.get("CLAMAV_LOG_DIR", "/logs"))
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
STATE_FILE = STATE_DIR / "notifier-state.json"
POLL_SECONDS = max(float(os.environ.get("NOTIFIER_POLL_SECONDS", "15")), 1.0)
HTTP_TIMEOUT_SECONDS = max(float(os.environ.get("TELEGRAM_TIMEOUT_SECONDS", "15")), 1.0)
REPLAY_EXISTING = os.environ.get("NOTIFIER_REPLAY_EXISTING", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
MAX_DELIVERED_IDS = 5000


def new_state() -> dict[str, Any]:
    return {
        "version": 2,
        "initialized": False,
        "files": {},
        "pending": [],
        "delivered": [],
    }


def load_state() -> dict[str, Any]:
    try:
        with STATE_FILE.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        if not isinstance(state, dict):
            raise ValueError("state root is not an object")
    except FileNotFoundError:
        return new_state()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[notifier] state could not be read; starting fresh: {exc}", flush=True)
        return new_state()

    defaults = new_state()
    for key, value in defaults.items():
        state.setdefault(key, value)
    if not isinstance(state["files"], dict):
        state["files"] = {}
    if not isinstance(state["pending"], list):
        state["pending"] = []
    if not isinstance(state["delivered"], list):
        state["delivered"] = []
    return state


def save_state(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".notifier-state.", suffix=".tmp", dir=STATE_DIR
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_FILE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def file_identity(path: Path) -> tuple[str, int]:
    info = path.stat()
    return f"{info.st_dev}:{info.st_ino}", info.st_size


def event_identifier(identity: str, offset: int, raw_line: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(identity.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(offset).encode("ascii"))
    digest.update(b"\0")
    digest.update(raw_line)
    return digest.hexdigest()


def parse_event(raw_line: bytes, identifier: str, log_name: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("event") != "threat_detected":
        return None

    source = payload.get("source")
    threat = payload.get("threat")
    if not isinstance(source, str) or not source:
        return None
    if not isinstance(threat, str) or not threat:
        threat = "unknown"

    return {
        "id": identifier,
        "scan": str(payload.get("scan") or "unknown"),
        "threat": threat,
        "source": source,
        "quarantine": payload.get("quarantine"),
        "quarantine_success": payload.get("quarantine_success"),
        "source_log": log_name,
        "created_at": int(time.time()),
        "attempts": 0,
        "next_attempt_at": 0,
    }


def log_files() -> list[Path]:
    try:
        candidates = [path for path in LOG_DIR.iterdir() if path.is_file() and ".log" in path.name]
    except FileNotFoundError:
        return []
    return sorted(candidates, key=lambda path: path.name)


def collect_events(state: dict[str, Any]) -> None:
    paths = log_files()
    pending_ids = {str(item.get("id")) for item in state["pending"] if isinstance(item, dict)}
    delivered_ids = {str(item) for item in state["delivered"]}

    if not state.get("initialized"):
        for path in paths:
            try:
                identity, size = file_identity(path)
            except OSError:
                continue
            state["files"][identity] = {
                "offset": 0 if REPLAY_EXISTING else size,
                "last_path": str(path),
            }
        state["initialized"] = True
        return

    for path in paths:
        try:
            identity, size = file_identity(path)
        except OSError:
            continue

        record = state["files"].setdefault(identity, {"offset": 0, "last_path": str(path)})
        offset = int(record.get("offset", 0))
        if offset < 0 or size < offset:
            offset = 0

        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                while True:
                    line_offset = handle.tell()
                    raw_line = handle.readline()
                    if not raw_line:
                        break
                    if not raw_line.endswith(b"\n"):
                        handle.seek(line_offset)
                        break
                    identifier = event_identifier(identity, line_offset, raw_line)
                    event = parse_event(raw_line.rstrip(b"\r\n"), identifier, path.name)
                    if event and identifier not in pending_ids and identifier not in delivered_ids:
                        state["pending"].append(event)
                        pending_ids.add(identifier)
                        print(
                            f"[notifier] queued threat={event['threat']!r} source={event['source']!r}",
                            flush=True,
                        )
                    offset = handle.tell()
        except OSError as exc:
            print(f"[notifier] could not read {path}: {exc}", flush=True)
            continue

        record["offset"] = offset
        record["last_path"] = str(path)
        record["last_seen_at"] = int(time.time())


def render_message(event: dict[str, Any]) -> str:
    quarantine_success = event.get("quarantine_success")
    if quarantine_success is True:
        quarantine_result = f"Moved to: {event.get('quarantine') or 'unknown'}"
    elif quarantine_success is False:
        quarantine_result = "Quarantine FAILED — inspect the source immediately"
    else:
        quarantine_result = "Quarantine result: unknown"

    return (
        "🚨 ClamAV malware alert\n"
        f"Scan: {event.get('scan', 'unknown')}\n"
        f"Threat: {event.get('threat', 'unknown')}\n"
        f"Source: {event.get('source', 'unknown')}\n"
        f"{quarantine_result}\n"
        f"Log: {event.get('source_log', 'unknown')}"
    )


def send_telegram(event: dict[str, Any]) -> None:
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")
    body = json.dumps({"chat_id": CHAT_ID, "text": render_message(event)}).encode("utf-8")
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
        details = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(f"Telegram HTTP {exc.code}: {details}") from exc
    payload = json.loads(response_body.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise RuntimeError("Telegram API returned ok=false")


def deliver_pending(state: dict[str, Any]) -> None:
    now = int(time.time())
    for event in list(state["pending"]):
        if not isinstance(event, dict) or int(event.get("next_attempt_at", 0)) > now:
            continue
        try:
            send_telegram(event)
        except Exception as exc:
            attempts = int(event.get("attempts", 0)) + 1
            event["attempts"] = attempts
            event["last_error"] = str(exc)
            event["next_attempt_at"] = now + min(3600, 30 * (2 ** min(attempts - 1, 7)))
            print(f"[notifier] delivery failed; retry scheduled: {exc}", flush=True)
            save_state(state)
            continue

        state["pending"].remove(event)
        state["delivered"].append(event["id"])
        state["delivered"] = state["delivered"][-MAX_DELIVERED_IDS:]
        save_state(state)
        print(f"[notifier] alert delivered id={event['id']}", flush=True)


def healthcheck() -> int:
    try:
        if not BOT_TOKEN or not CHAT_ID:
            raise RuntimeError("Telegram credentials are missing")
        if not LOG_DIR.is_dir() or not os.access(LOG_DIR, os.R_OK | os.X_OK):
            raise RuntimeError(f"log directory is not readable: {LOG_DIR}")
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        probe = STATE_DIR / ".health-write-probe"
        probe.write_text("ok\n", encoding="ascii")
        probe.unlink()
        print("healthy")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"unhealthy: {exc}")
        return 1


def main() -> int:
    if "--healthcheck" in os.sys.argv:
        return healthcheck()
    if not BOT_TOKEN or not CHAT_ID:
        print("[notifier] Telegram credentials are required", flush=True)
        return 2

    state = load_state()
    print(
        f"[notifier] started log_dir={LOG_DIR} replay_existing={REPLAY_EXISTING}",
        flush=True,
    )
    while True:
        try:
            collect_events(state)
            save_state(state)
            deliver_pending(state)
        except Exception as exc:
            print(f"[notifier] cycle failed: {exc}", flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
