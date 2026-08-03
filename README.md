# clamav-notifier

Central, durable Telegram delivery for the four ClamAV event producers. No
scanner sends Telegram directly and the notifier does not parse human log files.

## Event contract

Producers atomically write one JSON file per event under:

```text
/events/clamav-scheduled
/events/torrent-intake
/events/web-scan-move
/events/clamav-defs-updater
```

Every event has `schema_version`, `event_id`, `event_type`, `service`, `severity`,
UTC `timestamp`, and `message`. Optional bounded fields include `source_path`,
`destination_path`, `threat_name`, `action_success`, `scan_type`, `job_id`,
`torrent_hash`, and `definition_age_seconds`. Producers must never place tokens,
passwords, tracker passkeys, or magnet URIs in an event.

The notifier opens regular files with `O_NOFOLLOW`, verifies their identity,
validates and bounds the schema, commits them to SQLite, and only then removes the
spool file. `event_id` is the durable deduplication key, including across restarts.
Malformed files are recorded without copying their possibly sensitive body.

## Delivery behavior

- Detections and infection actions are delivered immediately.
- Informational updates are retained as suppressed; `service_recovered` is sent.
- Operational failures wait for the short aggregation interval. After a group has
  been sent, repeats collect until the repeat window expires and are sent as one
  message with an occurrence count.
- Telegram messages are plain text; no fragile Markdown escaping is used.
- HTTP and API failures use exponential retry. Telegram `429 retry_after` is
  honored.
- A row becomes `sent` only after Telegram returns `ok=true` and a message ID.
- Sent/suppressed history and rejected-file metadata have configurable retention,
  so the SQLite database does not grow forever.

SQLite state, pending retries, and the last heartbeat live in
`/state/notifier.sqlite3`. Delivery is intentionally at-least-once: a process
failure in the tiny interval after Telegram accepts a message but before the
SQLite commit can produce one duplicate, which is preferable to silently losing
an alert.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | required | bot token; keep only in mode-0600 `.env` |
| `TELEGRAM_CHAT_ID` | required | target chat |
| `TELEGRAM_TIMEOUT_SECONDS` | `15` | HTTP timeout |
| `NOTIFIER_POLL_SECONDS` | `5` | spool poll interval |
| `NOTIFIER_AGGREGATION_SECONDS` | `30` | first operational grouping delay |
| `NOTIFIER_REPEAT_WINDOW_SECONDS` | `900` | repeat-alert grouping window |
| `NOTIFIER_RETENTION_DAYS` | `90` | sent/suppressed event retention |
| `NOTIFIER_REJECTED_RETENTION_DAYS` | `30` | rejected metadata retention |
| `NOTIFIER_MAX_EVENT_BYTES` | `131072` | maximum input file size |
| `NOTIFIER_MAX_FILES_PER_CYCLE` | `1000` | bounded imports per poll |
| `NOTIFIER_HEALTH_MAX_AGE_SECONDS` | `180` | maximum heartbeat age |

Deploy with:

```sh
cp .env.example .env
chmod 600 .env
# Set the real token and chat ID.
docker compose -f docker-compose.example.yml up -d
```

The Compose example mounts `/opt/docker/clamav-shared/events` read/write because
the notifier removes a file only after durable import. It mounts
`/opt/docker/clamav-shared/state/notifier` for SQLite, uses a read-only root
filesystem, drops all capabilities, and bounds PIDs, memory, CPU, open files, and
Docker logs.

## Validation and publishing

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile notifier.py
TELEGRAM_BOT_TOKEN=test TELEGRAM_CHAT_ID=test \
  docker compose -f docker-compose.example.yml config --quiet
docker build -t clamav-notifier:test .
```

GitHub Actions publishes `ghcr.io/<owner>/clamav-notifier` for `linux/amd64` and
`linux/arm64`.
