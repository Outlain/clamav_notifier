# Integration

Each producer mounts only its own subdirectory at `/events` and writes atomic
schema-v1 JSON. The notifier mounts their parent at `/events`. This preserves
service attribution and prevents one scanner from editing another scanner's
queue.

The notifier is the suite's sole Telegram implementation. Leave the removed
Torrent Intake Telegram variables unset; adding a second sender would duplicate
detection alerts. Human-readable scheduled scan logs remain useful for operators
and the UI but are not an alert transport.

Start order is flexible because event files are durable. Starting the notifier
before producers gives immediate delivery; starting it later imports everything
still in the spool directories. Back up `/state/notifier.sqlite3` with the
container stopped (or use a SQLite-aware backup) to retain sent-state
deduplication during host migration.
