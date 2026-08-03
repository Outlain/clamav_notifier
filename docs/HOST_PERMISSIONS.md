# Host permissions

The image runs as UID/GID `10001:10001` by default. The same numeric identity is
used by event producers so the notifier can import and delete their completed
spool files.

```sh
sudo install -d -m 0750 -o 10001 -g 10001 \
  /opt/docker/clamav-shared/events \
  /opt/docker/clamav-shared/events/clamav-scheduled \
  /opt/docker/clamav-shared/events/torrent-intake \
  /opt/docker/clamav-shared/events/web-scan-move \
  /opt/docker/clamav-shared/events/clamav-defs-updater \
  /opt/docker/clamav-shared/state/notifier
```

`/events` needs read/search access at its root and read/write/search access in the
producer subdirectories. `/state` needs read/write/search access for SQLite WAL
files. No definitions, media, scan log, or Docker socket mount is needed.
