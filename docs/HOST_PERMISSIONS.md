# Host permissions

The image defaults to UID/GID `10001:10001`.

It needs:

- Read access to `/mnt/media/docker/clamav/logs`.
- Read/write/search access to `/opt/docker/clamav-notifier/state`.

The log mount should remain read-only. The state directory stores `notifier-state.json` using mode `0600`.
