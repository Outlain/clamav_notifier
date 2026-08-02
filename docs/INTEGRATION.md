# Integration with clamav-scheduled

Mount the host directory containing `clamav_scheduled.log` and its rotated files at `/logs:ro`.

The current scheduled scanner writes structured `threat_detected` JSON events containing:

- Scan type.
- Threat signature.
- Original source path.
- Quarantine destination.
- Whether quarantine succeeded.

The notifier ignores ordinary human-readable progress lines. Its persistent state directory prevents duplicate alerts after restarts and preserves failed alerts until Telegram accepts them.
