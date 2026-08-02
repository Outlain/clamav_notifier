# clamav-scheduled-notifier

A standalone Telegram notifier for the structured malware events emitted by the current `clamav-scheduled` main branch.

This repository is intended to be uploaded by itself to a GitHub repository named `clamav-scheduled-notifier`.

## Expected event

The notifier watches `.log` files for one-line JSON events such as:

```json
{"event":"threat_detected","scan":"FULL","threat":"Eicar-Signature","source":"/scan/eicar.com","quarantine":"/quarantine/eicar.com","quarantine_success":true}
```

## What it does

- Reads scheduled-scanner logs read-only.
- Stores inode/offset tracking and a durable delivery queue under `/state`.
- Does not replay old logs on first start unless explicitly enabled.
- Retries failed Telegram deliveries with exponential backoff.
- Sends plain-text Telegram messages, avoiding Markdown filename parsing problems.
- Handles log rotation and truncation without rereading every log from byte zero.
- Publishes amd64 and arm64 images to GHCR through GitHub Actions.

## Deploy

1. Upload this entire folder to a new GitHub repository.
2. Keep the default branch named `main`.
3. Enable GitHub Actions and package publishing.
4. Copy `.env.example` to `.env` on the Docker host.
5. Add the Telegram bot token and chat ID.
6. Deploy `docker-compose.example.yml`.

The published image will be:

```text
ghcr.io/<github-owner>/clamav-scheduled-notifier:latest
```

Do not commit the real `.env` file or Telegram token.

## Local validation

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile notifier.py
TELEGRAM_BOT_TOKEN=test TELEGRAM_CHAT_ID=test docker compose -f docker-compose.example.yml config --quiet
docker build -t clamav-scheduled-notifier:test .
```
