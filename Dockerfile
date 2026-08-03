FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG PYTHON_PACKAGE_VERSION=3.14.5-r0

RUN apk upgrade --no-cache \
    && apk add --no-cache "python3=${PYTHON_PACKAGE_VERSION}" \
    && addgroup -S -g 10001 clamav-helper \
    && adduser -S -D -u 10001 -G clamav-helper -h /home/clamav-helper clamav-helper \
    && install -d -o 10001 -g 10001 -m 0750 /home/clamav-helper /state /events

COPY notifier.py /usr/local/bin/notifier.py
RUN chmod 0555 /usr/local/bin/notifier.py

ENV EVENTS_DIR=/events \
    STATE_DIR=/state \
    NOTIFIER_POLL_SECONDS=5 \
    NOTIFIER_AGGREGATION_SECONDS=30 \
    NOTIFIER_REPEAT_WINDOW_SECONDS=900 \
    NOTIFIER_RETENTION_DAYS=90 \
    NOTIFIER_REJECTED_RETENTION_DAYS=30 \
    TELEGRAM_TIMEOUT_SECONDS=15 \
    HOME=/home/clamav-helper \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=1m --timeout=10s --start-period=1m --retries=3 \
    CMD ["python3", "/usr/local/bin/notifier.py", "--healthcheck"]

CMD ["python3", "/usr/local/bin/notifier.py"]
