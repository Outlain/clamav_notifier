FROM python:3.14.5-alpine3.22

RUN addgroup -S -g 10001 clamav-helper \
    && adduser -S -D -u 10001 -G clamav-helper -h /home/clamav-helper clamav-helper \
    && install -d -o 10001 -g 10001 -m 0750 /home/clamav-helper /state

COPY notifier.py /usr/local/bin/notifier.py
RUN chmod 0555 /usr/local/bin/notifier.py

ENV CLAMAV_LOG_DIR=/logs \
    STATE_DIR=/state \
    NOTIFIER_POLL_SECONDS=15 \
    NOTIFIER_REPLAY_EXISTING=false \
    TELEGRAM_TIMEOUT_SECONDS=15 \
    HOME=/home/clamav-helper \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=1m --timeout=10s --start-period=30s --retries=3 \
    CMD ["python3", "/usr/local/bin/notifier.py", "--healthcheck"]

CMD ["python3", "/usr/local/bin/notifier.py"]
