# GuardLayer REST API as a sidecar or internal service.
#   docker build -t guardlayer .
#   docker run -p 127.0.0.1:8000:8000 -e GUARDLAYER_API_KEY=change-me --read-only --tmpfs /tmp guardlayer
# Hardened Compose and Kubernetes examples: deploy/ and DEPLOYMENT.md.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[api]" \
    && useradd --create-home --uid 10001 guard \
    && mkdir -p /var/log/guardlayer && chown guard:guard /var/log/guardlayer

USER guard
EXPOSE 8000
# uvicorn reads WEB_CONCURRENCY for its worker count (default 1). With more than one worker, put
# {pid} in the [audit] path so each worker owns its own hash-chained file.
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "guardlayer.api:app", "--host", "0.0.0.0", "--port", "8000"]
