# GuardLayer REST API as a sidecar service.
#   docker build -t guardlayer .
#   docker run -p 8000:8000 -e GUARDLAYER_API_KEY=change-me guardlayer
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[api]" && useradd --create-home --uid 10001 guard

USER guard
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "guardlayer.api:app", "--host", "0.0.0.0", "--port", "8000"]
