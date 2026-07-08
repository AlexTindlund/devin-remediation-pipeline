FROM python:3.12-slim

WORKDIR /app

# Deps first for layer caching; httpx needs nothing extra on slim.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY orchestrator/ ./orchestrator/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/

# SQLite lives on a mounted volume so state survives container restarts.
ENV DB_PATH=/data/remediation.db
VOLUME ["/data"]

EXPOSE 8000

# One worker on purpose: the in-process poller must not be duplicated across
# workers (each copy would poll the same sessions). One is correct at this scale.
CMD ["uvicorn", "orchestrator.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
