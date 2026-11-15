FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt requirements.lock ./
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim AS runner
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:${PATH}" IMAGEGUARD_DATA_DIR=/data IMAGEGUARD_MODELS_DIR=/data/models
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 appuser && useradd -u 10001 -g appuser -m appuser \
    && mkdir /data && chown appuser:appuser /data
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import os,base64,urllib.request; r=urllib.request.Request('http://127.0.0.1:8000/api/health'); p=os.environ.get('IMAGEGUARD_ADMIN_PASSWORD',''); r.add_header('Authorization','Basic '+base64.b64encode((os.environ.get('IMAGEGUARD_ADMIN_USER','admin')+':'+p).encode()).decode()); urllib.request.urlopen(r,timeout=3)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
