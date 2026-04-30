FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY osint/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY osint/app.py .
COPY osint/config.py .
COPY osint/cache.py .
COPY osint/rate_limiter.py .
COPY osint/http_client.py .
COPY osint/aggregator.py .
COPY osint/explainer.py .
COPY osint/extractors ./extractors
COPY osint/providers ./providers
COPY osint/scopes.yaml .
COPY shared ./shared

EXPOSE 8028

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8028"]
