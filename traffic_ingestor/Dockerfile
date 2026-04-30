FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY traffic_ingestor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY traffic_ingestor/app.py .
COPY traffic_ingestor/config.py .
COPY traffic_ingestor/emitter.py .
COPY traffic_ingestor/adapters ./adapters
COPY traffic_ingestor/features ./features
COPY traffic_ingestor/detectors ./detectors

EXPOSE 8027

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8027"]
