FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY integrations/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY integrations/app.py .
COPY integrations/config.py .
COPY integrations/anonymize.py .
COPY integrations/http_client.py .
COPY integrations/rate_limiter.py .
COPY integrations/state.py .
COPY integrations/scopes.yaml .
COPY integrations/providers ./providers
COPY integrations/adapters ./adapters
COPY shared ./shared

RUN mkdir -p /app/integration_state

EXPOSE 8025

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8025"]
