FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY orchestrator/app.py ./app.py
COPY shared ./shared
RUN mkdir -p /app/federated_shared /app/ledger

EXPOSE 8021

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8021"]