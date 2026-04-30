FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY audit/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY audit/app.py ./app.py
COPY shared ./shared
RUN mkdir -p /app/ledger

EXPOSE 8022

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8022"]