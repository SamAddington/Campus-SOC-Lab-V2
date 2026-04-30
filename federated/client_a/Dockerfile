FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY data ./data
RUN mkdir -p /app/shared

EXPOSE 8011

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8011"]