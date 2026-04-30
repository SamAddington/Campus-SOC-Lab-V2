FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY policy_engine/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY policy_engine/app.py ./app.py
COPY policy_engine/rules.yaml ./rules.yaml
COPY shared ./shared

EXPOSE 8020

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8020"]