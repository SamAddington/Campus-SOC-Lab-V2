FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY llm_assistant/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY llm_assistant/app.py .
COPY llm_assistant/teacher_student.py .
COPY llm_assistant/providers ./providers
COPY shared ./shared

EXPOSE 8024

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8024"]
