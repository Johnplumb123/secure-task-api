FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as a non-root user so a compromise of the app doesn't give root in the container
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser

ENV DATABASE_URL=sqlite:////data/tasks.db
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
