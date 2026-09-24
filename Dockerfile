FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PERSISTENCE_PATH=/app/data/analyzer_cache.sqlite3

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --system analyzer \
    && useradd --system --gid analyzer --home-dir /app analyzer \
    && mkdir -p /app/data \
    && chown analyzer:analyzer /app/data

COPY --chown=analyzer:analyzer app ./app

USER analyzer
EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
