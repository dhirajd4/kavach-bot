# api + worker image. M2 adds Dockerfile.sandbox (Playwright), M3/M4 add tesseract/androguard.
FROM python:3.12.10-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN useradd --create-home --uid 10001 kavach

COPY pyproject.toml ./
COPY src ./src
RUN pip install .

COPY alembic.ini ./
COPY migrations ./migrations

USER kavach
EXPOSE 8000
CMD ["uvicorn", "kavach.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
