# api + worker image (Tesseract for OCR). The sandbox has its own image: Dockerfile.sandbox.
FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN useradd --create-home --uid 10001 kavach

# OCR (M3): Tesseract 5 with Hindi + English models.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-hin tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first, in their own cached layer, from the hash-locked file: every package and
# sub-dependency is pinned by SHA-256 (see `make lock`). A changed or tampered file fails here.
COPY requirements/runtime.txt ./requirements/runtime.txt
RUN pip install --retries 10 --timeout 60 --require-hashes --no-deps -r requirements/runtime.txt
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-deps --no-build-isolation .

COPY alembic.ini ./
COPY migrations ./migrations

USER kavach
EXPOSE 8000
CMD ["uvicorn", "kavach.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
