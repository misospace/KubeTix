# Multi-stage build (issue #354): the builder stage installs gcc/libpq-dev
# only to compile ``psycopg2-binary`` from source when no pre-built wheel is
# available for the active CPython release (see issue #310: psycopg2-binary
# 2.9.10 ships only an sdist for the newest CPython minor). The runtime stage
# copies only the built virtualenv and application code, so the compilers and
# headers never ship in the production image.
FROM python:3.14-slim AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage: no gcc, no libpq-dev. psycopg2-binary bundles its own libpq,
# so no system packages are required here. The bundled Bitnami postgresql
# subchart in the Helm chart relies on this driver being present at runtime.
FROM python:3.14-slim

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application (kubetix-api/.dockerignore keeps test artifacts such as
# test_default.sqlite and .pytest_cache/ out of the build context, so they
# are not shipped in the image).
COPY . .

# Create non-root user
RUN useradd -m -u 1000 kubetix && chown -R kubetix:kubetix /app
USER kubetix

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
