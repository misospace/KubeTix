FROM python:3.14-slim

WORKDIR /app

# Install libpq headers so ``psycopg2-binary`` can be built from source
# when no pre-built wheel is available for the active CPython release
# (see issue #310: psycopg2-binary 2.9.10 ships only a sdist for the
# newest CPython minor). The bundled Bitnami postgresql subchart in the
# Helm chart relies on this driver being present at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
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
