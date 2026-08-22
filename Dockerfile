FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Install dependencies (CLI-only set: kc-share.py imports stdlib plus
# cryptography.fernet, so the image must not pull in the kubetix-api
# runtime — see requirements-cli.txt)
COPY requirements-cli.txt .
RUN pip install --no-cache-dir -r requirements-cli.txt

# Copy application
COPY kc-share.py .
COPY __init__.py .

# Create non-root user for security
RUN useradd -m -u 1000 kubeshare && \
    chown -R kubeshare:kubeshare /app
USER kubeshare

# Default command
ENTRYPOINT ["python3", "kc-share.py"]

# Expose nothing (CLI tool, no network service)
