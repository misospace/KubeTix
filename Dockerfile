FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
