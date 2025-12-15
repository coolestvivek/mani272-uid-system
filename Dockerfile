FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for mitmproxy
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir mitmproxy

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/database /app/whitelists /app/certs

# Expose ports - Web (8247) and MITM Proxy (7934)
EXPOSE 8247 7934

# Run both Flask and MITM Proxy
CMD ["python", "start_all.py"]
