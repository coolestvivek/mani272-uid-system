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

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/database /app/whitelists

# Expose ports
EXPOSE 8247

# Run the Flask app
CMD ["python", "app.py"]
