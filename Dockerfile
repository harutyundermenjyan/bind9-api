# BIND9 REST API Dockerfile
# Multi-stage build for smaller image

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies (bind9 tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9-utils \
    bind9-dnsutils \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY app/ ./app/

# Create non-root user
RUN useradd -m -u 1000 bind9api && \
    mkdir -p /var/lib/bind9-api && \
    chown -R bind9api:bind9api /app /var/lib/bind9-api

# Environment variables
ENV BIND9_API_HOST=0.0.0.0 \
    BIND9_API_PORT=8080 \
    BIND9_API_DEBUG=false \
    BIND9_API_DATABASE_URL=sqlite+aiosqlite:///./bind9_api.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health/live').raise_for_status()"

# Run as non-root user
USER bind9api

# Start application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]

