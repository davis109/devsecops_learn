FROM python:3.11-slim

WORKDIR /app

# Install git
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY helios/ /app/helios/
COPY servers/git-committer/ /app/servers/git-committer/

# Expose port
EXPOSE 8004

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8004/health')"

# Run the server
CMD ["python", "-m", "uvicorn", "servers.git_committer.app:app", "--host", "0.0.0.0", "--port", "8004"]
