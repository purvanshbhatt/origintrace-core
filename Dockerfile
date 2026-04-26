# Use the official lightweight Python 3.11 image
FROM python:3.11-slim

# Set strict environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# 1. Install system dependencies
# Specifically require git, gcc, and make to compile radare2 locally
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    git \
    make \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Build and install Radare2 from source
# r2pipe requires the underlying radare2 binaries on the host OS
RUN git clone --depth 1 https://github.com/radareorg/radare2.git \
    && cd radare2 \
    && sys/install.sh \
    && cd .. \
    && rm -rf radare2

# 3. Setup Python Application
WORKDIR /app

# Copy requirements strictly to cache the pip install layer
COPY requirements.txt .

# Ensure pip is upgraded and install Python deps (pefile, r2pipe, google-genai, fastapi)
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Run the app under an unprivileged user for security
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Expose the Cloud Run port
EXPOSE 8080

# Run Uvicorn via execution form
CMD ["sh", "-c", "uvicorn mock_api.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
