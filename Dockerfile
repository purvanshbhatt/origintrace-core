# ============================================================
# OriginTrace Engine — Production Dockerfile
# Semantic Lifting via r2ghidra + Concolic Execution via angr
# ============================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# 1. Install ALL system dependencies in a single layer.
#    patch + pkg-config are required by radare2's configure script.
#    g++ + cmake are required to compile the r2ghidra plugin.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget git make gcc g++ cmake pkg-config patch libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Build and install Radare2 from source + r2ghidra plugin
RUN git clone --depth 1 https://github.com/radareorg/radare2.git \
    && cd radare2 \
    && ./sys/install.sh \
    && r2pm -U \
    && r2pm -gi r2ghidra

# 3. Setup Python Application
WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# 4. Non-root execution for security
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8080

# 5. Run the production FastAPI server
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
