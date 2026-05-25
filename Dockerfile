# ─── Stage 1: builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# System deps needed to compile some wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source
COPY cli.py       ./
COPY core/        ./core/
COPY fingerprints/ ./fingerprints/

# /data is the mount point for the user's current directory
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["python", "/app/cli.py"]
CMD ["--help"]
