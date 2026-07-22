# ATP v1.8 — Production Dockerfile
# Multi-stage: builder → runner (minimal attack surface)

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build deps for blake3
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc cargo rustc \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Runner stage ─────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy only what we need
COPY --from=builder /root/.local /root/.local
COPY . .

# Ensure scripts in user path
ENV PATH=/root/.local/bin:$PATH

# Expose ATP ports
#   8443 → TCP+TLS
#   8444 → Gossip
#   8080 → Health check / metrics
EXPOSE 8443 8444 8080

# Health check via our own endpoint
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Production entry point
CMD ["python", "main.py"]
