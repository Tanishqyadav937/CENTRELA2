# Multi-stage Dockerfile for Bayora Microservices
# Targets: 'light' (base + requirements.txt only) and 'ml' (light + ML deps)
# The specific service to run is passed via the Kubernetes 'command' or 'args'

# ============================================================================
# Stage: light
# Base image with lightweight dependencies (FastAPI, Kafka, DB, crypto, etc.)
# Used by: session-manager, audit-service, audit-gateway, auth-service, benchmark-service, red-team
# ============================================================================
FROM python:3.11-slim AS light

WORKDIR /app

# Install lightweight Python requirements
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bayora/ ./bayora/

# Ensure Python can find the bayora package module
ENV PYTHONPATH=/app

# Default command (will be overridden by Kubernetes Deployment manifests)
CMD ["uvicorn", "bayora.services.session_manager.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ============================================================================
# Stage: ml
# Extends 'light' with ML dependencies (torch, transformers, vllm, peft, etc.)
# Used by: llm-proxy, blue-team
# ============================================================================
FROM light AS ml

# Install ML-specific dependencies on top of light stage
COPY requirements-llm.txt ./
RUN pip install --no-cache-dir -r requirements-llm.txt
