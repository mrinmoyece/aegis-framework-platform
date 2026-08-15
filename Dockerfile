ARG PYTHON_IMAGE=python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52

FROM ${PYTHON_IMAGE} AS builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.12.5
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra postgres

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.source="https://github.com/mrinmoyece/aegis-framework-platform" \
      org.opencontainers.image.description="Aegis framework-first durable Layer 3"
ENV PATH="/app/.venv/bin:${PATH}" \
    LANGGRAPH_STRICT_MSGPACK=true \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid aegis --no-create-home --shell /usr/sbin/nologin aegis
COPY --from=builder --chown=aegis:aegis /app/.venv /app/.venv
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["uvicorn", "aegis_framework.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
